import asyncio as aio
import logging
import struct
from abc import ABC, abstractmethod
from array import array
from asyncio import Future, Task
from itertools import cycle
from typing import (Awaitable, Collection, Iterable, Iterator, MutableMapping,
                    Optional, Sequence)

from . import packet as pkt
from .cache import AbstractCache, LruCache
from .packet import Answer, Question
from .tunnel import AbstractTunnel

__all__ = \
    (
        'AbstractResolver',
        'StubResolver',
        'CachedResolver',
        'AutoResolver',
    )


logger = logging.getLogger(__name__)


class AbstractResolver(ABC):
    """A DNS resolver abstract base class."""

    __slots__ = '_loop'

    def __init__(self) -> None:
        """Initializes a AbstractResolver instance."""
        self._loop = aio.get_event_loop()

    @property
    @abstractmethod
    def questions(self) -> Collection[Question]:
        """Returns a snapshot view of the outstanding questions submitted to the instance."""
        raise NotImplementedError

    def resolve(self, questions: Iterable[Question]) -> Sequence[Answer]:
        """Resolves DNS questions."""
        return self._loop.run_until_complete(self.batch(questions))

    def resolve_question(self, question: Question) -> Answer:
        """Resolves a DNS question."""
        return self._loop.run_until_complete(self.submit_question(question))

    def batch(self, questions: Iterable[Question]) -> Awaitable[Sequence[Answer]]:
        """
        Batches DNS questions to be resolved.

        Returns:
            A awaitable object that represents the eventual answers to all given questions.
            When awaited the object yields the sequence of answers.
        """
        return aio.gather(*(self.submit_question(question) for question in questions))

    def submit(self, questions: Iterable[Question]) -> Sequence[Awaitable[Answer]]:
        """
        Submits DNS questions to be resolved.

        Returns:
            A sequence of awaitable objects that represent eventual answers to the questions.

            When awaited the objects yield the answers.
        """
        return [self.submit_question(question) for question in questions]

    @abstractmethod
    def submit_question(self, question: Question) -> Awaitable[Answer]:
        """
        Submits a DNS question to be resolved.

        Returns:
            A awaitable object that represents the eventual answer to the question.

            When awaited the object yields the answer.
        """
        raise NotImplementedError


class StubResolver(AbstractResolver):
    """
    A DNS stub resolver that forwards requests to upstream recursive servers.

    Uses a iterable of AbstractTunnel instances to resolve queries.
    """

    def __init__(self, tunnels: Iterable[AbstractTunnel]) -> None:
        """
        Initializes a StubResolver instance.

        Args:
            tunnels: A non-empty iterable of AbstractTunnel instances.
        """
        super().__init__()

        self._tunnels: Sequence[AbstractTunnel] = tuple(tunnels)
        self._counters: Sequence[int] = array('H', [0] * len(self._tunnels))
        self._schedule: Iterator[int] = cycle(range(len(self._tunnels)))

        self._answers: MutableMapping[Question, Task] = dict()

    def __repr__(self) -> str:
        return f'{self.__class__.__name__}({list(self._tunnels)!r})'

    @property
    def tunnels(self) -> Sequence[AbstractTunnel]:
        """Returns a snapshot view of the tunnels used by the instance."""
        return list(self._tunnels)

    @property
    def counters(self) -> Sequence[int]:
        """Returns a snapshot view of the tunnel query counters used by the instance."""
        return list(self._counters)

    @property
    def questions(self) -> Collection[Question]:
        return set(self._answers)

    def submit_question(self, question: Question) -> Awaitable[Answer]:
        def done_cb(future: Future) -> None:
            """Removes a future from tracking when it finishes."""
            del self._answers[question]

        # Return the original task if this is a duplicate question
        answer_task = self._answers.get(question)
        if answer_task is not None:
            return aio.shield(answer_task)

        # Schedule the question resolution
        answer_task = self._loop.create_task(self._aresolve_question(question))
        answer_task.add_done_callback(done_cb)
        self._answers[question] = answer_task

        # Return the resolution task
        return aio.shield(answer_task)

    async def _aresolve_question(self, question: Question) -> Awaitable[Answer]:
        """Resolves a question using the via the tunnel streams."""
        async def query_tunnels() -> Awaitable[bytes]:
            """Holds a staggered race until a tunnel query succeeds."""
            async def query_tunnel(tunnel_index: int) -> Awaitable[bytes]:
                """Resolves a query via the specified tunnel."""
                msg_id = self._counters[tunnel_index]
                try: self._counters[tunnel_index] += 1
                except OverflowError: self._counters[tunnel_index] = 0

                tunnel_query = struct.pack('!H', msg_id) + query_tail
                tunnel = self._tunnels[tunnel_index]
                return await tunnel.submit_query(tunnel_query)

            # Wait 100 ms before starting the next query attempt
            STAGGER_TIMEOUT = 0.1

            # Initialize the set of competing tasks
            running = set()

            while True:
                # Schedule a new task and add it to the running set
                running.add(self._loop.create_task(query_tunnel(next(self._schedule))))

                # Wait for a competitor to finish
                (finished, _) = await aio.wait(running, timeout=STAGGER_TIMEOUT, return_when=aio.FIRST_COMPLETED)

                # Return the winners result and cancel the losers
                if finished:
                    winner = finished.pop()

                    for loser in running:
                        loser.cancel()

                    return winner.result()

        # Wait 2000 ms per query resolution
        QUERY_TIMEOUT = 2.0

        query_tail = question.to_query(0)[2:]

        try:
            reply = await aio.wait_for(query_tunnels(), QUERY_TIMEOUT)
            return pkt.Packet.parse(reply).get_answer()

        except (aio.TimeoutError, ConnectionError):
            return Answer(pkt.SERVFAIL)


class CachedResolver(StubResolver):
    """
    A DNS stub resolver that caches answers.

    Uses a AbstractCache instance to store resource records for later reference.
    """
    def __init__(self, tunnels: Iterable[AbstractTunnel], cache: Optional[AbstractCache] = None) -> None:
        """Initialize a CachedResolver instance.

        Args:
            tunnels: A non-empty iterable of AbstractTunnel instances.
            cache: A AbstractCache instance used to store answer records.
        """
        super().__init__(tunnels)

        self._cache = cache if cache is not None else LruCache(10000)

    @property
    def cache(self) -> AbstractCache:
        return self._cache

    def submit_question(self, question: Question) -> Awaitable[Answer]:
        # Check the cache for the answer first
        answer = self._cache.get_entry(question)
        if answer is not None and not answer.expired:
            answer.stamp()
            future = self._loop.create_future()
            future.set_result(answer)
            return future

        # Schedule the resolution for the question
        return super().submit_question(question)

    async def _aresolve_question(self, question: Question) -> Awaitable[Answer]:
        answer = await super()._aresolve_question(question)

        if self._is_cacheable(answer):
            self._cache.set_entry(question, answer)
            self._cache.get_entry(question)

        return answer

    def _is_cacheable(self, answer: Answer) -> bool:
        """Returns true if the answer should be cached."""
        try:
            next(answer.records)
        except StopIteration:
            return False

        if answer.rcode != pkt.NOERROR:
            return False

        if answer.expired:
            return False

        return True


class AutoResolver(CachedResolver):
    """A DNS stub resolver that automatically refreshes cache entries."""

    def __init__(self, tunnels: Iterable[AbstractTunnel]) -> None:
        """Initialize a AutoResolver instance."""
        super().__init__(tunnels, LruCache(50000))

        self._refresher = self._loop.create_task(self._arefresh())

    async def _arefresh(self) -> Awaitable[None]:
        """Asynchronously refreshes cached records."""
        MIN_SLEEP_TIME = 10

        try:
            while True:
                await aio.sleep(MIN_SLEEP_TIME)

                questions = [question for (question, answer) in self._cache.most_recent(10000) if answer.timeleft <= MIN_SLEEP_TIME]
                resolutions = (StubResolver._aresolve_question(self, question) for question in questions)
                answers = await aio.gather(*resolutions)

                for (question, answer) in zip(questions, answers):
                    if self._is_cacheable(answer):
                        self._cache.set_entry(question, answer)

                logger.info(f'<AutoResolver {id(self):x}> Refresher woke up - cache.stats={self._cache.stats!r}')

        except Exception as exc:
            print(exc)
            raise
