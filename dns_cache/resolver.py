import asyncio as aio
import itertools as it
from struct import Struct
from array import array
from asyncio import Future, Task
from functools import cached_property
from typing import (Awaitable, Collection, Iterable, Iterator, MutableMapping,
                    Optional, Sequence)

from . import packet as pkt
from . import utility as utl
from .packet import Answer, Question
from .tunnel import AbstractTunnel
from .utility import Cache

__all__ = \
[
    'StubResolver',
    'CachedResolver',
    'AutoResolver',
]


class StubResolver:
    """A DNS stub resolver that forwards requests to upstream recursive servers."""
    def __init__(self, tunnels: Iterable[AbstractTunnel]) -> None:
        """
        Initializes a StubResolver instance.

        Args:
            tunnels: A non-empty iterable of AbstractTunnel instances.
        """
        self._loop = aio.get_event_loop()

        self._tunnels: Sequence[AbstractTunnel] = tuple(tunnels)
        self._counters: Sequence[int] = array('H', [0] * len(self._tunnels))
        self._schedule: Iterator[int] = it.cycle(range(len(self._tunnels)))

        self._answers: MutableMapping[Question, Task] = {}

    def __repr__(self) -> str:
        return f'{self.__class__.__name__}({self._tunnels!r})'

    @property
    def tunnels(self) -> Sequence[AbstractTunnel]:
        """Returns a read-only view of the tunnels used by the instance."""
        return self._tunnels

    @property
    def counters(self) -> Sequence[int]:
        """Returns a read-only view of the query counters for each tunnel used by the instance."""
        return utl.SequenceView(self._counters)

    @property
    def questions(self) -> Collection[Question]:
        """Returns a read-only view of the outstanding questions submitted to the instance."""
        return self._answers.keys()

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

    def submit_question(self, question: Question) -> Awaitable[Answer]:
        """
        Submits a DNS question to be resolved.

        Returns:
            A awaitable object that represents the eventual answer to the question.

            When awaited the object yields the answer.
        """
        return utl.AwaitableView(self._submit_question(question))

    def _submit_question(self, question: Question) -> Awaitable[Answer]:
        # Basic input validation
        if not isinstance(question, Question):
            raise TypeError(f'Expected a Question instance, not {type(question)}')

        # Return the original task if this is a duplicate question
        answer_task = self._answers.get(question)
        if answer_task is not None:
            return answer_task

        # Schedule the question resolution
        answer_task = aio.shield(self._aresolve_question(question))
        self._answers[question] = answer_task

        return answer_task

    __packer = Struct('!H').pack

    async def _aresolve_question(self, question: Question) -> Awaitable[Answer]:
        """Resolves a question using the via the tunnel streams."""
        try:
            query_tail = question.to_query(0)[2:]
            packer = self.__packer

            async def query_tunnel(tunnel_index: int) -> Awaitable[bytes]:
                """Resolves a query via the specified tunnel."""
                msg_id = self._counters[tunnel_index]
                try: self._counters[tunnel_index] += 1
                except OverflowError: self._counters[tunnel_index] = 0

                tunnel_query = packer(msg_id) + query_tail
                tunnel = self._tunnels[tunnel_index]
                return await tunnel.submit_query(tunnel_query)

            async def query_tunnels() -> Awaitable[bytes]:
                """
                Resolves a query via multiple tunnels until one succeeds.

                Holds a staggered race until a tunnel query succeeds.
                """
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
            QUERY_TIME = 2.0

            try:
                reply = await aio.wait_for(query_tunnels(), QUERY_TIME)
                return pkt.Packet.parse(reply).get_answer()

            except (aio.TimeoutError, ConnectionError):
                return Answer(pkt.SERVFAIL)

        finally:
            del self._answers[question]


class CachedResolver(StubResolver):
    """A DNS stub resolver that caches answers.
    """
    def __init__(self, tunnels: Iterable[AbstractTunnel], cache: Optional[Cache] = None) -> None:
        """Initialize a CachedResolver instance.

        Args:
            tunnels: A non-empty iterable of AbstractTunnel instances.
            cache: A Cache instance used to store answer records.
        """
        super().__init__(tunnels)

        self._cache: MutableMapping[Question, Answer] = cache or utl.LruCache(10000)

    def resolve(self, questions: Iterable[Question]) -> Sequence[Answer]:
        # Check the cache for the answers first
        answers, indices = [], []
        for (index, question) in enumerate(questions):
            answer = self._cache.get(question)
            if answer is not None and not answer.expired:
                answers.append(answer)
            else:
                answers.append(self.submit_question(question))
                indices.append(index)

        # Schedule and wait for resolution of the questions
        for index in indices:
            answers[index] = self._loop.run_until_complete(answers[index])

        return answers

    def resolve_question(self, question: pkt.Question) -> pkt.Answer:
        # Check the cache for the answer first
        answer = self._cache.get(question)
        if answer is not None and not answer.expired:
            return answer

        # Schedule the resolution for the question
        return super().resolve_question(question)

    def submit_question(self, question: Question) -> Awaitable[Answer]:
        # Check the cache for the answer first
        answer = self._cache.get_entry(question)
        if answer is not None and not answer.expired:
            answer.stamp()
            future = self._loop.create_future()
            future.set_result(answer)
            return utl.AwaitableView(future)

        # Schedule the resolution for the question
        return super().submit_question(question)

    async def _aresolve_question(self, question: Question) -> Awaitable[Answer]:
        answer = await super()._aresolve_question(question)

        if answer.rcode == pkt.NOERROR:
            self._cache.set_entry(question, answer)

        return answer


class AutoResolver(CachedResolver):
    """A DNS stub resolver that caches answers and auto refreshes cache entries.
    """
    def __init__(self, tunnels: Iterable[AbstractTunnel], **kwargs) -> None:
        """Initialize a AutoResolver instance.

        Args:
            period: The time between refreshing stale cache entries (in seconds).
            refresh_size: The maximum number of entries to refresh at once.
        """
        super().__init__(tunnels, **kwargs)

        self.refresh_period = kwargs.get('refresh_period', 30.0)
        self.refresh_size = kwargs.get('refresh_size', 1000)
