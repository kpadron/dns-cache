import asyncio as aio
import itertools as it
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

        self._tunnels: Sequence[AbstractTunnel] = list(tunnels)
        self._counters: Sequence[int] = [0] * len(self._tunnels)
        self._schedule: Iterator[int] = it.cycle(range(len(self._tunnels)))

        # TODO: Attempt to use futures here maybe with weakref dict as well
        self._queries: MutableMapping[Question, aio.Future] = {}

    def __repr__(self) -> str:
        return f'{self.__class__.__name__}({self._tunnels!r})'

    @property
    def tunnels(self) -> Sequence[AbstractTunnel]:
        """Returns a read-only view of the tunnels used by the instance."""
        return utl.SequenceView(self._tunnels)

    @property
    def counters(self) -> Sequence[int]:
        """Returns a read-only view of the query counters for each tunnel used by the instance."""
        return utl.SequenceView(self._counters)

    @property
    def questions(self) -> Collection[Question]:
        """Returns a read-only view of the outstanding questions submitted to the instance."""
        return self._queries.keys()

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
        # Return the original task if this is a duplicate question
        task = self._queries.get(question)
        if task is not None:
            return task

        # Select a tunnel to send the query through
        index = self._select_tunnel()

        # Get next query id for this tunnel
        tunnel = self._tunnels[index]
        counter = self._counters[index]
        self._counters[index] = (counter + 1) & 0xffff

        # Generate a query packet for this question
        query_packet = question.to_query(counter)

        # Create and schedule query resolution task
        answer_packet = tunnel.submit_query(query_packet)

        # Schedule wrapper task
        # TODO: just return awaitable instead of scheduling
        task = self._loop.create_task(self._ahandle_answer(question, answer_packet))

        # Add task to tracking
        self._queries[question] = task

        return task

    async def _ahandle_answer(self, question: Question, answer_packet: Awaitable[bytes]) -> Awaitable[Answer]:
        """Wraps a tunnel resolution task and returns a DNS query answer."""
        try: return pkt.Packet.parse(await answer_packet).get_answer()
        except Exception: return Answer(pkt.SERVFAIL)
        finally: del self._queries[question]

    def _select_tunnel(self) -> int:
        """Selects a tunnel index based on a round-robin schedule."""
        return next(self._schedule)


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
            future = self._loop.create_future()
            future.set_result(answer)
            return utl.AwaitableView(future)

        # Schedule the resolution for the question
        return super().submit_question(question)

    async def _ahandle_answer(self, question: pkt.Question, task: aio.Task) -> pkt.Answer:
        answer = await super()._ahandle_answer(question, task)
        if answer.rcode == pkt.NOERROR:
            self._cache.add(question, answer)

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
