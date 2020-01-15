import asyncio as aio
import itertools as it
import random
import typing

import dns_packet as dp
import dns_tunnel as dt
import dns_util as du

__all__ = \
[
    'AutoResolver',
    'CachedResolver',
    'StubResolver',
]

class StubResolver:
    """A DNS stub resolver that forwards requests to upstream recursive servers.
    """
    def __init__(self, tunnels: typing.Iterable[dt.BaseTunnel]) -> None:
        """Initialize a StubResolver instance.

        Args:
            tunnels: A non-empty iterable of BaseTunnel instances.
        """
        self._loop = aio.get_event_loop()

        self._tunnels: typing.Sequence[dt.BaseTunnel] = list(tunnels)
        self._counters: typing.Sequence[int] = [0] * len(self._tunnels)

        self._queries: typing.MutableMapping[dp.Question, aio.Task] = {}

    def __repr__(self) -> str:
        return f'{self.__class__.__name__}({self._tunnels!r})'

    @property
    def tunnels(self) -> typing.Sequence[dt.BaseTunnel]:
        """Returns a read-only view of the tunnels used by the instance.
        """
        return du.SequenceView(self._tunnels)

    @property
    def counters(self) -> typing.Sequence[int]:
        """Returns a read-only view of the query counters for each tunnel used by the instance.
        """
        return du.SequenceView(self._counters)

    @property
    def questions(self) -> typing.Collection[dp.Question]:
        """Returns a read-only view of the outstanding questions submitted to the instance.
        """
        return self._queries.keys()

    def resolve(self, questions: typing.Iterable[dp.Question]) -> typing.Sequence[dp.Answer]:
        """Resolve DNS question(s).
        """
        return self._loop.run_until_complete(self.batch(questions))

    def resolve_question(self, question: dp.Question) -> dp.Answer:
        """Resolve a DNS question.
        """
        return self._loop.run_until_complete(self.submit_question(question))

    def batch(self, questions: typing.Iterable[dp.Question]) -> aio.Task:
        """Submit DNS question(s) to be resolved.

        Returns:
            A task object that represents the eventual results of all given questions.
            The task object can be awaited to receive the sequence of answers.
        """
        return aio.gather(*(self.submit_question(question) for question in questions))

    def submit(self, questions: typing.Iterable[dp.Question]) -> typing.Sequence[aio.Task]:
        """Submit DNS question(s) to be resolved.

        Returns:
            A sequence of task objects(s) that represent eventual answer(s) to the question(s).
            These task object(s) can be awaited to receive the answer(s).
        """
        return [self.submit_question(question) for question in questions]

    def submit_question(self, question: dp.Question) -> aio.Task:
        """Submit a DNS question to be resolved.

        Returns:
            A task object that represents the eventual answer to the question.
            This task object can be awaited to receive the answer.
        """
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
        task = tunnel.submit_query(query_packet)

        # Schedule wrapper task
        task = self._loop.create_task(self._ahandle_answer(question, task))

        # Add task to tracking
        self._queries[question] = task

        return task

    async def _ahandle_answer(self, question: dp.Question, task: aio.Task) -> dp.Answer:
        """Wrap a tunnel resolution task and return a DNS query answer.
        """
        try: return dp.Packet.parse(await task).get_answer()
        except Exception: return dp.Answer(dp.SERVFAIL)
        finally: del self._queries[question]

    def _select_tunnel(self) -> dt.BaseTunnel:
        """Select a tunnel index randomly based on total tunnel traffic.
        """
        queries = [len(tunnel.queries) for tunnel in self._tunnels]
        max_weight = max(queries)
        cum_weights = [max_weight - weight + 1 for weight in queries]
        return random.choices(range(len(self._tunnels)), cum_weights=cum_weights)[0]

class CachedResolver(StubResolver):
    """A DNS stub resolver that caches answers.
    """
    def __init__(self, tunnels: typing.Iterable[dt.BaseTunnel], **kwargs) -> None:
        """Initialize a CachedResolver instance.

        Args:
            cache - A Cache instance used to store answer records.
        """
        super().__init__(tunnels)

        self._cache: typing.MutableMapping[dp.Question, dp.Answer] = kwargs.get('cache', du.LruCache(10000))

    def resolve(self, questions: typing.Iterable[dp.Question]) -> typing.Sequence[dp.Answer]:
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

    def resolve_question(self, question: dp.Question) -> dp.Answer:
        # Check the cache for the answer first
        answer = self._cache.get(question)
        if answer is not None and not answer.expired:
            return answer

        # Schedule the resolution for the question
        return super().resolve_question(question)

    def submit_question(self, question: dp.Question) -> aio.Task:
        async def answer_wrapper(answer: dp.Answer) -> dp.Answer:
            """Simple answer wrapper that can be scheduled as a task.
            """
            return answer

        # Check the cache for the answer first
        answer = self._cache.get(question)
        if answer is not None and not answer.expired:
            return self._loop.create_task(answer_wrapper(answer))

        # Schedule the resolution for the question
        return super().submit_question(question)

    async def _ahandle_answer(self, question: dp.Question, task: aio.Task) -> dp.Answer:
        answer = await super()._ahandle_answer(question, task)
        if answer.rcode == dp.NOERROR:
            self._cache.add(question, answer)

        return answer


class AutoResolver(CachedResolver):
    """A DNS stub resolver that caches answers and auto refreshes cache entries.
    """
    def __init__(self, tunnels: typing.Iterable[dt.BaseTunnel], **kwargs) -> None:
        """Initialize a AutoResolver instance.

        Args:
            period: The time between refreshing stale cache entries (in seconds).
            refresh_size: The maximum number of entries to refresh at once.
        """
        super().__init__(tunnels, **kwargs)

        self.refresh_period = kwargs.get('refresh_period', 30.0)
        self.refresh_size = kwargs.get('refresh_size', 1000)
