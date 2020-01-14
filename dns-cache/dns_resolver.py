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
            tunnels: A non-empty iterable of BaseTunnel instances used for communicating with upstream servers.
        """
        self._tunnels: typing.Sequence[dt.BaseTunnel] = list(tunnels)
        self._counters: typing.Sequence[int] = [0] * len(self._tunnels)

        self._loop = aio.get_event_loop()

        self._queries: typing.MutableMapping[dp.Question, aio.Future] = dict()

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
    def queries(self) -> typing.Collection[dp.Question]:
        """Returns a read-only view of the outstanding queries submitted to the instance.
        """
        return self._queries.keys()

    def resolve(self, questions: typing.Iterable[dp.Question]) -> typing.Sequence[dp.Answer]:
        """Resolve DNS questions.
        """
        return self._loop.run_until_complete(self.aresolve(questions))

    def resolve_question(self, question: dp.Question) -> dp.Answer:
        """Resolve a DNS question.
        """
        return self._loop.run_until_complete(self.aresolve_question(question))

    def submit(self, questions: typing.Iterable[dp.Question]) -> typing.Sequence[aio.Future]:
        """Synchronously submit DNS questions to be resolved.

        Returns:
            A sequence of future(s) that represent eventual answer(s) to the question(s).
            These future(s) can be awaited to receive the answer(s).
        """
        return self._loop.run_until_complete(self.asubmit(questions))

    def submit_question(self, question: dp.Question) -> aio.Future:
        """Synchronously submit a DNS question to be resolved.

        Returns:
            A future that represents the eventual answer to the question. This
            future can be awaited to receive the answer.
        """
        return self._loop.run_until_complete(self.asubmit_question(question))

    async def aresolve(self, questions: typing.Iterable[dp.Question]) -> typing.Sequence[dp.Answer]:
        """Asynchronously resolve DNS questions.
        """
        return await aio.gather(*(await self.asubmit(questions)))

    async def aresolve_question(self, question: dp.Question) -> dp.Answer:
        """Asynchronously resolve a DNS question.
        """
        return await (await self.asubmit_question(question))

    async def asubmit(self, questions: typing.Iterable[dp.Question]) -> typing.Sequence[aio.Future]:
        """Asynchronously submit DNS questions to be resolved.

        Returns:
            A sequence of future(s) that represent eventual answer(s) to the question(s).
            These future(s) can be awaited to receive the answer(s).
        """
        # Submit queries to the instance
        try:
            tasks = []

            for question in questions:
                tasks.append(await self.asubmit_question(question))

            return tasks

        # Handle cleanup after exception
        except Exception:
            await du.cancel_all(tasks)
            raise

    async def asubmit_question(self, question: dp.Question) -> aio.Future:
        """Asynchronously submit a DNS question to be resolved.

        Returns:
            A future that represents the eventual answer to the question. This
            future can be awaited to receive the answer.
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

        # Generate query for this question
        query = question.to_query(counter)

        # Create and schedule query resolution task
        task = await tunnel.asubmit_query(query)
        self._queries[question] = task

        # Schedule wrapper task and return it
        return self._loop.create_task(self._ahandle_answer(question, task))

    async def _ahandle_answer(self, question: dp.Question, task: aio.Task) -> dp.Answer:
        """Wrap a tunnel resolution task and return a DNS query answer.
        """
        try:
            packet = dp.Packet.parse(await task)
            answer = packet.get_answer()
            return answer

        except Exception:
            return dp.Answer(dp.SERVFAIL)

        finally:
            del self._queries[question]

    def _select_tunnel(self) -> dt.BaseTunnel:
        """Select a tunnel index randomly based on total tunnel traffic.
        """
        queries = [len(tunnel.queries) for tunnel in self._tunnels]
        max_weight = max(queries)
        cum_weights = [max_weight - weight + 1 for weight in queries]
        return random.choices(range(len(self._tunnels)), cum_weights=cum_weights)[0]


class CachedResolver(StubResolver):
    """
    """
    def __init__(self, tunnels: typing.Iterable[dt.BaseTunnel], cache: du.LruCache) -> None:
        """
        """
        super().__init__(tunnels)

        self._cache = cache

    async def asubmit_query(self, query: bytes, identifier: typing.Hashable = None) -> aio.Task:
        raise NotImplementedError


class AutoResolver(CachedResolver):
    """
    """
    pass
