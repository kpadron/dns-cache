import asyncio as aio
import itertools as it
import random
import typing

import dns_tunnel as dt
import dns_util as du

__all__ = \
[
    'StubResolver',
    'CachedResolver',
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

        self._queries: typing.MutableSet[typing.Tuple[int, typing.Hashable]] = set()

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
    def queries(self) -> typing.Collection[typing.Tuple[int, typing.Hashable]]:
        """Returns a read-only view of the outstanding query contexts submitted to the instance.
        """
        return du.CollectionView(self._queries)

    def resolve(self, queries: typing.Iterable[bytes], identifiers: typing.Iterable[typing.Hashable] = None) -> typing.Sequence[bytes]:
        """Resolve DNS queries.
        """
        return self._loop.run_until_complete(self.aresolve(queries, identifiers))

    def resolve_query(self, query: bytes, identifier: typing.Optional[typing.Hashable] = None) -> bytes:
        """Resolve a DNS query.
        """
        return self._loop.run_until_complete(self.aresolve_query(query, identifier))

    def submit(self, queries: typing.Iterable[bytes], identifiers: typing.Iterable[typing.Hashable] = None) -> typing.Sequence[aio.Task]:
        """Synchronously submit DNS queries to be resolved.

        Args:
            queries: The DNS query packet(s) to resolve.
            identifiers: Optional Hashable identifier(s) (can be used to differentiate queries).

        Returns:
            A sequence of asyncio.Task(s) that represent eventual results of the query resolutions.
            These Task(s) can be awaited to receive the answer packet(s) or empty bytestring(s) on error.

        Raises:
            ValueError: When attempting to submit a duplicate query context.
        """
        return self._loop.run_until_complete(self.asubmit(queries, identifiers))

    def submit_query(self, query: bytes, identifier: typing.Hashable = None) -> aio.Task:
        """Synchronously submit a DNS query to be resolved.

        Args:
            query: The DNS query packet to resolve.
            identifier: Optional Hashable identifier (can be used to differentiate queries).

        Returns:
            A asyncio.Task that represents the eventual result of the query resolution. This
            Task can be awaited to receive the answer packet or empty bytestring on error.

        Raises:
            ValueError: When attempting to submit a duplicate query context.
        """
        return self._loop.run_until_complete(self.asubmit_query(query, identifier))

    async def aresolve(self, queries: typing.Iterable[bytes], identifiers: typing.Iterable[typing.Hashable] = None) -> typing.Sequence[bytes]:
        """Asynchronously resolve DNS queries.
        """
        return await aio.gather(*(await self.asubmit(queries, identifiers)))

    async def aresolve_query(self, query: bytes, identifier: typing.Hashable = None) -> bytes:
        """Asynchronously resolve a DNS query.
        """
        return await (await self.asubmit_query(query, identifier))

    async def asubmit(self, queries: typing.Iterable[bytes], identifiers: typing.Iterable[typing.Hashable] = None) -> typing.Sequence[aio.Task]:
        """Asynchronously submit DNS queries to be resolved.

        Args:
            queries: The DNS query packet(s) to resolve.
            identifiers: Optional Hashable identifier(s) (can be used to differentiate queries).

        Returns:
            A sequence of asyncio.Task(s) that represent eventual results of the query resolutions.
            These Task(s) can be awaited to receive the answer packet(s) or empty bytestring(s) on error.

        Raises:
            ValueError: When attempting to submit a duplicate query context.
        """
        # Async generator function used to create an async iterator of tasks
        async def agen_tasks() -> typing.AsyncIterator[aio.Task]:
            if identifiers is None:
                for query in queries:
                    yield await self.asubmit_query(query)

            else:
                for (query, identifier) in it.zip_longest(queries, identifiers):
                    if query is None:
                        break

                    yield await self.asubmit_query(query, identifier)

        # Submit queries to the instance
        try:
            tasks = []

            async for task in agen_tasks():
                tasks.append(task)

            return tasks

        # Handle cleanup after exception
        except Exception:
            for task in tasks:
                await du.full_cancel(task)

            raise

    async def asubmit_query(self, query: bytes, identifier: typing.Hashable = None) -> aio.Task:
        """Asynchronously submit a DNS query to be resolved.

        Args:
            query: The DNS query packet to resolve.
            identifier: Optional Hashable identifier (can be used to differentiate queries).

        Returns:
            A asyncio.Task that represents the eventual result of the query resolution. This
            Task can be awaited to receive the answer packet or empty bytestring on error.

        Raises:
            ValueError: When attempting to submit a duplicate query context.
        """
        # Extract query id from query packet
        qid = du.get_short(query)

        # Create context tuple
        context = (qid, identifier)

        # Ensure we are not already processing a matching query
        if context in self._queries:
            raise ValueError(f'(query, identifier) - already processing query context {context}')

        # Select a tunnel to send the query through
        tunnel = self._select_tunnel()
        index = self._tunnels.index(tunnel)

        # Get next query id for this tunnel
        counter = self._counters[index]
        self._counters[index] = (counter + 1) & 0xffff

        # Overwrite query id
        query = bytearray(query)
        du.set_short(query, counter)

        # Create and schedule query resolution task
        task = await tunnel.asubmit_query(query)
        self._queries.add(context)

        # Schedule wrapper task and return it
        return self._loop.create_task(self._ahandle_resolve(task, context))

    async def _ahandle_resolve(self, task: aio.Task, context: typing.Tuple[int, typing.Hashable]) -> bytes:
        """Wrap a tunnel resolution task and replace packet query id.
        """
        try:
            answer = bytearray(await task)
            du.set_short(answer, context[0])
            return answer

        except Exception:
            return b''

        finally:
            self._queries.discard(context)

    def _select_tunnel(self) -> dt.BaseTunnel:
        """Select a tunnel randomly based on total tunnel traffic.
        """
        queries = [len(tunnel.queries) for tunnel in self._tunnels]
        max_weight = max(queries)
        cum_weights = [max_weight - weight + 1 for weight in queries]
        return random.choices(self._tunnels, cum_weights=cum_weights)[0]


class CachedResolver(StubResolver):
    """
    """
    def __init__(self, tunnels: typing.Iterable[dt.BaseTunnel]) -> None:
        """
        """
        raise NotImplementedError

    async def asubmit_query(self, query: bytes, identifier: typing.Hashable = None) -> aio.Task:
        raise NotImplementedError