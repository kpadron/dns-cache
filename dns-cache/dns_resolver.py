import asyncio as _aio
import itertools as _it
import random as _random
import typing as _typing

import dns_tunnel as _dt
import dns_util as _du


class StubResolver:
    """A DNS stub resolver that forwards requests to upstream recursive servers.
    """
    def __init__(self, tunnels: _typing.Iterable[_dt.BaseTunnel]) -> None:
        """Initialize a StubResolver instance.

        Args:
            tunnels: A non-empty iterable of BaseTunnel instances used for communicating with upstream servers.
        """
        self._tunnels: _typing.Sequence[_dt.BaseTunnel] = list(tunnels)
        self._counters: _typing.Sequence[int] = [0] * len(self._tunnels)

        self._loop = _aio.get_event_loop()

        self._queries: _typing.MutableSet[_typing.Tuple[int, _typing.Hashable]] = set()

    def __repr__(self) -> str:
        return f'{self.__class__.__name__}({self._tunnels!r})'

    @property
    def tunnels(self) -> _typing.Sequence[_dt.BaseTunnel]:
        """Returns a read-only view of the tunnels used by the instance.
        """
        return _du.SequenceView(self._tunnels)

    @property
    def counters(self) -> _typing.Sequence[int]:
        """Returns a read-only view of the query counters for each tunnel used by the instance.
        """
        return _du.SequenceView(self._counters)

    @property
    def queries(self) -> _typing.Collection[_typing.Tuple[int, _typing.Hashable]]:
        """Returns a read-only view of the outstanding query contexts submitted to the instance.
        """
        return _du.CollectionView(self._queries)

    def resolve(self, queries: _typing.Iterable[bytes], identifiers: _typing.Iterable[_typing.Hashable] = None) -> _typing.Sequence[bytes]:
        """Resolve DNS queries.
        """
        return self._loop.run_until_complete(self.aresolve(queries, identifiers))

    def resolve_query(self, query: bytes, identifier: _typing.Optional[_typing.Hashable] = None) -> bytes:
        """Resolve a DNS query.
        """
        return self._loop.run_until_complete(self.aresolve_query(query, identifier))

    def submit(self, queries: _typing.Iterable[bytes], identifiers: _typing.Iterable[_typing.Hashable] = None) -> _typing.Sequence[_aio.Task]:
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

    def submit_query(self, query: bytes, identifier: _typing.Hashable = None) -> _aio.Task:
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

    async def aresolve(self, queries: _typing.Iterable[bytes], identifiers: _typing.Iterable[_typing.Hashable] = None) -> _typing.Sequence[bytes]:
        """Asynchronously resolve DNS queries.
        """
        return await _aio.gather(*(await self.asubmit(queries, identifiers)))

    async def aresolve_query(self, query: bytes, identifier: _typing.Hashable = None) -> bytes:
        """Asynchronously resolve a DNS query.
        """
        return await (await self.asubmit_query(query, identifier))

    async def asubmit(self, queries: _typing.Iterable[bytes], identifiers: _typing.Iterable[_typing.Hashable] = None) -> _typing.Sequence[_aio.Task]:
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
        async def agen_tasks() -> _typing.AsyncIterator[_aio.Task]:
            if identifiers is None:
                for query in queries:
                    yield await self.asubmit_query(query)

            else:
                for (query, identifier) in _it.zip_longest(queries, identifiers):
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
                await _du.full_cancel(task)

            raise

    async def asubmit_query(self, query: bytes, identifier: _typing.Hashable = None) -> _aio.Task:
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
        qid = _du.get_short(query)

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
        _du.set_short(query, counter)

        # Create and schedule query resolution task
        task = await tunnel.asubmit_query(query)
        self._queries.add(context)

        # Schedule wrapper task and return it
        return self._loop.create_task(self._ahandle_resolve(task, context))

    async def _ahandle_resolve(self, task: _aio.Task, context: _typing.Tuple[int, _typing.Hashable]) -> bytes:
        """Wrap a tunnel resolution task and replace packet query id.
        """
        try:
            answer = bytearray(await task)
            _du.set_short(answer, context[0])
            return answer

        except Exception:
            return b''

        finally:
            self._queries.discard(context)

    def _select_tunnel(self) -> _dt.BaseTunnel:
        """Select a tunnel randomly based on total tunnel traffic.
        """
        queries = [len(tunnel.queries) for tunnel in self._tunnels]
        max_weight = max(queries)
        cum_weights = [max_weight - weight + 1 for weight in queries]
        return _random.choices(self._tunnels, cum_weights=cum_weights)[0]
