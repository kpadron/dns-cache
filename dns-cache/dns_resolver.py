import asyncio as aio
import itertools as it
import random
import struct
from typing import (Collection, Hashable, Iterable, Iterator, MutableMapping,
                    MutableSet, Optional, Sequence, Tuple)

import dns_tunnel as dt
from dns_util import BytesLike, get_short, set_short


class StubResolver:
    """A DNS stub resolver that forwards requests to upstream recursive servers.
    """
    def __init__(self, tunnels: Iterable[dt.BaseTunnel]) -> None:
        """Initialize a StubResolver instance.

        Args:
            tunnels: A non-empty iterable of BaseTunnel instances used for communicating with upstream servers.
        """
        self._tunnels: Sequence[dt.BaseTunnel] = list(tunnels)
        self._counters: MutableMapping[dt.BaseTunnel, int] = {tunnel: 0 for tunnel in self._tunnels}

        self._loop = aio.get_event_loop()

        self._queries: MutableSet[Tuple[int, Hashable]] = set()

    def __repr__(self) -> str:
        return f'{self.__class__.__name__}({self._tunnels!r})'

    @property
    def tunnels(self) -> Sequence[dt.BaseTunnel]:
        """Returns a sequence of tunnels used by the instance.
        """
        return list(self._tunnels)

    @property
    def counters(self) -> Sequence[int]:
        """Returns a snapshot of the query counters for each tunnel used by the instance.
        """
        return [self._counters[tunnel] for tunnel in self._tunnels]

    @property
    def queries(self) -> Collection[Tuple[int, Hashable]]:
        """Returns a snapshot of the current outstanding query contexts submitted to the instance.
        """
        return set(self._queries)

    def resolve(self, queries: Iterable[BytesLike], identifiers: Optional[Iterable[Hashable]] = None) -> Sequence[bytes]:
        """Resolve DNS queries.
        """
        return self._loop.run_until_complete(self.aresolve(queries, identifiers))

    def resolve_query(self, query: BytesLike, identifier: Optional[Hashable] = None) -> bytes:
        """Resolve a DNS query.
        """
        return self._loop.run_until_complete(self.submit_query(query, identifier))

    async def aresolve(self, queries: Iterable[BytesLike], identifiers: Optional[Iterable[Hashable]] = None) -> Sequence[bytes]:
        """Asynchronously resolve DNS queries.
        """
        return await aio.gather(*self.submit(queries, identifiers))

    async def aresolve_query(self, query: BytesLike, identifier: Optional[Hashable] = None) -> bytes:
        """Asynchronously resolve a DNS query.
        """
        return await self.submit_query(query, identifier)

    def submit(self, queries: Iterable[BytesLike], identifiers: Optional[Iterable[Hashable]] = None) -> Sequence[aio.Task]:
        """Submit DNS queries to be resolved.

        Args:
            queries: The DNS query packet(s) to resolve.
            identifiers: Optional Hashable identifier(s) (can be used to differentiate queries).

        Returns:
            A sequence of asyncio.Task(s) that represent eventual results of the query resolutions.
            These Task(s) can be awaited to receive the answer packet(s) or empty bytestring(s) on error.
        """
        # Submit queries to the instance
        tasks = []
        try:
            for task in self._submit_gen(queries, identifiers):
                tasks.append(task)

            return tasks

        # Handle cleanup after exception
        except Exception:
            for task in tasks:
                task.cancel()

            raise

    def _submit_gen(self, queries: Iterable[BytesLike], identifiers: Optional[Iterable[Hashable]] = None) -> Iterator[aio.Task]:
        """Generator function used to create an iterator when submitting queries to the instance.
        """
        if identifiers is None:
            for query in queries:
                yield self.submit_query(query)

        else:
            for (query, identifier) in it.zip_longest(queries, identifiers):
                if query is None:
                    break

                yield self.submit_query(query, identifier)

    def submit_query(self, query: BytesLike, identifier: Optional[Hashable] = None) -> aio.Task:
        """Submit a DNS query to be resolved.

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
        qid = get_short(query)

        # Create context tuple
        context = (qid, identifier)

        # Ensure we are not already processing a matching query
        if context in self._queries:
            raise ValueError(f'(query, identifier) - already processing query context {context}')

        # Select a tunnel to send the query through
        tunnel = self._select_tunnel()

        # Get next query id for this upstream server
        counter = self._counters[tunnel]
        self._counters[tunnel] = (counter + 1) & 0xffff

        # Overwrite query id
        query = bytearray(query)
        set_short(counter, query)

        # Create and schedule query resolution task
        task = tunnel.submit_query(query)
        self._queries.add(context)

        # Schedule wrapper task and return it
        return self._loop.create_task(self._ahandle_resolve(task, context))

    async def _ahandle_resolve(self, task: aio.Task, context: Tuple[int, Hashable]) -> bytes:
        """Wrap a tunnel resolution task and replace packet query id.
        """
        try:
            answer = bytearray(await task)
            set_short(context[0], answer)
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
