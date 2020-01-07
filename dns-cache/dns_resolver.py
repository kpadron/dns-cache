import asyncio as aio
import random
import struct
from itertools import accumulate
from typing import (Hashable, Iterable, MutableMapping, MutableSet, Optional,
                    Sequence, Set, Tuple, Union)

import dns_tunnel as dt
from dns_util import BytesLike, get_short, set_short


class StubResolver:
    """A DNS stub resolver that forwards requests to upstream recursive servers.
    """
    def __init__(self, upstreams: Iterable[dt.BaseTunnel]) -> None:
        """Initialize a StubResolver instance.

        Args:
            upstreams: A iterable of BaseTunnel instances used for communicating with upstream servers.
        """
        self._upstreams: Sequence[dt.BaseTunnel] = tuple(upstreams)
        self._counters: MutableMapping[int, int] = {id(upstream): 0 for upstream in self._upstreams}

        self._loop = aio.get_event_loop()

        self._queries: MutableSet[Tuple[int, Hashable]] = set()

    def __repr__(self) -> str:
        return f'{self.__class__.__name__}(%r)' % (list(self._upstreams),)

    @property
    def upstreams(self) -> Sequence[dt.BaseTunnel]:
        """Returns a sequence of upstreams used by the instance.
        """
        return self._upstreams

    @property
    def queries(self) -> Set[Tuple[int, Hashable]]:
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
        if identifiers is None:
            return [self.submit_query(query) for query in queries]

        return [self.submit_query(query, identifier) for (query, identifier) in zip(queries, identifiers)]

    def submit_query(self, query: BytesLike, identifier: Optional[Hashable] = None) -> aio.Task:
        """Submit a DNS query to be resolved.

        Args:
            query: The DNS query packet to resolve.
            identifier: Optional Hashable identifier (can be used to differentiate queries).

        Returns:
            A asyncio.Task that represents the eventual result of the query resolution. This
            Task can be awaited to receive the answer packet or empty bytestring on error.
        """
        # Extract query id from query packet
        qid = get_short(query)

        # Create context tuple
        context = (qid, identifier)

        # Ensure we are not already processing a matching query
        if context in self._queries:
            raise ValueError(f'(query, identifier) - already processing {context}')

        # Select an upstream server to forward query to
        upstream = self._select_upstream()

        # Get next query id for this upstream server
        index = id(upstream)
        counter = self._counters[index]
        self._counters[index] = (counter + 1) & 0xffff

        # Overwrite query id
        query = bytearray(query)
        set_short(counter, query)

        # Create and schedule query resolution task
        task = upstream.submit_query(query)
        self._queries.add(context)

        # Schedule wrapper task and return it
        return self._loop.create_task(self._ahandle_resolve(task, context))

    async def _ahandle_resolve(self, task: aio.Task, context: Tuple[int, Hashable]) -> bytes:
        """Wrap a upstream server resolution task and replace packet query id.
        """
        try:
            answer = bytearray(await task)
            set_short(context[0], answer)
            return answer

        except ValueError:
            return b''

        finally:
            self._queries.discard(context)

    def _select_upstream(self) -> dt.BaseTunnel:
        """Select an upstream randomly based on tunnel traffic.
        """
        cum_weights = tuple(accumulate(upstream.MAX_OUTSTANDING_QUERIES - len(upstream.queries) + 1 for upstream in self._upstreams))
        return random.choices(self._upstreams, cum_weights=cum_weights)[0]
