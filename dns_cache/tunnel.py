import asyncio as aio
import functools as ft
import ssl
import struct
from abc import ABC, abstractmethod
from asyncio import Future, Protocol, Transport
from typing import (Awaitable, Callable, Collection, Iterable, MutableMapping,
                    MutableSequence, MutableSet, Optional, Sequence, Tuple,
                    Union)

from . import utility as utl

__all__ = \
[
    'AbstractTunnel',
    'TcpTunnel',
    'TlsTunnel',
]


class AbstractTunnel(ABC):
    """
    DNS transport tunnel abstract base class.

    Pure Virtual Properties:
        connected: Whether the tunnel is connected or not.

    Pure Virtual Methods:
        __init__: Initializes a new class instance.
        _submit_query: Submits a DNS query to be resolved.
        _aconnect: Connects to the tunnel peer.
        _adisconnect: Disconnects from the tunnel peer.
    """
    # Maximum amount of time (in seconds) to wait for a tunnel operation
    DEFAULT_TIMEOUT: float = 1.5

    @abstractmethod
    def __init__(self) -> None:
        """Initializes a AbstractTunnel instance."""
        self._loop = aio.get_event_loop()

    def __enter__(self) -> 'AbstractTunnel':
        """Enter context."""
        self.connect()
        return self

    def __exit__(self, exc_type, exc_value, exc_trace) -> None:
        """Exit context."""
        self.disconnect()

    async def __aenter__(self) -> Awaitable['AbstractTunnel']:
        """Enter async context."""
        await self.aconnect()
        return self

    async def __aexit__(self, exc_type, exc_value, exc_trace) -> Awaitable[None]:
        """Exit async context."""
        await self.adisconnect()

    @property
    @abstractmethod
    def connected(self) -> bool:
        """Returns true if the instance is connected to the peer."""
        ...

    def connect(self) -> bool:
        """
        Synchronously connect to the peer.

        Returns:
            True if connected to the peer, False otherwise.
        """
        return self._loop.run_until_complete(self.aconnect())

    def disconnect(self) -> None:
        """Synchronously disconnect from the peer."""
        return self._loop.run_until_complete(self.adisconnect())

    def submit_query(self, query: bytes) -> Awaitable[bytes]:
        """
        Submit a DNS query for resolution via the peer.

        Args:
            query: The DNS query packet to resolve.

        Returns:
            A awaitable object that represents the eventual result of the resolution.
            When awaited the object yields the response packet or an empty bytestring on error.
        """
        return utl.AwaitableView(self._submit_query(query))

    def complete_query(self, pending_answer: Awaitable[bytes]) -> bytes:
        """
        Synchronously completes a DNS query previously submitted.

        Args:
            pending_answer: The awaitable returned by submit_query.

        Returns:
            The DNS response packet or empty bytestring on error.
        """
        return self._loop.run_until_complete(pending_answer)

    def resolve_query(self, query: bytes) -> bytes:
        """
        Synchronously resolve a DNS query via the peer.

        Args:
            query: The DNS query packet to resolve.

        Returns:
            The DNS response packet or empty bytestring on error.
        """
        return self._loop.run_until_complete(self._submit_query(query))

    def resolve_queries(self, queries: Iterable[bytes]) -> Sequence[bytes]:
        """
        Synchronously resolve DNS queries via the peer.

        Args:
            queries: The iterable of DNS query packets to resolve.

        Returns:
            The sequence of DNS response packets or empty bytestrings on error.
        """
        return self._loop.run_until_complete(aio.gather(*(self._submit_query(query) for query in queries)))

    async def aconnect(self, timeout: float = DEFAULT_TIMEOUT) -> Awaitable[bool]:
        """
        Asynchronously connect to the peer with a optional timeout.

        Returns:
            True if connected to the peer, False otherwise.
        """
        try: return await aio.wait_for(self._aconnect(), timeout)
        except aio.TimeoutError: return False

    async def adisconnect(self, timeout: float = DEFAULT_TIMEOUT) -> Awaitable[None]:
        """Asynchronously disconnect from the peer with a optional timeout."""
        try: await aio.wait_for(self._adisconnect(), timeout)
        except aio.TimeoutError: pass

    async def aresolve_query(self, query: bytes, timeout: Optional[float] = None) -> Awaitable[bytes]:
        """
        Asynchronously resolve a DNS query with a optional timeout.

        Args:
            query: The DNS query packet to resolve.
            timeout: The time duration to wait for this operation to complete (in seconds).

        Returns:
            The DNS response packet or empty bytestring on error.
        """
        try: return await aio.wait_for(self._submit_query(query), timeout)
        except aio.TimeoutError: return b''

    @abstractmethod
    def _submit_query(self, query: bytes) -> Awaitable[bytes]:
        """
        Submit a DNS query for resolution via the peer.

        Args:
            query: The DNS query packet to resolve.

        Returns:
            A awaitable object that represents the eventual result of the resolution.
            When awaited the object yields the response packet or an empty bytestring on error.
        """
        ...

    @abstractmethod
    async def _aconnect(self) -> Awaitable[bool]:
        """
        Asynchronously connect to the peer.

        Returns:
            True if connected to the peer, False otherwise.
        """
        ...

    @abstractmethod
    async def _adisconnect(self) -> None:
        """Asynchronously disconnect from the peer."""
        ...


# Functions used to peek and manipulate DNS messages
_peek_packet = struct.Struct('!H').unpack_from
_prefix_packet = struct.Struct('!H').pack_into
_peek_prefixed_packet = struct.Struct('!HH').unpack_from


class Stream(Protocol):
    """DNS over stream-based transport protocol."""
    def __init__(self) -> None:
        """Initializes a Stream protocol instance."""
        self._loop = aio.get_event_loop()
        self._transport: Optional[Transport] = None
        self._buffer = bytearray()
        self._drainers: MutableSequence[Future] = []
        self._replies: MutableMapping[int, Future] = {}
        self._connected = False
        self._paused = False

    def connection_made(self, transport: Transport) -> None:
        """Initializes the stream connection."""
        self._transport = transport
        self._connected = True

    def connection_lost(self, exc: Optional[BaseException]) -> None:
        """Deinitializes the stream connection."""
        self._connected = False
        self._transport = None

        # Finalize messages in read buffer
        if self._buffer:
            self.data_received(b'')

        self._buffer.clear()

        # Finalize reply futures
        for reply in self._replies.values():
            if not reply.done():
                reply.set_result(None)

        # Finalize drain futures
        self.resume_writing()

    def pause_writing(self) -> None:
        """Pauses writing to the stream connection."""
        self._paused = True

    def resume_writing(self) -> None:
        """Resumes writing to the stream connection."""
        self._paused = False

        for drainer in self._drainers:
            if not drainer.done():
                drainer.set_result(None)

        self._drainers.clear()

    def data_received(self, data: bytes) -> None:
        """Receives data from the stream connection."""
        # Minimum size of a DNS message with a length prefix
        MIN_PREFIXED_SIZE = 14

        # Add new data to the buffer
        buffer = self._buffer
        buffer.extend(data)

        # Process DNS messages in the buffer
        while True:
            # Ensure the buffer holds at least a minimum DNS reply
            buffer_size = len(buffer)
            if buffer_size < MIN_PREFIXED_SIZE:
                return

            # Peek the DNS message fields
            (msg_size, msg_id) = _peek_prefixed_packet(buffer)

            # Verify that the reported reply size is sane
            msg_size += 2
            if msg_size < MIN_PREFIXED_SIZE:
                # Corrupted/Malicious DNS message stream
                self._transport.abort()
                return

            # Ensure we have the a full DNS message
            if buffer_size < msg_size:
                return

            # Remove the message from the buffer
            message = buffer[2:msg_size]
            del buffer[:msg_size]

            # Set the result for the reply future
            reply = self._replies.get(msg_id)
            if reply is not None:
                if not reply.done():
                    reply.set_result(message)

    def eof_received(self) -> None:
        """Handles receiving EOF on the stream connection."""
        print(f'DEBUG: got EOF buffer={self._buffer!r}')
        self._transport.abort()

    @property
    def connected(self) -> bool:
        """Returns true IFF connected to the peer."""
        return self._connected

    def abort(self) -> None:
        """Aborts the stream connection."""
        if self._connected:
            self._transport.abort()

    async def aresolve(self, query: bytes) -> Awaitable[bytes]:
        """
        Resolve a DNS query via the stream connection peer.

        This coroutine can be safely cancelled.

        Args:
            query: The DNS query packet to resolve.

        Returns:
            The DNS reply packet.

        Raises:
            ConnectionError: If the query could not be resolved.
            TimeoutError: If a query resolution times out.
        """
        # Forbid duplicate query ids
        msg_id: int = _peek_packet(query)[0]
        assert msg_id not in self._replies

        # Create a new future for this query's reply
        reply = self._loop.create_future()
        reply.add_done_callback(ft.partial(self._reply_done, msg_id))
        self._replies[msg_id] = reply

        # Construct length prefixed DNS query packet
        query_size = len(query)
        prefixed_query = bytearray(query_size + 2)
        _prefix_packet(prefixed_query, 0, query_size)
        prefixed_query[2:] = query

        return await self._aresolution(prefixed_query, reply)

    def _reply_done(self, reply_id: int, reply: Future) -> None:
        """Finalizes tracking for a reply future when it completes."""
        del self._replies[reply_id]

    async def _aresolution(self, prefixed_query: bytes, reply: Future) -> Awaitable[bytes]:
        """DNS query resolution process."""
        try:
            # Ensure the transport stream is connected
            if not self._connected:
                raise ConnectionResetError('Connection lost')

            # Write the query to the transport stream
            self._transport.write(prefixed_query)
            await self._drain_writes()

            # Wait for the reply to be received
            data = await reply
            if data is None:
                raise ConnectionResetError('Connection lost')

            # Return reply packet
            return data

        except (aio.CancelledError, ConnectionError):
            reply.cancel()
            raise

    async def _drain_writes(self) -> Awaitable[None]:
        """Waits for buffered data to be flushed to the stream connection."""
        if not self._paused:
            return

        assert self._connected

        drainer = self._loop.create_future()
        self._drainers.append(drainer)
        await drainer


class TcpTunnel(AbstractTunnel):
    """DNS tunnel over TCP transport class."""
    # Maximum number of outstanding queries before new submissions will block
    MAX_QUERIES: int = 30000

    # Maximum time (in seconds) to allot to any single query resolution
    MAX_QUERY_TIME: float = 3.0

    def __init__(self, host: str, port: int) -> None:
        """
        Initializes a TcpTunnel instance.

        Args:
            host: The hostname or address of the tunnel peer.
            port: The port number to connect to.
        """
        super().__init__()

        self.host = str(host)
        self.port = int(port)

        self._limiter = aio.BoundedSemaphore(self.MAX_QUERIES)
        self._clock = aio.Lock()

        self._queries: MutableSet[int] = set()

        self._connected = utl.StateEvent()
        self._stream: Optional[Stream] = None

    def __repr__(self) -> str:
        return f'{self.__class__.__name__}({self.host!r}, {self.port!r})'

    @property
    def connected(self) -> bool:
        return self._connected.is_set()

    @property
    def queries(self) -> int:
        return len(self._queries)

    def _submit_query(self, query: bytes) -> Awaitable[bytes]:
        # Valid sizes of a DNS query without a length prefix
        MIN_QUERY_SIZE = 12
        MAX_QUERY_SIZE = 65535

        # Ensure that the query packet size is sane
        query_size = len(query)
        if query_size < MIN_QUERY_SIZE:
            raise ValueError('query - malformed query packet (too small)')
        elif query_size > MAX_QUERY_SIZE:
            raise ValueError('query - malformed query packet (too big)')

        # Forbid duplicate query ids
        msg_id: int = _peek_packet(query)[0]
        if msg_id in self._queries:
            raise ValueError(f'query - already processing message id 0x{msg_id:x} ({msg_id})')

        # Start tracking this query
        self._queries.add(msg_id)

        # Schedule the resolution of this query
        return self._loop.create_task(self._aresolution(query))

    async def _aresolution(self, query: bytes) -> Awaitable[bytes]:
        """Asynchronous query resolution process."""
        # Extract message id from query packet
        msg_id: int = _peek_packet(query)

        task = aio.current_task(self._loop)
        if task is not None:
            self._loop.call_later(self.MAX_QUERY_TIME, lambda: task.cancel())

        try:
            # Limit maximum outstanding queries
            async with self._limiter:
                # Attempt to resolve the query
                while True:
                    # Ensure that the tunnel is connected
                    if not await self._aconnect():
                        continue

                    # Resolve the query via the tunnel
                    try:
                        return await self._stream.aresolve(query)
                    except ConnectionError:
                        self._connected.clear()

        finally:
            self._queries.discard(msg_id)

    async def _aconnect(self, **kwargs) -> Awaitable[bool]:
        async with self._clock:
            # Only connect if currently disconnected
            if self.connected and self._stream.connected:
                return True

            # Establish a TCP connection
            try:
                (_, self._stream) = await self._loop.create_connection(
                    Stream,
                    self.host,
                    self.port,
                    **kwargs)

                self._connected.set()
                return True

            except ConnectionError:
                return False

    async def _adisconnect(self) -> Awaitable[None]:
        async with self._clock:
            # Only disconnect if currently connected
            if self.connected:
                if self._stream.connected:
                    self._stream.abort()

                self._connected.clear()


class TlsTunnel(TcpTunnel):
    """DNS tunnel over TLS transport class."""
    def __init__(self, host: str, port: int, authname: str, cafile: Optional[str] = None) -> None:
        """
        Initialize a TlsTunnel instance.

        Args:
            host: The hostname or address of the tunnel peer.
            port: The port number to connect to.
            authname: The name used to authenticate the peer.
            cafile: The file path to CA certificates (in PEM format) used to authenticate the peer.
        """
        super().__init__(host, port)

        self.authname = str(authname)
        self.cafile = cafile

        self._context = ssl.create_default_context(cafile=self.cafile)
        self._context.check_hostname = True

    def __repr__(self) -> str:
        r = f'{self.__class__.__name__}({self.host!r}, {self.port!r}, {self.authname!r}'
        if self.cafile is not None: r += f', {self.cafile!r}'
        return r + ')'

    async def _aconnect(self) -> Awaitable[bool]:
        try: return await super()._aconnect(ssl=self._context, server_hostname=self.authname)
        except ssl.SSLError: return False
