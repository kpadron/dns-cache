import asyncio as aio
import functools as ft
import ssl
import struct
from abc import ABCMeta, abstractmethod
from asyncio import Future, Protocol, Transport
from typing import (Awaitable, Collection, Iterable, MutableMapping,
                    MutableSequence, MutableSet, Optional)

from . import utility as utl

__all__ = \
[
    'AbstractTunnel',
    'TcpTunnel',
    'TlsTunnel',
]


class AbstractTunnel(metaclass=ABCMeta):
    """
    DNS transport tunnel abstract base class.

    Pure Virtual Properties:
        connected: Whether the tunnel is connected or not.
        queries: A read-only view of the current outstanding queries.

    Pure Virtual Methods:
        __init__: Initializes a new class instance.
        _submit_query: Submits a DNS query to be resolved.
        _aconnect: Connects to the tunnel peer.
        _adisconnect: Disconnects from the tunnel peer.
    """
    __slots__ = ('_loop')

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

    def __exit__(self, *args) -> None:
        """Exit context."""
        self.disconnect()

    async def __aenter__(self) -> Awaitable['AbstractTunnel']:
        """Enter async context."""
        await self.aconnect()
        return self

    async def __aexit__(self, *args) -> Awaitable[None]:
        """Exit async context."""
        await self.adisconnect()

    @property
    @abstractmethod
    def connected(self) -> bool:
        """Returns true if the instance is connected to the peer."""
        pass

    @property
    @abstractmethod
    def queries(self) -> Collection:
        """Returns a read-only view of the queries currently tracked by the instance."""
        pass

    def connect(self, timeout: Optional[float] = None) -> None:
        """
        Synchronously connect to the peer.

        Raises:
            ConnectionError: Failed to establish a tunnel connection to the peer.
            TimeoutError: Failed to complete the operation by the deadline.
        """
        return self._loop.run_until_complete(self.aconnect(timeout))

    def disconnect(self, timeout: Optional[float] = None) -> None:
        """
        Synchronously disconnect from the peer.

        Raises:
            ConnectionError: Failed to establish a tunnel connection to the peer.
            TimeoutError: Failed to complete the operation by the deadline.
        """
        return self._loop.run_until_complete(self.adisconnect(timeout))

    def submit_query(self, query: bytes) -> Awaitable[bytes]:
        """
        Submit a DNS query for resolution via the peer.

        Args:
            query: The DNS query packet to resolve.

        Returns:
            A awaitable object that represents the eventual result of the resolution.
            When awaited the object yields the reply packet or raises a ConnectionError
            exception.

        Raises:
            ValueError: If the query packet is invalid.
        """
        return utl.AwaitableView(self._submit_query(query))

    def complete_query(self, pending_reply: Awaitable[bytes], timeout: Optional[float] = None) -> bytes:
        """
        Synchronously completes a DNS query previously submitted.

        Args:
            pending_reply: The awaitable returned by submit_query.

        Returns:
            The DNS reply packet.

        Raises:
            ConnectionError: Failed to resolve the query via the tunnel peer.
            TimeoutError: Failed to complete the operation by the deadline.
        """
        if timeout is not None:
            timeout = float(timeout)

        try:
            return self._loop.run_until_complete(aio.wait_for(pending_reply, timeout))

        except aio.TimeoutError as exc:
            raise TimeoutError from exc

    def resolve_query(self, query: bytes, timeout: Optional[float] = None) -> bytes:
        """
        Synchronously resolve a DNS query via the peer.

        Args:
            query: The DNS query packet to resolve.

        Returns:
            The DNS reply packet.

        Raises:
            ValueError: If the query packet is invalid.
            ConnectionError: Failed to resolve the query via the tunnel peer.
            TimeoutError: Failed to complete the operation by the deadline.
        """
        return self._loop.run_until_complete(self.aresolve_query(query, timeout))

    async def aconnect(self, timeout: Optional[float] = None) -> Awaitable[None]:
        """
        Asynchronously connect to the peer.

        Raises:
            ConnectionError: Failed to establish a tunnel connection to the peer.
            TimeoutError: Failed to complete the operation by the deadline.
        """
        if timeout is not None:
            timeout = float(timeout)

        try:
            await aio.wait_for(self._aconnect(), timeout)

        except aio.TimeoutError as exc:
            raise TimeoutError from exc

    async def adisconnect(self, timeout: Optional[float] = None) -> Awaitable[None]:
        """
        Asynchronously disconnect from the peer.
        
        Raises:
            ConnectionError: Failed to close the tunnel connection to the peer.
            TimeoutError: Failed to complete the operation by the deadline.
        """
        if timeout is not None:
            timeout = float(timeout)

        try:
            await aio.wait_for(self._adisconnect(), timeout)

        except aio.TimeoutError as exc:
            raise TimeoutError from exc

    async def aresolve_query(self, query: bytes, timeout: Optional[float] = None) -> Awaitable[bytes]:
        """
        Asynchronously resolve a DNS query.

        Args:
            query: The DNS query packet to resolve.

        Returns:
            The DNS reply packet.

        Raises:
            ValueError: If the query packet is invalid.
            ConnectionError: Failed to resolve the query via the tunnel peer.
            TimeoutError: Failed to complete the operation by the deadline.
        """
        if timeout is not None:
            timeout = float(timeout)

        try:
            return await aio.wait_for(self._submit_query(query), timeout)

        except aio.TimeoutError as exc:
            raise TimeoutError from exc

    @abstractmethod
    def _submit_query(self, query: bytes) -> Awaitable[bytes]:
        """
        Submit a DNS query for resolution via the peer.

        Args:
            query: The DNS query packet to resolve.

        Returns:
            A awaitable object that represents the eventual result of the resolution.
            When awaited the object yields the reply packet or raises a ConnectionError
            exception.

        Raises:
            ValueError: If the query packet is invalid.
        """
        pass

    @abstractmethod
    async def _aconnect(self) -> Awaitable[None]:
        """
        Asynchronously connect to the peer.

        Raises:
            ConnectionError: Failed to establish a tunnel connection to the peer.
        """
        pass

    @abstractmethod
    async def _adisconnect(self) -> Awaitable[None]:
        """
        Asynchronously disconnect from the peer.

        Raises:
            ConnectionError: Failed to close the tunnel connection to the peer.
        """
        pass


# Functions used to peek and manipulate DNS messages
_peek_packet = struct.Struct('!H').unpack_from
_prefix_packet = struct.Struct('!H').pack
_peek_prefixed_packet = struct.Struct('!HH').unpack_from


class Stream(Protocol):
    """DNS over stream-based transport protocol."""
    __slots__ = \
        (
            '_loop',
            '_connected',
            '_paused',
            '_transport',
            '_buffer',
            '_drainers',
            '_replies',
        )

    def __init__(self) -> None:
        """Initializes a Stream protocol instance."""
        self._loop = aio.get_running_loop()

        self._connected = False
        self._paused = False

        self._transport: Optional[Transport] = None
        self._buffer = bytearray()

        self._drainers: MutableSequence[Future] = []
        self._replies: MutableMapping[int, Future] = {}

    def connection_made(self, transport: Transport) -> None:
        """Initializes the stream connection."""
        print(f'DEBUG {self._loop.time()}: {id(self)} connection established')
        self._transport = transport
        self._connected = True

    def connection_lost(self, exc: Optional[Exception]) -> None:
        """Deinitializes the stream connection."""
        print(f'DEBUG {self._loop.time()}: {id(self)} connection lost')
        self._connected = False

        # Ensure the tranport is closed
        self._transport.abort()
        self._transport = None

        # Finalize reply futures
        for reply_future in self._replies.values():
            if not reply_future.done():
                reply_future.set_result(None)

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
            # Ensure the buffer holds at least a minimum DNS message
            buffer_size = len(buffer)
            if buffer_size < MIN_PREFIXED_SIZE:
                return

            # Peek the DNS message fields
            (msg_size, msg_id) = _peek_prefixed_packet(buffer)

            # Verify that the reported message size is sane
            msg_size += 2
            if msg_size < MIN_PREFIXED_SIZE:
                # Corrupted/Malicious DNS message stream
                self._transport.abort()
                return

            # Ensure we have the a full DNS message
            if buffer_size < msg_size:
                return

            # Remove the message from the buffer
            message = buffer[:msg_size]
            del buffer[:msg_size]

            # Set the result for the reply future
            reply_future = self._replies.get(msg_id)
            if reply_future is not None and not reply_future.done():
                reply_future.set_result(message)

    def eof_received(self) -> None:
        """Handles receiving EOF on the stream connection."""
        print(f'DEBUG {self._loop.time()}: {id(self)} got EOF buffer={self._buffer!r}')
        self._transport.abort()

    @property
    def connected(self) -> bool:
        """Returns true IFF connected to the peer."""
        return self._connected

    def abort(self) -> None:
        """Aborts the stream connection."""
        if self._connected:
            self._transport.abort()

    async def aresolve(self, prefixed_query: bytes) -> Awaitable[bytes]:
        """
        Resolve a DNS query via the stream connection peer.

        This coroutine can be safely cancelled.

        Args:
            prefixed_query: The length-prefixed DNS query packet to resolve.

        Returns:
            The length-prefixed DNS reply packet.

        Raises:
            ConnectionError: If the query could not be resolved
                             due to a stream connection error.
        """
        # Ensure the transport stream is connected
        if not self._connected:
            raise ConnectionResetError('Connection lost')

        # Forbid duplicate query ids
        (_, msg_id) = _peek_prefixed_packet(prefixed_query)
        assert msg_id not in self._replies

        # Create a new future for this query's reply
        reply_future = self._loop.create_future()
        self._replies[msg_id] = reply_future

        try:
            # Write the query to the transport stream
            self._transport.write(prefixed_query)
            await self._drain_writes()

            # Wait for the reply to be received
            prefixed_reply = await reply_future
            if prefixed_reply is None:
                raise ConnectionResetError('Connection lost')

            # Return reply packet
            return prefixed_reply

        except (aio.CancelledError, ConnectionError):
            reply_future.cancel()
            raise

        finally:
            del self._replies[msg_id]

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
    MAX_QUERIES: int = 10000

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

        self._connected = False

        self._limiter = aio.BoundedSemaphore(self.MAX_QUERIES)
        self._clock = aio.Lock()

        self._queries: MutableSet[int] = set()

        self._stream: Optional[Stream] = None

    def __repr__(self) -> str:
        return f'{self.__class__.__name__}({self.host!r}, {self.port!r})'

    @property
    def connected(self) -> bool:
        return self._stream is not None and self._stream.connected

    @property
    def queries(self) -> Collection[int]:
        return utl.CollectionView(self._queries)

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

        # Construct the length-prefixed query packet
        prefixed_query = _prefix_packet(query_size) + query

        # Start tracking this query
        self._queries.add(msg_id)

        # Schedule the resolution of this query
        return self._loop.create_task(self._aresolution(prefixed_query, msg_id))

    async def _aresolution(self, prefixed_query: bytes, msg_id: int) -> Awaitable[bytes]:
        """Asynchronous query resolution process."""
        try:
            # Limit maximum outstanding queries
            async with self._limiter:
                # Attempt to resolve the query
                while True:
                    try:
                        # Ensure that the tunnel is connected
                        await self._aconnect()

                        # Resolve the query via the tunnel
                        return (await self._stream.aresolve(prefixed_query))[2:]

                    except ConnectionError:
                        self._stream = None

        finally:
            self._queries.discard(msg_id)

    async def _aconnect(self, **kwargs) -> Awaitable[None]:
        async with self._clock:
            # Only connect if currently disconnected
            if self.connected:
                return True

            # Establish a TCP connection
            try:
                (_, self._stream) = await self._loop.create_connection(
                    Stream,
                    self.host,
                    self.port,
                    **kwargs)

            except Exception as exc:
                raise ConnectionError from exc

    async def _adisconnect(self) -> Awaitable[None]:
        async with self._clock:
            # Only disconnect if currently connected
            if self.connected:
                try:
                    self._stream.abort()

                except Exception as exc:
                    raise ConnectionError from exc


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

    async def _aconnect(self) -> Awaitable[None]:
        await super()._aconnect(ssl=self._context, server_hostname=self.authname)
