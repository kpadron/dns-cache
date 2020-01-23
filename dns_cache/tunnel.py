import asyncio as aio
import logging
import ssl
import struct
from abc import ABCMeta, abstractmethod
from asyncio import Future, Protocol, Transport
from functools import cached_property
from typing import (Awaitable, Collection, Iterable, MutableMapping,
                    MutableSequence, MutableSet, Optional, Tuple)

from . import utility as utl

logger = logging.getLogger(__name__)

__all__ = \
[
    'AbstractTunnel',
    'TcpTunnel',
    'TlsTunnel',
]


# Functions used to peek and manipulate DNS messages
_peek_packet = struct.Struct('!H').unpack_from
_prefix_packet = struct.Struct('!H').pack
_peek_prefixed_packet = struct.Struct('!HH').unpack_from


class AbstractTunnel(metaclass=ABCMeta):
    """
    DNS transport tunnel abstract base class.

    Pure Virtual Properties:
        connected: Whether the tunnel is connected or not.
        queries: A read-only view of the current outstanding queries.

    Pure Virtual Methods:
        __init__: Initializes a new tunnel instance.
        aopen: Establishes the tunnel connection.
        close: Closes the tunnel connection.
        submit_query: Submits a DNS query to be resolved.
    """
    __slots__ = '_loop'

    @abstractmethod
    def __init__(self) -> None:
        """Initializes a AbstractTunnel instance."""
        self._loop = aio.get_event_loop()

    def __enter__(self) -> 'AbstractTunnel':
        """Enter context."""
        self.open()
        return self

    def __exit__(self, *args) -> None:
        """Exit context."""
        self.close()

    async def __aenter__(self) -> Awaitable['AbstractTunnel']:
        """Enter async context."""
        await self.aopen()
        return self

    async def __aexit__(self, *args) -> Awaitable[None]:
        """Exit async context."""
        self.close()

    @property
    @abstractmethod
    def connected(self) -> bool:
        """Returns true if and only if the tunnel connection is established."""
        raise NotImplementedError

    @property
    @abstractmethod
    def queries(self) -> Collection[int]:
        """Returns a read-only view of the queries currently tracked by the instance."""
        raise NotImplementedError

    def open(self, timeout: Optional[float] = None) -> None:
        """
        Establishes the tunnel connection to the peer.

        This method is idempotent.

        Args:
            timeout: A relative deadline for the operation (in seconds).

        Raises:
            ConnectionError: Failed to establish the tunnel connection.
            TimeoutError: Failed to complete the operation by the deadline.
        """
        if timeout is not None:
            timeout = float(timeout)

        if not self.connected:
            try:
                self._loop.run_until_complete(aio.wait_for(self.aopen(), timeout))

            except aio.TimeoutError as exc:
                raise TimeoutError from exc

    @abstractmethod
    def close(self) -> None:
        """
        Closes the tunnel connection to the peer.

        This method is idempotent.

        Raises:
            ConnectionError: Failed to cleanly close the tunnel connection.
            TimeoutError: Failed to complete the operation by the deadline.
        """
        raise NotImplementedError

    @abstractmethod
    def submit_query(self, query: bytes) -> Awaitable[bytes]:
        """
        Submits a DNS query for resolution via the tunnel.

        Args:
            query: The DNS query packet to resolve.

        Returns:
            A awaitable object that represents the eventual result of the resolution.

            When awaited the object yields the reply packet or raises ConnectionError.

            The awaitable object can be safely cancelled.

        Raises:
            ValueError: Given query packet is invalid.
        """
        raise NotImplementedError

    def complete_query(self, pending_reply: Awaitable[bytes], timeout: Optional[float] = None) -> bytes:
        """
        Completes a DNS query resolution previously submitted to the instance.

        Args:
            pending_reply: The awaitable object returned by submit_query.
            timeout: A relative deadline for the operation (in seconds).

        Returns:
            The DNS reply packet.

        Raises:
            ConnectionError: Failed to resolve query due to broken tunnel connection.
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
        Resolves a DNS query via the tunnel.

        Args:
            query: The DNS query packet to resolve.
            timeout: A relative deadline for the operation (in seconds).

        Returns:
            The DNS reply packet.

        Raises:
            ValueError: Given query packet is invalid.
            ConnectionError: Failed to resolve query due to broken tunnel connection.
            TimeoutError: Failed to complete the operation by the deadline.
        """
        if timeout is not None:
            timeout = float(timeout)

        try:
            return self._loop.run_until_complete(aio.wait_for(self.submit_query(query), timeout))

        except aio.TimeoutError as exc:
            raise TimeoutError from exc

    @abstractmethod
    async def aopen(self) -> Awaitable[None]:
        """
        Establishes the tunnel connection to the peer.

        This method is idempotent.

        This coroutine can be safely cancelled.

        Raises:
            ConnectionError: Failed to establish the tunnel connection.
        """
        raise NotImplementedError


class Stream(Protocol):
    """DNS over stream-based transport protocol."""
    __slots__ = \
        (
            '_loop',
            '_connected',
            '_paused',
            '_transport',
            '_peer',
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
        self._peer = None
        self._buffer = bytearray()

        self._drainers: MutableSequence[Future] = []
        self._replies: MutableMapping[int, Future] = {}

    @property
    def connected(self) -> bool:
        """Returns true if and only if connected to the peer."""
        return self._connected

    @property
    def peer(self) -> Optional[Tuple[str, int]]:
        """Returns stream peer information."""
        return self._peer

    def connection_made(self, transport: Transport) -> None:
        """Initializes the stream connection."""
        self._transport = transport
        self._peer = transport.get_extra_info('peername')
        self._connected = True

        logger.info(f'<{self.__class__.__name__} {id(self)} {self._peer}> Connection established')

    def connection_lost(self, exc: Optional[Exception]) -> None:
        """Deinitializes the stream connection."""
        logger.info(f'<{self.__class__.__name__} {id(self)} {self._peer}> Connection lost')

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
        logger.debug(f'<{self.__class__.__name__} {id(self)} {self._peer}> Writing paused')

        self._paused = True

    def resume_writing(self) -> None:
        """Resumes writing to the stream connection."""
        logger.debug(f'<{self.__class__.__name__} {id(self)} {self._peer}> Writing resumed')

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

        logger.debug(f'<{self.__class__.__name__} {id(self)} {self._peer}> Data received - len(data)={len(data)}, len(buffer)={len(buffer)}')

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

            logger.debug(f'<{self.__class__.__name__} {id(self)} {self._peer}> Message received - msg_size={msg_size}, msg_id={msg_id}')

            # Set the result for the reply future
            reply_future = self._replies.get(msg_id)
            if reply_future is not None and not reply_future.done():
                reply_future.set_result(message)

    def eof_received(self) -> None:
        """Handles receiving EOF on the stream connection."""
        logger.info(f'<{self.__class__.__name__} {id(self)} {self._peer}> EOF received - buffer={self._buffer!r}')
        self._transport.abort()

    def abort(self) -> None:
        """Aborts the stream connection."""
        if self._connected:
            logger.info(f'<{self.__class__.__name__} {id(self)} {self._peer}> Aborting connection')
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
            ConnectionError: Failed to resolve query due to broken stream connection.
        """
        # Ensure the transport stream is connected
        if not self._connected:
            raise ConnectionError('Stream is not connected')

        # Extract query message id
        (_, msg_id) = _peek_prefixed_packet(prefixed_query)

        assert msg_id not in self._replies

        # Create a new future for this query's reply
        reply_future = self._loop.create_future()
        self._replies[msg_id] = reply_future

        try:
            # Async checkpoint (can be cancelled or disconnected here)
            await aio.sleep(0)

            # Ensure the transport
            if not self._connected:
                raise ConnectionResetError('Stream connection was broken')

            # Write the query to the transport stream
            self._transport.write(prefixed_query)
            await self._drain_writes()

            # Wait for the reply to be received
            prefixed_reply = await reply_future
            if prefixed_reply is None:
                raise ConnectionResetError('Stream connection was broken')

            # Return reply packet
            return prefixed_reply

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

        self._limiter = aio.Semaphore(self.MAX_QUERIES)
        self._clock = aio.Lock()

        self._queries: MutableSet[int] = set()

        self._stream: Optional[Stream] = None

    def __repr__(self) -> str:
        return f'{self.__class__.__name__}({self.host!r}, {self.port!r})'

    @property
    def connected(self) -> bool:
        return self._stream is not None and self._stream.connected

    @cached_property
    def queries(self) -> Collection[int]:
        return utl.CollectionView(self._queries)

    def submit_query(self, query: bytes) -> Awaitable[bytes]:
        # Valid sizes of a DNS query without a length prefix
        MIN_QUERY_SIZE = 12
        MAX_QUERY_SIZE = 65535

        # Ensure that the query packet size is sane
        query_size = len(query)
        if query_size < MIN_QUERY_SIZE:
            raise ValueError('Malformed query packet (too small)')
        elif query_size > MAX_QUERY_SIZE:
            raise ValueError('Malformed query packet (too big)')

        # Forbid duplicate query ids
        msg_id: int = _peek_packet(query)[0]
        if msg_id in self._queries:
            raise ValueError(f'Already processing message id 0x{msg_id:04x} ({msg_id})')

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
                        if not self.connected:
                            await self.aopen()

                        # Resolve the query via the stream tunnel
                        stream = self._stream
                        prefixed_reply = await stream.aresolve(prefixed_query)

                        # Return the unprefixed reply packet
                        return prefixed_reply[2:]

                    except ConnectionRefusedError:
                        raise

                    except ConnectionError:
                        if stream is self._stream:
                            self._stream = None

        finally:
            self._queries.discard(msg_id)

    async def aopen(self, **kwargs) -> Awaitable[None]:
        async with self._clock:
            # Only open if currently closed
            if not self.connected:
                # Establish a TCP connection
                try:
                    (_, self._stream) = await self._loop.create_connection(
                        Stream,
                        self.host,
                        self.port,
                        **kwargs)

                except Exception as exc:
                    if not isinstance(exc, ConnectionError):
                        raise ConnectionError from exc

    def close(self) -> None:
        # Only close if currently open
        if self.connected:
            try:
                self._stream.abort()
                self._stream = None

            except Exception as exc:
                if not isinstance(exc, ConnectionError):
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

    async def aopen(self) -> Awaitable[None]:
        await super().aopen(ssl=self._context, server_hostname=self.authname)
