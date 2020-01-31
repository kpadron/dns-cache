import asyncio as aio
import logging
import ssl
import struct
from abc import ABC, abstractmethod
from asyncio import Future, Transport
from typing import (Awaitable, Collection, Iterable, MutableMapping,
                    MutableSet, Optional, Tuple)

from .protocol import AbstractStreamProtocol

__all__ = \
    (
        'AbstractTunnel',
        'TcpTunnel',
        'TlsTunnel',
    )


logger = logging.getLogger(__name__)


class AbstractTunnel(ABC):
    """
    DNS transport tunnel abstract base class.

    Pure Virtual Properties:
        connected: Whether the tunnel is connected or not.
        queries: A snapshot view of the current outstanding queries.

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
        """Returns a snapshot view of the queries currently tracked by the instance."""
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


class Stream(AbstractStreamProtocol):
    """DNS over stream-based transport protocol."""

    __slots__ = \
        (
            '_peer',
            '_replies',
        )

    def __init__(self) -> None:
        """Initializes a Stream protocol instance."""
        super().__init__()

        self._peer: Optional[Tuple[str, int]] = None
        self._replies: MutableMapping[int, Future] = {}

    @property
    def peer(self) -> Optional[Tuple[str, int]]:
        """Returns stream peer information."""
        return self._peer

    def connection_made(self, transport: Transport) -> None:
        """Initializes the stream connection."""
        super().connection_made(transport)

        self._peer = transport.get_extra_info('peername')
        self.schedule_closer()

        logger.info(f'<{self.__class__.__name__} {id(self):x} {self._peer}> Connection established')

    def connection_lost(self, exc: Optional[Exception]) -> None:
        """Deinitializes the stream connection."""
        logger.info(f'<{self.__class__.__name__} {id(self):x} {self._peer}> Connection lost')

        self._peer = None

        transport = self._transport
        replies = self._replies
        super().connection_lost(exc)

        # Ensure the tranport is closed
        transport.abort()

        # Finalize reply futures
        for reply_future in replies.values():
            if not reply_future.done():
                reply_future.set_result(None)

        replies.clear()

    def eof_received(self) -> None:
        logger.info(f'<{self.__class__.__name__} {id(self):x} {self._peer}> EOF received - buffer={self._buffer!r}')
        self._transport.abort()

    def abort(self) -> None:
        """Aborts the stream connection."""
        if self._connected:
            logger.info(f'<{self.__class__.__name__} {id(self):x} {self._peer}> Aborting connection')
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
            ConnectionError: Failed to resolve query due to broken stream connection.
        """
        # Ensure the transport stream is connected
        if not self._connected:
            raise ConnectionError('Stream is not connected')

        # Extract query message id
        msg_id: int = struct.unpack_from('!H', query)[0]

        assert msg_id not in self._replies

        # Create a new future for this query's reply
        reply_future = self._loop.create_future()
        self._replies[msg_id] = reply_future

        # Cancel the closer since there are now outstanding queries
        self.cancel_closer()

        try:
            # Async checkpoint (check for cancellation or broken stream)
            await aio.sleep(0)

            # Ensure the transport stream is connected
            if not self._connected:
                raise ConnectionResetError('Stream connection was broken')

            # Write the query to the transport stream
            self.write_message(query)
            await self._drain_writes()

            # Wait for the reply to be received
            reply = await reply_future
            if reply is None:
                raise ConnectionResetError('Stream connection was broken')

            # Return the reply packet
            return reply

        except aio.CancelledError:
            reply_future.cancel()
            raise

    def _message_received(self, message: bytes):
        # Set the result for the reply future
        msg_id: int = struct.unpack_from('!H', message)[0]
        reply_future = self._replies.get(msg_id)
        if reply_future is not None:
            if not reply_future.done():
                reply_future.set_result(message)

            del self._replies[msg_id]

        # Schedule the closer if there are no outstanding queries
        if not self._replies:
            self.schedule_closer()


class TcpTunnel(AbstractTunnel):
    """DNS tunnel over TCP transport class."""

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

        self._limiter = aio.Semaphore(10000)
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
        return set(self._queries)

    def submit_query(self, query: bytes) -> Awaitable[bytes]:
        async def aresolution() -> Awaitable[bytes]:
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
                            return await stream.aresolve(query)

                        except ConnectionRefusedError:
                            raise

                        except ConnectionError:
                            if stream is self._stream:
                                self._stream = None

            finally:
                self._queries.discard(msg_id)

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
        msg_id: int = struct.unpack_from('!H', query)[0]
        if msg_id in self._queries:
            raise ValueError(f'Already processing message id 0x{msg_id:04x} ({msg_id})')

        # Start tracking this query
        self._queries.add(msg_id)

        # Schedule the resolution of this query
        return self._loop.create_task(aresolution())

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
                    if isinstance(exc, ConnectionError):
                        raise

                    raise ConnectionError from exc

    def close(self) -> None:
        # Only close if currently open
        if self.connected:
            stream = self._stream
            self._stream = None

            try:
                stream.abort()

            except Exception as exc:
                if isinstance(exc, ConnectionError):
                    raise

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
