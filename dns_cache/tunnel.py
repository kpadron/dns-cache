import asyncio as aio
import functools as ft
import ssl
import struct
from abc import ABC, abstractmethod
from typing import (Awaitable, Collection, Iterable, MutableMapping, Optional,
                    Sequence, Tuple, Union)

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
        queries: The current number of outstanding queries.

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

    async def __aenter__(self) -> 'AbstractTunnel':
        """Enter async context."""
        await self.aconnect()
        return self

    async def __aexit__(self, exc_type, exc_value, exc_trace) -> None:
        """Exit async context."""
        await self.adisconnect()

    @property
    @abstractmethod
    def connected(self) -> bool:
        """Returns true if the instance is connected to the peer."""
        ...

    @property
    @abstractmethod
    def queries(self) -> int:
        """Returns the current number of outstanding queries."""
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


class TcpTunnel(AbstractTunnel, aio.Protocol):
    """DNS tunnel over TCP transport class."""
    # Maximum number of outstanding queries before new submissions will block
    MAX_QUERIES: int = 30000

    # Maximum time (in seconds) to allot to any single query resolution
    MAX_QUERY_TIME: float = 3.0

    # Struct objects used to peek and manipulate DNS message fields
    _peeker = struct.Struct('!H').unpack_from
    _prefixer = struct.Struct('!H').pack_into
    _prefixed_peeker = struct.Struct('!HH').unpack_from

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

        self._futures: MutableMapping[int, aio.Future] = {}

        self._limiter = aio.BoundedSemaphore(self.MAX_QUERIES)
        self._clock = aio.Lock()

        self._connected = utl.StateEvent()
        self._paused = utl.StateEvent()
        self._buffer = bytearray()
        self._transport: aio.Transport = None

    def __repr__(self) -> str:
        return f'{self.__class__.__name__}({self.host!r}, {self.port!r})'

    @property
    def connected(self) -> bool:
        return self._connected.is_set()

    @property
    def queries(self) -> int:
        return len(self._futures)

    def connection_made(self, transport: aio.Transport) -> None:
        """Initializes the tunnel connection."""
        self._transport = transport
        self._connected.set()

    def connection_lost(self, exc: Exception) -> None:
        """Deinitializes the tunnel connection."""
        self._connected.clear()
        self._paused.clear()
        self._buffer.clear()
        self._transport = None

    def pause_writing(self) -> None:
        """Pauses writing to the tunnel connection."""
        self._paused.set()

    def resume_writing(self) -> None:
        """Resumes writing to the tunnel connection."""
        self._paused.clear()

    def data_received(self, data: bytes) -> None:
        """Receives data from the tunnel connection."""
        # Minimum size of a DNS reply with a length prefix
        MIN_REPLY_SIZE = 14

        # Add new data to the buffer
        buffer = self._buffer
        buffer.extend(data)

        print(f'DEBUG: added {len(data)} bytes to buffer {len(buffer)}')

        # Process DNS reply messages in the buffer
        while True:
            # Ensure the buffer holds at least a minimum DNS reply
            buffer_size = len(buffer)
            if buffer_size < MIN_REPLY_SIZE:
                return

            # Peek the DNS message fields
            (reply_size, reply_id) = self._prefixed_peeker(buffer)

            # Verify that the reported reply size is sane
            reply_size += 2
            if reply_size < MIN_REPLY_SIZE:
                # TODO: consider aborting the tunnel
                # connection due to corrupted/malicious
                # DNS message stream
                raise NotImplementedError('corrupted/malicious message stream should probably abort the connection')

            # Ensure we have the full DNS reply message
            if buffer_size < reply_size:
                return

            # Set the reply as the matching future's result
            future = self._futures.get(reply_id)
            if future is not None and not future.done():
                future.set_result(buffer[2:reply_size])

            # Remove the DNS reply from the buffer
            del buffer[:reply_size]

    def eof_received(self) -> None:
        """Handles receiving EOF on the tunnel connection."""
        print(f'DEBUG: got EOF buffer={self._buffer!r}')
        self._transport.abort()

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
        query_id: int = self._peeker(query)[0]
        if query_id in self._futures:
            raise ValueError('query - already processing query id 0x%x (%d)' % (query_id, query_id))

        # Construct length prefixed DNS query packet
        prefixed_query = bytearray(query_size + 2)
        self._prefixer(prefixed_query, 0, query_size)
        prefixed_query[2:] = query

        # Create a new future for this query
        future_reply = self._loop.create_future()

        # Add the future to tracking and setup finalizer
        future_reply.add_done_callback(ft.partial(self._reply_done, query_id))
        self._futures[query_id] = future_reply

        # Schedule the resolution of this query
        resolution = self._loop.create_task(self._aresolution(prefixed_query, future_reply))

        # Bound the resources used by this query
        self._loop.call_later(self.MAX_QUERY_TIME, lambda: resolution.cancel())

        # Return the future query reply
        return future_reply

    def _reply_done(self, query_id: int, future_reply: aio.Future) -> None:
        """Finalizes tracking for a future reply when it completes."""
        del self._futures[query_id]

        if future_reply.result() == b'':
            print(f'DEBUG: future reply {query_id} cancelled')
        else:
            print(f'DEBUG: future reply {query_id} done')

    async def _aresolution(self, prefixed_query: bytes, future_reply: aio.Future) -> Awaitable[None]:
        """Asynchronous query resolution process."""
        try:
            # Limit maximum outstanding queries
            async with self._limiter:
                # Attempt to resolve the query
                while not future_reply.done():
                    # Send the query packet through the tunnel
                    if not await self._awrite_query(prefixed_query):
                        continue

                    # Receive the reply packet from the tunnel
                    await self._await_reply(future_reply)

        # Finalize the future if the resolution was cancelled
        except aio.CancelledError:
            if not future_reply.done():
                future_reply.set_result(b'')

            raise

    async def _awrite_query(self, prefixed_query: bytes) -> Awaitable[bool]:
        """Writes a length prefixed DNS query packet to the tunnel."""
        # Connect to the peer if necessary
        if not self.connected and not await aio.shield(self.aconnect()):
            return False

        # Wait for writing to be resumed if necessary
        await self._paused.wait_false()

        # Connection is closed so report failure
        transport = self._transport
        if not self.connected or transport.is_closing():
            return False

        # Write the DNS query packet and report success
        try: transport.write(prefixed_query)
        except ConnectionError: return False

        return True

    async def _await_reply(self, future_reply: aio.Future) -> Awaitable[bool]:
        """Waits for the matching reply or a tunnel disconnection."""
        # Schedule competing futures
        shielded_reply = aio.shield(future_reply)
        disconnect = self._loop.create_task(self._connected.wait_false())

        # Wait for the first future to finish
        (done, _) = await aio.wait((shielded_reply, disconnect), return_when=aio.FIRST_COMPLETED)
        disconnect.cancel()

        # Return true if the reply future is finished
        return shielded_reply in done

    async def _aconnect(self, **kwargs) -> Awaitable[bool]:
        async with self._clock:
            # Only connect if currently disconnected
            if self.connected:
                return True

            # Establish a TCP connection
            try: await self._loop.create_connection(lambda: self, self.host, self.port, **kwargs)
            except ConnectionError: return False

            return True

    async def _adisconnect(self) -> Awaitable[None]:
        async with self._clock:
            # Only disconnect if currently connected
            if not self.connected:
                return

            # Close the TCP connection
            self._transport.abort()
            await self._connected.wait_false()


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
