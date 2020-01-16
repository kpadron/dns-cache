import asyncio as aio
import ssl
from abc import ABC, abstractmethod
from typing import (Awaitable, Collection, MutableMapping, Optional, Tuple,
                    Union)

import dns_util as du

__all__ = \
[
    'BaseTunnel',
    'TcpTunnel',
    'TlsTunnel',
]


class BaseTunnel(ABC):
    """
    DNS transport tunnel abstract base class.

    Pure Virtual Properties:
        connected: Whether the tunnel is connected or not.
        queries: View of the outstanding queries.

    Pure Virtual Methods:
        __init__: Initializes a new class instance.
        submit_query: Submits a DNS query to be resolved.
        _aconnect: Connects to the tunnel peer.
        _adisconnect: Disconnects from the tunnel peer.
    """
    # Maximum amount of time (in seconds) to wait for a tunnel operation
    DEFAULT_TIMEOUT: float = 3.0

    @abstractmethod
    def __init__(self) -> None:
        """Initializes a BaseTunnel instance."""
        self._loop = aio.get_event_loop()

    def __enter__(self) -> 'BaseTunnel':
        """Enter context."""
        self.connect()
        return self

    def __exit__(self, exc_type, exc_value, exc_trace) -> None:
        """Exit context."""
        self.disconnect()

    async def __aenter__(self) -> 'BaseTunnel':
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
    def queries(self) -> Collection[int]:
        """Returns a read-only view of the outstanding queries."""
        ...

    def connect(self) -> bool:
        """
        Synchronously connect to the peer.

        Returns:
            True if connected to the peer, False otherwise.
        """
        return self._loop.run_until_complete(self.aconnect())

    def disconnect(self) -> bool:
        """
        Synchronously disconnect from the peer.

        Returns:
            True if disconnected from the peer, False otherwise.
        """
        return self._loop.run_until_complete(self.adisconnect())

    @abstractmethod
    def submit_query(self, query: bytes) -> Awaitable[bytes]:
        """
        Submit a DNS query for resolution via the peer.

        Args:
            query: The DNS query packet to resolve.

        Returns:
            A awaitable object that represents the eventual result of the resolution.
            When awaited the object yields the response packet or an empty bytestring on error.
        """
        ...

    def resolve_query(self, query: bytes) -> bytes:
        """
        Synchronously resolve a DNS query via the peer.

        Args:
            query: The DNS query packet to resolve.

        Returns:
            The DNS response packet or empty bytestring on error.
        """
        return self._loop.run_until_complete(self.submit_query(query))

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
        try: return await aio.wait_for(self.submit_query(query), timeout)
        except aio.TimeoutError: return b''

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


class TcpTunnel(BaseTunnel):
    """TCP DNS tunnel transport class."""
    # Maximum number of outstanding queries before new submissions will block
    MAX_OUTSTANDING_QUERIES: int = 30000

    # Maximum number of send attempts per query packet
    MAX_SEND_ATTEMPTS: int = 3

    def __init__(self, host: str, port: int, auto_connect: bool = True) -> None:
        """
        Initializes a TcpTunnel instance.

        Args:
            host: The hostname or address of the peer.
            port: The port number to connect on.
            auto_connect: A boolean value indicating if the instance will automatically
                          reconnect to the peer during send operations if disconnected.
        """
        super().__init__()

        self.host = str(host)
        self.port = int(port)
        self.auto_connect = bool(auto_connect)

        self._limiter = aio.BoundedSemaphore(self.MAX_OUTSTANDING_QUERIES)

        self._clock = aio.Lock()
        self._wlock = aio.Lock()

        self._has_queries = aio.Event()
        self._futures: MutableMapping[int, aio.Future] = {}

        self._connected = du.StateEvent()
        self._stream: Union[Tuple[aio.StreamReader, aio.StreamWriter], None] = None
        self._listener: Union[aio.Task, None] = None

    def __repr__(self) -> str:
        r = f'{self.__class__.__name__}({self.host!r}, {self.port!r}'
        if not self.auto_connect: r += ', False'
        return r + ')'

    @property
    def connected(self) -> bool:
        return self._connected.is_set()

    @property
    def queries(self) -> Collection[int]:
        return self._futures.keys()

    def submit_query(self, query: bytes) -> Awaitable[bytes]:
        # Extract query id from packet
        qid = du.get_short(query)

        # Submit query to tracking
        future = self._track_query(qid)

        # Schedule the resolution of this query
        self._loop.create_task(self._ahandle_resolve(query, qid, future))

        # Return the future
        return future

    def _track_query(self, qid: int) -> aio.Future:
        """Add a query and future to outstanding request tracking and return the future."""
        # Disallow duplicate queries
        if qid in self._futures:
            raise ValueError('qid - already processing query id 0x%x (%d)' % (qid, qid))

        # Create a new future for this query
        future = self._loop.create_future()
        self._futures[qid] = future

        # Indicate that there are now outstanding queries
        if len(self._futures) == 1:
            self._has_queries.set()

        return future

    def _set_answer(self, answer: bytes, qid: int = None) -> None:
        """Marks the matching future as done and sets its result to answer."""
        # Extract the query id if necessary
        if qid is None:
            try: qid = du.get_short(answer)
            except ValueError: return

        # Check for the matching future
        future = self._futures.get(qid)
        if future is None:
            return

        # Mark the future as done and set its result
        future.set_result(answer)

    def _untrack_query(self, qid: int, future: aio.Future) -> None:
        """Remove a query and future from outstanding request tracking."""
        # Ensure the matching future is done
        if not future.done():
            future.set_result(b'')

        # Remove the query and matching future from tracking
        del self._futures[qid]

        # Indicate that there are now no outstanding queries
        if len(self._futures) == 0:
            self._has_queries.clear()

    async def _ahandle_resolve(self, query: bytes, qid: int, future: aio.Future) -> Awaitable[None]:
        # Attempt to resolve query
        try:
            # Limit maximum outstanding queries
            async with self._limiter:
                # Exhaust all allowable send attempts
                for _ in range(self.MAX_SEND_ATTEMPTS):
                    # Send the query packet to the peer
                    if not await self._asend_query(query):
                        continue

                    # Receive the answer packet from the peer
                    if await self._await_answer(future):
                        return

        # Cleanup any traces of this resolution
        finally:
            self._untrack_query(qid, future)

    async def _asend_query(self, query: bytes) -> Awaitable[bool]:
        """Send a query packet to the peer."""
        # Connect to the peer if necessary
        if self.auto_connect and not self.connected and not await self.aconnect():
            return False

        # Attempt to send the query packet
        try:
            await self._asend_packet(query)
            return True

        # Handle connection errors
        except ConnectionError:
            return False

    async def _await_answer(self, future: aio.Future) -> Awaitable[bool]:
        """Wait for the matching answer packet or a disconnect from the peer."""
        disconnect = self._loop.create_task(self._connected.wait_false())
        (done, _) = await aio.wait((future, disconnect), return_when=aio.FIRST_COMPLETED)
        disconnect.cancel()

        # Matching answer packet was received
        if future in done:
            return True

        # Tunnel was disconnected
        return False

    async def _asend_packet(self, data: bytes) -> Awaitable[None]:
        """Write a DNS packet to the transport stream."""
        # Construct the DNS query packet to send
        prefix = len(data)
        packet = bytearray(prefix + 2)
        du.set_short(packet, prefix)
        packet[2:] = data

        # Write packet data to the transport stream
        async with self._wlock:
            writer = self._stream[1]
            writer.write(packet)
            await writer.drain()

    async def _arecv_packet(self) -> Awaitable[bytes]:
        """Read a DNS packet from the transport stream."""
        # Read packet data from the transport stream
        reader = self._stream[0]
        prefix = du.get_short(await reader.readexactly(2))
        return await reader.readexactly(prefix)

    async def _aconnect(self) -> Awaitable[bool]:
        async with self._clock:
            # Connect to the peer if necessary
            if not self.connected:
                # Establish TCP connection
                try:
                    self._stream = await aio.open_connection(self.host, self.port)

                    self._listener = self._loop.create_task(self._astream_listener())
                    self._connected.set()

                    return True

                # Handle connection errors
                except ConnectionError:
                    return False

    async def _adisconnect(self) -> Awaitable[None]:
        writer = None

        if self.connected:
            # Forget the peer connection
            writer = self._stream[1]
            self._connected.clear()

            # Cancel the stream listener if necessary
            if not self._listener.done():
                await du.full_cancel(self._listener)

        # Perform disconnection
        if writer is not None:
            # Close the connection
            writer.close()

            # Wait for the full disconnection if possible
            try: await writer.wait_closed()
            except AttributeError: pass

    async def _astream_listener(self) -> Awaitable[None]:
        """Asynchronous task that listens for and aggregates peer answer packets."""
        # Wait for a connection to be established
        await self._connected.wait_true()

        # Listen for peer answer packets
        while True:
            # Wait for outstanding requests
            await self._has_queries.wait()

            # Wait to receive a answer packet from the peer
            try:
                packet = await self._arecv_packet()

            # Handle connection errors
            except (ConnectionError, aio.IncompleteReadError):
                # Schedule disconnection
                self._loop.create_task(self.adisconnect())
                return

            # Add the answer packet to the relevant future
            self._set_answer(packet)


class TlsTunnel(TcpTunnel):
    """TLS DNS tunnel transport class."""
    def __init__(self, host: str, port: int, authname: str, cafile: Optional[str] = None, auto_connect: bool = True) -> None:
        """Initialize a TlsTunnel instance.

        Args:
            host: The hostname or address of the peer.
            port: The port number to connect on.
            authname: The name used to authenticate the peer.
            cafile: The file path to CA certificates (in PEM format) used to authenticate the peer.
            auto_connect: A boolean value indicating if the instance will automatically
                          reconnect to the peer during send operations if disconnected.
        """
        super().__init__(host, port, auto_connect)

        self.authname = str(authname)
        self.cafile = cafile

        self._context = ssl.create_default_context(cafile=self.cafile)
        self._context.check_hostname = True

    def __repr__(self) -> str:
        r = f'{self.__class__.__name__}({self.host!r}, {self.port!r}, {self.authname!r}'
        if self.cafile is not None: r += f', {self.cafile!r}'
        if not self.auto_connect: r += ', False'
        return r + ')'

    async def _aconnect(self) -> bool:
        async with self._clock:
            # Connect to the peer if necessary
            if not self.connected:
                # Establish TLS session
                try:
                    self._stream = await aio.open_connection(
                        self.host, self.port, ssl=self._context,
                        server_hostname=self.authname)

                    self._listener = self._loop.create_task(self._astream_listener())
                    self._connected.set()

                    return True

                # Handle connection errors
                except (ConnectionError, ssl.SSLError):
                    return False

    async def _adisconnect(self) -> None:
        try: await super()._adisconnect()
        except ssl.SSLError: pass
