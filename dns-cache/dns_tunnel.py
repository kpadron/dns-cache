import asyncio as aio
import ssl
import struct
from abc import ABC, abstractmethod
from typing import (Any, ByteString, Iterable, KeysView, MutableMapping,
                    MutableSet, Optional, Sequence, Tuple, Union)

from dns_util import BytesLike, StateEvent, get_short, wait_first


class BaseTunnel(ABC):
    """DNS transport tunnel base class.

    Pure Virtual Properties:
    - connected
    - has_queries
    - has_answers
    - queries
    - answers

    Pure Virtual Methods:
    - __init__
    - aconnect
    - adisconnect
    - submit_query
    """
    # Maximum amount of time (in seconds) to wait for establishing a tunnel connection
    DEFAULT_CONNECT_TIMEOUT: float = 1.2

    @abstractmethod
    def __init__(self, **kwargs) -> None:
        """Initialize a BaseTunnel instance.
        """
        self._loop = aio.get_event_loop()

    @property
    @abstractmethod
    def connected(self) -> bool:
        """Returns true if the instance is connected to the peer.
        """
        ...

    @property
    @abstractmethod
    def has_queries(self) -> bool:
        """Returns true if the instance has outstanding queries.
        """
        ...

    @property
    @abstractmethod
    def has_answers(self) -> bool:
        """Returns true if the instance has outstanding answers.
        """
        ...

    @property
    @abstractmethod
    def queries(self) -> KeysView[int]:
        """Returns a read-only view of the outstanding queries.
        """
        ...

    @property
    @abstractmethod
    def answers(self) -> KeysView[int]:
        """Returns a read-only view of the outstanding answers.
        """
        ...

    @abstractmethod
    async def aconnect(self, timeout: float = DEFAULT_CONNECT_TIMEOUT) -> bool:
        """Asynchronously connect to the peer.

        Args:
            timeout: The amount of time to wait for this operation (in seconds).

        Returns:
            True if connected to the peer, False otherwise.
        """
        ...

    @abstractmethod
    async def adisconnect(self, timeout: Optional[float] = None) -> bool:
        """Asynchronously disconnect from the peer.

        Args:
            timeout: The amount of time to wait for this operation (in seconds).

        Returns:
            True if disconnected from the peer, False otherwise.
        """
        ...

    async def aresolve(self, queries: Iterable[BytesLike], timeout: Optional[float] = None) -> Sequence[bytes]:
        """Asynchronously resolve DNS queries by forwarding to the peer.

        Args:
            queries: The DNS query packet(s) to forward.
            timeout: The amount of time to wait for this operation (in seconds).

        Returns:
            A sequence of DNS answer packet(s) or empty bytestring(s) on error.
        """
        try: return await aio.wait_for(aio.gather(*(self.submit_query(query) for query in queries)), timeout)
        except aio.TimeoutError: return []

    async def aresolve_query(self, query: BytesLike, timeout: Optional[float] = None) -> bytes:
        """Asynchronously resolve a DNS query by forwarding to the peer.

        Args:
            query: The DNS query packet to forward.
            timeout: The amount of time to wait for this operation (in seconds).

        Returns:
            The DNS answer packet or empty bytestring on error.
        """
        try: return await aio.wait_for(self.submit_query(query), timeout)
        except aio.TimeoutError: return b''

    async def __aenter__(self) -> 'BaseTunnel':
        """Enter async context.
        """
        await self.aconnect()
        return self

    async def __aexit__(self, exc_type, exc_value, traceback) -> None:
        """Exit async context.
        """
        await self.adisconnect()

    def connect(self) -> bool:
        """Synchronously connect to the peer.

        Returns:
            True if connected to the peer, False otherwise.
        """
        return self._loop.run_until_complete(self.aconnect())

    def disconnect(self) -> bool:
        """Synchronously disconnect from the peer.

        Returns:
            True if disconnected from the peer, False otherwise.
        """
        return self._loop.run_until_complete(self.adisconnect())

    def resolve(self, queries: Iterable[BytesLike]) -> Sequence[bytes]:
        """Synchronously resolve DNS queries by forwarding to the peer.

        Args:
            queries: The DNS query packet(s) to forward.

        Returns:
            The DNS answer packet(s) or empty bytestring(s) on error.
        """
        return self._loop.run_until_complete(self.aresolve(queries))

    def resolve_query(self, query: BytesLike) -> bytes:
        """Synchronously resolve a DNS query by forwarding to the peer.

        Args:
            query: The DNS query packet to forward.

        Returns:
            The DNS answer packet or empty bytestring on error.
        """
        return self._loop.run_until_complete(self.aresolve_query(query))

    def submit(self, queries: Iterable[BytesLike]) -> Sequence[aio.Task]:
        """Submit DNS queries for resolution via the peer.

        Args:
            queries: The DNS query packet(s) to resolve.

        Returns:
            A sequence of asyncio.Task(s) that represent the
            eventual result of each resolution. These Tasks(s)
            can be awaited to receive the answer packet(s) or
            empty bytestring(s) on error.
        """
        return [self.submit_query(query) for query in queries]

    @abstractmethod
    def submit_query(self, query: BytesLike) -> aio.Task:
        """Submit a DNS query for resolution via the peer.

        Args:
            query: The DNS query packet to resolve.

        Returns:
            A asyncio.Task that represents the eventual result
            of the resolution. This Task can be awaited to receive
            the answer packet or an empty bytestring on error.
        """
        ...

    def __enter__(self) -> 'BaseTunnel':
        """Enter context.
        """
        return self._loop.run_until_complete(self.__aenter__())

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        """Exit context.
        """
        self._loop.run_until_complete(self.__aexit__(exc_type, exc_value, traceback))


class TcpTunnel(BaseTunnel):
    """TCP DNS tunnel transport class.

    Attributes:
        MAX_OUTSTANDING_QUERIES: The maximum number of outstanding queries allowed before blocking on new ones.
        MAX_SEND_ATTEMPTS: The maximum number of transmissions per send operation.
    """
    MAX_OUTSTANDING_QUERIES: int = 30000
    MAX_SEND_ATTEMPTS: int = 3

    def __init__(self, host: str, port: int, auto_connect: bool = True, **kwargs) -> None:
        """Initialize a TcpTunnel instance.

        Args:
            host: The hostname or address of the peer.
            port: The port number to connect on.
            auto_connect: A boolean value indicating if this instance will automatically
                          reconnect to the peer during send operations if disconnected.
        """
        super().__init__(**kwargs)

        self.host: str = str(host)
        self.port: int = int(port)
        self.auto_connect = bool(auto_connect)

        self._limiter = aio.BoundedSemaphore(self.MAX_OUTSTANDING_QUERIES)

        self._clock = aio.Lock()
        self._wlock = aio.Lock()

        self._has_queries = aio.Event()
        self._has_answers = aio.Event()

        self._queries: MutableMapping[int, aio.Event] = dict()
        self._answers: MutableMapping[int, bytes] = dict()

        self._connected = StateEvent()
        self._stream: Tuple[aio.StreamReader, aio.StreamWriter] = None
        self._listener = self._loop.create_task(self._astream_listener())

    def __del__(self) -> None:
        """Deinitialize a TcpTunnel instance.
        """
        # Cancel the listener if necessary
        if not self._listener.done():
            self._listener.cancel()
            try: self._loop.run_until_complete(self._listener)
            except aio.CancelledError: pass

        # Close the connection to the peer if necessary
        if self.connected:
            self._loop.run_until_complete(self.adisconnect())

    def __repr__(self) -> str:
        return f'{self.__class__.__name__}(%r, %r, auto_connect=%r)' % (
            self.host, self.port, self.auto_connect)

    @property
    def connected(self) -> bool:
        return self._connected.is_set()

    @property
    def has_queries(self) -> bool:
        return self._has_queries.is_set()

    @property
    def has_answers(self) -> bool:
        return self._has_answers.is_set()

    @property
    def queries(self) -> KeysView[int]:
        return self._queries.keys()

    @property
    def answers(self) -> KeysView[int]:
        return self._answers.keys()

    async def aconnect(self, timeout: float = BaseTunnel.DEFAULT_CONNECT_TIMEOUT) -> bool:
        # Connect to the peer
        try: return await aio.wait_for(self._aconnect(), timeout)
        except aio.TimeoutError: return False

    async def adisconnect(self, timeout: Optional[float] = None) -> bool:
        # Disconnect from the peer
        try: await aio.wait_for(self._adisconnect(), timeout)
        except aio.TimeoutError: return False
        return True

    async def _aconnect(self) -> bool:
        async with self._clock:
            # Connect to the peer if necessary
            if not self.connected:
                # Establish TCP connection
                try:
                    self._stream = await aio.open_connection(self.host, self.port)

                # Handle connection errors
                except ConnectionError:
                    return False

                # Update connection state variable
                self._connected.set()

        return True

    async def _adisconnect(self) -> None:
        writer = None

        # Forget the peer connection if connected
        async with self._clock:
            if self.connected:
                writer = self._stream[1]
                self._connected.clear()
                self._stream = None

        # Perform disconnection
        if writer is not None:
            # Close the connection
            writer.close()

            # Wait for the full disconnection if possible
            try: await writer.wait_closed()
            except AttributeError: pass

    async def _astream_listener(self) -> None:
        """Asynchronous task that listens for and aggregates peer answer packets.
        """
        # Listen for peer answer packets
        while True:
            # Wait for a connection to be established
            await self._connected.wait_true()

            # Wait for outstanding requests
            await self._has_queries.wait()

            # Wait to receive a answer packet from the peer
            try:
                packet = await self._arecv_packet()

            # Handle connection errors
            except (ConnectionError, aio.IncompleteReadError):
                # Reset the connection
                await self.adisconnect()
                continue

            # Add the answer packet to response tracking
            self._add_answer(packet)

    def submit_query(self, query: BytesLike) -> aio.Task:
        # Extract query id from packet
        qid = get_short(query)

        # Submit query to tracking
        self._track_query(qid)

        # Schedule the resolution of this query
        return self._loop.create_task(self._ahandle_resolve(query, qid))

    async def _ahandle_resolve(self, query: BytesLike, qid: int) -> bytes:
        """Resolve a query via the peer.
        """
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
                    answer = await self._arecv_answer(qid)
                    if answer is None:
                        continue

                    # Report resolution result
                    return answer

        # Cleanup any traces of this resolution
        finally:
            self._untrack_query(qid)

        # Report resolution failure
        return b''

    async def _asend_query(self, query: BytesLike) -> bool:
        """Send a query packet to the peer.
        """
        # Connect to the peer if necessary
        if self.auto_connect and not self.connected and not await self.aconnect():
            return False

        # Attempt to send the query packet
        try:
            await self._asend_packet(query)

        # Handle connection errors
        except ConnectionError:
            return False

        return True

    async def _arecv_answer(self, qid: int) -> Union[bytes, None]:
        """Receive the matching answer packet for the given query id.
        """
        # Schedule event waiting as tasks
        answer_event = self._loop.create_task(self._queries[qid].wait())
        disconnect_event = self._loop.create_task(self._connected.wait_false())

        # Wait for the matching answer to arrive or a disconnection from the peer
        await wait_first((answer_event, disconnect_event))

        # Check for the matching answer
        return self._answers.get(qid)

    async def _asend_packet(self, data: BytesLike) -> None:
        """Write a DNS packet to the transport stream.
        """
        # Construct the DNS query packet to send
        prefix = len(data)
        packet = bytearray(prefix + 2)
        packet[:2] = struct.pack('!H', prefix)
        packet[2:] = data

        # Write packet data to the transport stream
        async with self._wlock:
            writer = self._stream[1]
            writer.write(packet)
            await writer.drain()

    async def _arecv_packet(self) -> bytes:
        """Read a DNS packet from the transport stream.
        """
        # Read packet data from the transport stream
        reader = self._stream[0]
        prefix = struct.unpack('!H', await reader.readexactly(2))[0]
        return await reader.readexactly(prefix)

    def _track_query(self, qid: int) -> None:
        """Add a query id to outstanding request tracking.
        """
        if qid in self._queries:
            raise ValueError('qid - already processing query id 0x%x (%d)' % (qid, qid))

        self._queries[qid] = aio.Event()

        # Indicate that there are now outstanding queries
        if len(self._queries) == 1:
            self._has_queries.set()

    def _add_answer(self, answer: BytesLike, qid: Optional[int] = None) -> bool:
        """Add a answer packet to outstanding response tracking.
        """
        # Extract the query id if necessary
        if qid is None:
            try: qid = get_short(answer)
            except ValueError: return False

        # Check for the matching outstanding query
        answer_event = self._queries.get(qid)
        if answer_event is None:
            return False

        # Add the answer to response tracking
        self._answers[qid] = answer
        answer_event.set()

        # Indicate that there are now outstanding answers
        if len(self._answers) == 1:
            self._has_answers.set()

        return True

    def _untrack_query(self, qid: int) -> None:
        """Remove a query id from outstanding tracking.
        """
        # Remove any matching queries
        if qid in self._queries:
            del self._queries[qid]

            # Indicate that there are now no outstanding queries
            if len(self._queries) == 0:
                self._has_queries.clear()

        # Remove any matching answers
        if qid in self._answers:
            del self._answers[qid]

            # Indicate that there are now no outstanding answers
            if len(self._answers) == 0:
                self._has_answers.clear()


class TlsTunnel(TcpTunnel):
    """TLS DNS tunnel transport class.
    """
    def __init__(self, host: str, port: int, authname: str, **kwargs) -> None:
        """Initialize a TlsTunnel instance.

        Args:
            host: The hostname or address of the peer.
            port: The port number to connect on.
            authname: The name used to authenticate the peer.
        """
        super().__init__(host, port, **kwargs)
        self.authname = str(authname)

        self._context = ssl.create_default_context()
        self._context.check_hostname = True

    def __repr__(self) -> str:
        return f'{self.__class__.__name__}(%r, %r, %r, auto_connect=%r)' % (
            self.host, self.port, self.authname, self.auto_connect)

    async def _aconnect(self) -> bool:
        async with self._clock:
            # Connect to the peer if necessary
            if not self.connected:
                # Establish TLS session
                try:
                    self._stream = await aio.open_connection(
                        self.host, self.port, ssl=self._context,
                        server_hostname=self.authname)

                # Handle connection errors
                except ConnectionError:
                    return False

                # Update connection state variable
                self._connected.set()

        return True
