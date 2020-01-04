import asyncio as aio
import ssl
import struct
from typing import (Any, ByteString, Iterable, MutableMapping, MutableSet,
                    Optional, Sequence, Tuple, Union)

_DnsQueries = Union[ByteString, Iterable[ByteString]]
_DnsAnswers = Union[ByteString, Sequence[bytes]]
_AioStream = Union[Tuple[aio.StreamReader, aio.StreamWriter], None]


class BaseDnsTunnel:
    """DNS transport tunnel base class.

    Pure Virtual Methods:
        aconnect
        adisconnect
        aresolve
    """
    def __init__(self, **kwargs) -> None:
        """Initialize a BaseDnsTunnel instance.
        """
        self._loop = aio.get_event_loop()

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

    def resolve(self, query: _DnsQueries) -> _DnsAnswers:
        """Synchronously resolve a DNS query by forwarding to the peer.

        Args:
            query: The DNS query packet(s) to forward.

        Returns:
            The DNS query response packet(s) or empty bytes string(s) on error.
        """
        return self._loop.run_until_complete(self.aresolve(query))

    async def aconnect(self, timeout: Optional[float] = None) -> bool:
        """Asynchronously connect to the peer.

        Note: Must be overridden by sub-classes.

        Args:
            timeout: The amount of time to wait for this operation (in seconds).

        Returns:
            True if connected to the peer, False otherwise.
        """
        raise NotImplementedError

    async def adisconnect(self, timeout: Optional[float] = None) -> bool:
        """Asynchronously disconnect from the peer.

        Note: Must be overridden by sub-classes.

        Args:
            timeout: The amount of time to wait for this operation (in seconds).

        Returns:
            True if disconnected from the peer, False otherwise.
        """
        raise NotImplementedError

    async def aresolve(self, query: _DnsQueries, timeout: Optional[float] = None) -> _DnsAnswers:
        """Asynchronously resolve a DNS query by forwarding to the peer.

        Args:
            query: The DNS query packet to forward.
            timeout: The amount of time to wait for this operation (in seconds).

        Returns:
            The DNS query response packet or empty bytes string on error.
        """
        raise NotImplementedError


class TcpDnsTunnel(BaseDnsTunnel):
    """TCP DNS tunnel transport class.

    Attributes:
        MAX_SEND_ATTEMPTS: The maximum number of transmissions per send operation.
        MAX_CONNECTION_TIMEOUT: The amount of time to wait when establishing a connection (in seconds).
    """
    MAX_SEND_ATTEMPTS: int = 3
    MAX_CONNECTION_TIMEOUT: float = 0.75

    def __init__(self, host: str, port: int, auto_connect: bool = True, **kwargs) -> None:
        """Initialize a TcpDnsTunnel instance.

        Args:
            host: The hostname or address of the peer.
            port: The port number to connect on.
            auto_connect: A boolean value indicating if this instance will automatically
                          reconnect to the peer during send operations if disconnected.
        """
        super().__init__(**kwargs)

        self.auto_connect = bool(auto_connect)
        self.host: str = str(host)
        self.port: int = int(port)

        self._queries: MutableSet[int] = set()
        self._answers: MutableMapping[int, bytes] = dict()

        self._clock = aio.Lock()
        self._rlock = aio.Lock()
        self._wlock = aio.Lock()

        self._stream: _AioStream = None

    def is_closed(self) -> bool:
        """Returns a boolean value indicating if the underlying transport is closed.
        """
        try: return self._stream[1].transport.is_closing()
        except TypeError: return True

    def get_info(self, name: str) -> Any:
        """Returns information about the underlying transport.

        Args:
            name: The transport-specific information to return.

        Returns:
            The requested information or None on error.
        """
        try: return self._stream[1].transport.get_extra_info(name)
        except AttributeError: return None

    async def aconnect(self, timeout: Optional[float] = None) -> bool:
        # Connect to the peer
        try: return await aio.wait_for(self._aconnect(), timeout)
        except aio.TimeoutError: return False

    async def adisconnect(self, timeout: Optional[float] = None) -> bool:
        # Disconnect from the peer
        try:
            await aio.wait_for(self._adisconnect(), timeout)
            return True
        except aio.TimeoutError:
            return False

    async def aresolve(self, query: _DnsQueries, timeout: Optional[float] = None) -> _DnsAnswers:
        # Check input to determine functionality
        if isinstance(query, (ByteString, memoryview)):
            awaitable = self._aresolve(query)
            default_value = b''
        else:
            awaitable = aio.gather(*(self._aresolve(q) for q in query))
            default_value = []

        # Forward DNS queries to the peer
        try: return await aio.wait_for(awaitable, timeout)
        except aio.TimeoutError: return default_value

    async def _aconnect(self) -> bool:
        # Grab the connection lock
        async with self._clock:
            # Connect to the peer if necessary
            if self.is_closed():
                try:
                    # Establish TCP connection
                    self._stream = await aio.wait_for(aio.open_connection(self.host, self.port), self.MAX_CONNECTION_TIMEOUT)
                except Exception:
                    # Report connection failure
                    return False

            # Report connection success
            return True

    async def _adisconnect(self) -> None:
        writer = None

        # Grab connection lock
        async with self._clock:
            # Forget the peer connection if necessary
            if self._stream is not None:
                writer = self._stream[1]
                self._stream = None

        # Perform disconnection
        if writer is not None:
            # Close the connection
            writer.close()

            # Wait for the full disconnection if possible
            try: await writer.wait_closed()
            except AttributeError: pass

    async def _aresolve(self, query: bytes) -> bytes:
        """Resolve a query using the peer and return an answer.
        """
        # Extract query id from packet
        qid: int = struct.unpack('!H', memoryview(query)[:2])[0]

        try:
            # Attempt to resolve query
            for _ in range(self.MAX_SEND_ATTEMPTS):
                # Send the query packet to the peer
                if not await self._asend_query(query, qid):
                    continue

                # Receive answer packet from the peer
                answer = await self._arecv_answer(qid)

                # Report resolution result
                if answer:
                    return answer

            # Report resolution failure
            return b''

        finally:
            # Cleanup any traces of this resolution
            self._queries.discard(qid)
            if qid in self._answers: del self._answers[qid]

    async def _asend_query(self, query: bytes, qid: Optional[int] = None) -> bool:
        """Send a query packet to the peer using a given query id.
        """
        # Extract query id if necessary
        if qid is None:
            qid: int = struct.unpack('!H', memoryview(query)[:2])[0]

        # Connect to the peer if necessary
        if self.auto_connect and not await self._aconnect():
            return False

        # Attempt to send the query packet
        if not await self._asend_packet(query):
            return False

        # Add query to tracking
        self._queries.add(qid)
        return True

    async def _arecv_answer(self, qid: int) -> bytes:
        """Receive a answer packet from the peer for a given query id.
        """
        # Wait for the requested answer
        while True:
            # Check for matching answer
            answer = self._get_answer(qid)
            if answer is not None:
                return answer

            # Check if an answer is already being received
            was_busy = self._rlock.locked()
            async with self._rlock:
                # If an answer was being received previously
                # it is possible the requested answer was received
                # while waiting so check again before waiting for
                # a new answer
                if was_busy:
                    # Check for matching answer
                    answer = self._get_answer(qid)
                    if answer is not None:
                        return answer

                # Attempt to receive a answer packet
                packet = await self._arecv_packet()

            # Extract answer id from packet
            try:
                aid: int = struct.unpack('!H', memoryview(packet)[:2])[0]

            # Handle malformed packet
            except struct.error:
                return b''

            # Return the answer if it matches the current query
            if aid == qid:
                return packet

            # Add answer to tracking if it matches an outstanding query
            self._put_answer(packet, aid)

    async def _asend_packet(self, data: bytes) -> bool:
        # Construct DNS query packet to send
        prefix = len(data)
        packet = bytearray(prefix + 2)
        packet[:2] = struct.pack('!H', prefix)
        packet[2:] = data

        # Write packet data to the transport stream
        try:
            writer = self._stream[1]
            writer.write(packet)
            await writer.drain()
            return True

        # Handle connection errors
        except Exception:
            return False

    async def _arecv_packet(self) -> bytes:
        # Read packet data from the transport stream
        try:
            reader = self._stream[0]
            prefix = struct.unpack('!H', await reader.readexactly(2))[0]
            return await reader.readexactly(prefix)

        # Handle connection reset
        except TypeError:
            return b''

        # Handle premature EOF from the peer
        except aio.IncompleteReadError:
            await self._adisconnect()
            return b''

    def _get_answer(self, qid: int) -> Union[bytes, None]:
        """Get the answer packet for a given query id.
        """
        # Check for a matching outstanding query
        if qid not in self._queries:
            return b''

        # Check for matching answer
        return self._answers.get(qid)

    def _put_answer(self, answer: bytes, aid: Optional[int] = None) -> bool:
        """Put a answer packet for a given answer id.
        """
        # Extract answer id if necessary
        if aid is None:
            try: aid: int = struct.unpack('!H', memoryview(answer)[:2])[0]
            except struct.error: return False

        # Check for matching outstanding query
        if aid not in self._queries:
            return False

        # Add answer to tracking
        self._answers[aid] = answer
        return True


class TlsDnsTunnel(TcpDnsTunnel):
    """TLS DNS tunnel transport class.
    """
    def __init__(self, host, port, authname, **kwargs):
        """Initialize a TlsDnsTunnel instance.

        Args:
            host: The hostname or address of the peer.
            port: The port number to connect on.
            authname: The name used to authenticate the peer.
        """
        super().__init__(host, port, **kwargs)
        self.authname = authname

        self._context = ssl.create_default_context()
        self._context.check_hostname = True

    async def _aconnect(self) -> bool:
        # Grab the connection lock
        async with self._clock:
            # Connect to the peer if necessary
            if self.is_closed():
                try:
                    # Establish TLS session
                    self._stream = await aio.open_connection(
                        self.host, self.port,
                        ssl=self._context,
                        server_hostname=self.authname)

                except Exception:
                    # Report connection failure
                    return False

            # Report connection success
            return True
