import abc as _abc
import asyncio as _aio
import ssl as _ssl
import typing as _typing

import dns_util as _du


class BaseTunnel(_abc.ABC):
    """DNS transport tunnel base class.

    Pure Virtual Properties:
    - connected
    - has_queries
    - has_answers
    - queries
    - answers

    Pure Virtual Methods:
    - __init__
    - _aconnect
    - _adisconnect
    - asubmit_query
    """
    # Maximum amount of time (in seconds) to wait for establishing a tunnel connection
    DEFAULT_CONNECT_TIMEOUT: float = 1.2

    @_abc.abstractmethod
    def __init__(self, **kwargs) -> None:
        """Initialize a BaseTunnel instance.
        """
        self._loop = _aio.get_event_loop()

    @property
    @_abc.abstractmethod
    def connected(self) -> bool:
        """Returns true if the instance is connected to the peer.
        """
        ...

    @property
    @_abc.abstractmethod
    def has_queries(self) -> bool:
        """Returns true if the instance has outstanding queries.
        """
        ...

    @property
    @_abc.abstractmethod
    def has_answers(self) -> bool:
        """Returns true if the instance has outstanding answers.
        """
        ...

    @property
    @_abc.abstractmethod
    def queries(self) -> _typing.Collection[int]:
        """Returns a read-only view of the outstanding queries.
        """
        ...

    @property
    @_abc.abstractmethod
    def answers(self) -> _typing.Collection[int]:
        """Returns a read-only view of the outstanding answers.
        """
        ...

    async def aconnect(self, timeout: float = DEFAULT_CONNECT_TIMEOUT) -> bool:
        """Asynchronously connect to the peer with timeout.

        Args:
            timeout: The amount of time to wait for this operation (in seconds).

        Returns:
            True if connected to the peer, False otherwise.
        """
        try: return await _aio.wait_for(self._aconnect(), timeout)
        except _aio.TimeoutError: return False

    @_abc.abstractmethod
    async def _aconnect(self) -> bool:
        """Asynchronously connect to the peer.
        """
        ...

    async def adisconnect(self, timeout: float = DEFAULT_CONNECT_TIMEOUT) -> None:
        """Asynchronously disconnect from the peer with timeout.

        Args:
            timeout: The amount of time to wait for this operation (in seconds).
        """
        try: await _aio.wait_for(self._adisconnect(), timeout)
        except _aio.TimeoutError: pass

    @_abc.abstractmethod
    async def _adisconnect(self) -> None:
        """Asynchronously disconnect from the peer.
        """
        ...

    async def aresolve(self, queries: _typing.Iterable[bytes], timeout: _typing.Optional[float] = None) -> _typing.Sequence[bytes]:
        """Asynchronously resolve DNS queries by forwarding to the peer.

        Args:
            queries: The DNS query packet(s) to forward.
            timeout: The amount of time to wait for this operation (in seconds).

        Returns:
            A sequence of DNS answer packet(s) or empty bytestring(s) on error.
        """
        try: return await _aio.wait_for(_aio.gather(*(await self.asubmit(queries))), timeout)
        except _aio.TimeoutError: return []

    async def aresolve_query(self, query: bytes, timeout: _typing.Optional[float] = None) -> bytes:
        """Asynchronously resolve a DNS query by forwarding to the peer.

        Args:
            query: The DNS query packet to forward.
            timeout: The amount of time to wait for this operation (in seconds).

        Returns:
            The DNS answer packet or empty bytestring on error.
        """
        try: return await _aio.wait_for(await self.asubmit_query(query), timeout)
        except _aio.TimeoutError: return b''

    async def asubmit(self, queries: _typing.Iterable[bytes]) -> _typing.Sequence[_aio.Task]:
        """Asynchronously submit DNS queries for resolution via the peer.

        Args:
            queries: The DNS query packet(s) to resolve.

        Returns:
            A sequence of asyncio.Task(s) that represent the
            eventual result of each resolution. These Tasks(s)
            can be awaited to receive the answer packet(s) or
            empty bytestring(s) on error.
        """
        try:
            tasks = []

            for query in queries:
                tasks.append(await self.asubmit_query(query))

            return tasks

        except Exception:
            await _du.cancel_all(tasks)
            raise

    @_abc.abstractmethod
    async def asubmit_query(self, query: bytes) -> _aio.Task:
        """Asynchronously submit a DNS query for resolution via the peer.

        Args:
            query: The DNS query packet to resolve.

        Returns:
            A asyncio.Task that represents the eventual result
            of the resolution. This Task can be awaited to receive
            the answer packet or an empty bytestring on error.
        """
        ...

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

    def resolve(self, queries: _typing.Iterable[bytes]) -> _typing.Sequence[bytes]:
        """Synchronously resolve DNS queries by forwarding to the peer.

        Args:
            queries: The DNS query packet(s) to forward.

        Returns:
            The DNS answer packet(s) or empty bytestring(s) on error.
        """
        return self._loop.run_until_complete(self.aresolve(queries))

    def resolve_query(self, query: bytes) -> bytes:
        """Synchronously resolve a DNS query by forwarding to the peer.

        Args:
            query: The DNS query packet to forward.

        Returns:
            The DNS answer packet or empty bytestring on error.
        """
        return self._loop.run_until_complete(self.aresolve_query(query))

    def submit(self, queries: _typing.Iterable[bytes]) -> _typing.Sequence[_aio.Task]:
        """Synchronously submit DNS queries for resolution via the peer.

        Args:
            queries: The DNS query packet(s) to resolve.

        Returns:
            A sequence of asyncio.Task(s) that represent the
            eventual result of each resolution. These Tasks(s)
            can be awaited to receive the answer packet(s) or
            empty bytestring(s) on error.
        """
        return self._loop.run_until_complete(self.asubmit(queries))

    def submit_query(self, query: bytes) -> _aio.Task:
        """Synchronously submit a DNS query for resolution via the peer.

        Args:
            query: The DNS query packet to resolve.

        Returns:
            A asyncio.Task that represents the eventual result
            of the resolution. This Task can be awaited to receive
            the answer packet or an empty bytestring on error.
        """
        return self._loop.run_until_complete(self.asubmit_query(query))

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

    def __init__(self, host: str, port: int, **kwargs) -> None:
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
        self.auto_connect = bool(kwargs.get('auto_connect', True))

        self._limiter = _aio.BoundedSemaphore(self.MAX_OUTSTANDING_QUERIES)

        self._clock = _aio.Lock()
        self._wlock = _aio.Lock()

        self._has_queries = _aio.Event()
        self._has_answers = _aio.Event()

        self._queries: _typing.MutableMapping[int, _aio.Event] = {}
        self._answers: _typing.MutableMapping[int, bytes] = {}

        self._connected = _du.StateEvent()
        self._stream: _typing.Tuple[_aio.StreamReader, _aio.StreamWriter] = None
        self._listener: _aio.Task = None

    def __repr__(self) -> str:
        r = f'{self.__class__.__name__}({self.host!r}, {self.port!r}'
        if not self.auto_connect: r += ', auto_connect=False'
        return r + ')'

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
    def queries(self) -> _typing.Collection[int]:
        return _du.CollectionView(self._queries)

    @property
    def answers(self) -> _typing.Collection[int]:
        return _du.CollectionView(self._answers)

    async def _aconnect(self) -> bool:
        async with self._clock:
            # Connect to the peer if necessary
            if not self.connected:
                # Establish TCP connection
                try:
                    self._stream = await _aio.open_connection(self.host, self.port)

                    self._listener = self._loop.create_task(self._astream_listener())
                    self._connected.set()

                    return True

                # Handle connection errors
                except ConnectionError:
                    return False

    async def _adisconnect(self) -> None:
        writer = None

        if self.connected:
            # Forget the peer connection
            writer = self._stream[1]
            self._connected.clear()

            # Cancel the stream listener if necessary
            if not self._listener.done():
                await _du.full_cancel(self._listener)

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
            except (ConnectionError, _aio.IncompleteReadError):
                # Schedule disconnection
                self._loop.create_task(self.adisconnect())
                return

            # Add the answer packet to response tracking
            self._add_answer(packet)

    async def asubmit_query(self, query: bytes) -> _aio.Task:
        # Extract query id from packet
        qid = _du.get_short(query)

        # Submit query to tracking
        self._track_query(qid)

        # Schedule the resolution of this query
        return self._loop.create_task(self._ahandle_resolve(query, qid))

    async def _ahandle_resolve(self, query: bytes, qid: int) -> bytes:
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

                # Report resolution failure
                return b''

        # Cleanup any traces of this resolution
        finally:
            self._untrack_query(qid)

    async def _asend_query(self, query: bytes) -> bool:
        """Send a query packet to the peer.
        """
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

    async def _arecv_answer(self, qid: int) -> _typing.Union[bytes, None]:
        """Receive the matching answer packet for the given query id.
        """
        # Schedule event waiting as tasks
        answer_event = self._loop.create_task(self._queries[qid].wait())
        disconnect_event = self._loop.create_task(self._connected.wait_false())

        # Wait for the matching answer to arrive or a disconnection from the peer
        await _du.wait_first((answer_event, disconnect_event))

        # Check for the matching answer
        return self._answers.get(qid)

    async def _asend_packet(self, data: bytes) -> None:
        """Write a DNS packet to the transport stream.
        """
        # Construct the DNS query packet to send
        prefix = len(data)
        packet = bytearray(prefix + 2)
        _du.set_short(packet, prefix)
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
        prefix = _du.get_short(await reader.readexactly(2))
        return await reader.readexactly(prefix)

    def _track_query(self, qid: int) -> None:
        """Add a query id to outstanding request tracking.
        """
        if qid in self._queries:
            raise ValueError('qid - already processing query id 0x%x (%d)' % (qid, qid))

        self._queries[qid] = _aio.Event()

        # Indicate that there are now outstanding queries
        if len(self._queries) == 1:
            self._has_queries.set()

    def _add_answer(self, answer: bytes, qid: _typing.Optional[int] = None) -> bool:
        """Add a answer packet to outstanding response tracking.
        """
        # Extract the query id if necessary
        if qid is None:
            try: qid = _du.get_short(answer)
            except (TypeError, ValueError): return False

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

            cafile: The file path to CA certificates (in PEM format) used to authenticate the peer.
        """
        super().__init__(host, port, **kwargs)

        self.authname = str(authname)
        self.cafile = kwargs.get('cafile')

        self._context = _ssl.create_default_context(cafile=self.cafile)
        self._context.check_hostname = True

    def __repr__(self) -> str:
        r = f'{self.__class__.__name__}({self.host!r}, {self.port!r}, {self.authname!r}'
        if not self.auto_connect: r += ', auto_connect=False'
        if self.cafile is not None: r += f', cafile={self.cafile!r}'
        return r + ')'

    async def _aconnect(self) -> bool:
        async with self._clock:
            # Connect to the peer if necessary
            if not self.connected:
                # Establish TLS session
                try:
                    self._stream = await _aio.open_connection(
                        self.host, self.port, ssl=self._context,
                        server_hostname=self.authname)

                    self._listener = self._loop.create_task(self._astream_listener())
                    self._connected.set()

                    return True

                # Handle connection errors
                except (ConnectionError, _ssl.SSLError):
                    return False

    async def _adisconnect(self) -> None:
        try: await super()._adisconnect()
        except _ssl.SSLError: pass
