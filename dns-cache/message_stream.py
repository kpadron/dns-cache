import asyncio as aio
import ssl
import struct


class BaseMessageStream:
    """Connection-based message transport base class.

    Pure Virtual Methods:
        async def aconnect(timeout: float = None) -> bool
        async def adisconnect(timeout: float = None) -> bool
        async def asend(data: bytes, timeout: float = None) -> bool
        async def arecv(size: int, timeout: float = None) -> bytes
        async def asend_message(self, message: bytes, timeout: float = None) -> bool
        async def arecv_message(self, timeout: float = None) -> bytes

    Attributes:
        MAX_SEND_ATTEMPTS: The maximum number of transmissions per send operation.
    """
    MAX_SEND_ATTEMPTS = 3

    def __init__(self, auto_connect=True):
        """Initialize a BaseMessageStream instance.

        Args:
            auto_connect: A boolean value indicating if this instance will automatically
                          reconnect to the peer during send operations if disconnected.
        """
        self.auto_connect = bool(auto_connect)

        self._loop = aio.get_event_loop()

        self._clock = aio.Lock()
        self._rlock = aio.Lock()
        self._wlock = aio.Lock()

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

    def send(self, data: bytes) -> bool:
        """Synchronously send data to the peer.

        Args:
            data: The raw data to send to the peer.

        Returns:
            A boolean value indicating the success of the operation.
        """
        return self._loop.run_until_complete(self.asend(data))

    def recv(self, size: int) -> bytes:
        """Synchronously receive data from the peer.

        Args:
            size: The maximum amount of data to receive (in bytes).

        Returns:
            The raw data received from the peer on success,
            or empty bytes string on failure.
        """
        return self._loop.run_until_complete(self.arecv(size))

    def send_message(self, message: bytes) -> bool:
        """Synchronously send a message to the peer.

        Note: A 2-byte NBO length prefix is added to the message before sending.

        Args:
            message: The message to send to the peer.

        Returns:
            A boolean value indicating the success of the operation.
        """
        return self._loop.run_until_complete(self.asend_message(message))

    def recv_message(self) -> bytes:
        """Synchronously receive a message from the peer.

        Note: A 2-byte NBO length prefix is expected before the message data.

        Returns:
            The message received from the peer on success,
            or empty bytes string on failure.
        """
        return self._loop.run_until_complete(self.arecv_message())

    async def aconnect(self, timeout: float = None) -> bool:
        """Asynchronously connect to the peer.

        Note: Must be overridden by sub-classes.

        Args:
            timeout: The amount of time to wait for this operation (in seconds).

        Returns:
            True if connected to the peer, False otherwise.
        """
        raise NotImplementedError

    async def adisconnect(self, timeout: float = None) -> bool:
        """Asynchronously disconnect from the peer.

        Note: Must be overridden by sub-classes.

        Args:
            timeout: The amount of time to wait for this operation (in seconds).

        Returns:
            True if disconnected from the peer, False otherwise.
        """
        raise NotImplementedError

    async def asend(self, data: bytes, timeout: float = None) -> bool:
        """Asynchronously send data to the peer.

        Note: Must be overridden by sub-classes.

        Args:
            data: The raw data to send to the peer.
            timeout: The amount of time to wait for this operation (in seconds).

        Returns:
            A boolean value indicating the success of the operation.
        """
        raise NotImplementedError

    async def arecv(self, size: int, timeout: float = None) -> bytes:
        """Asynchronously receive data from the peer.

        Note: Must be overridden by sub-classes.

        Args:
            size: The maximum amount of data to receive (in bytes).
            timeout: The amount of time to wait for this operation (in seconds).

        Returns:
            The raw data received from the peer on success,
            or empty bytes string on failure.
        """
        raise NotImplementedError

    async def asend_message(self, message: bytes, timeout: float = None) -> bool:
        """Asynchronously send a message to the peer.

        Note: Must be overridden by sub-classes.
        Note: A 2-byte NBO length prefix is added to the message before sending.

        Args:
            message: The message to send to the peer.
            timeout: The amount of time to wait for this operation (in seconds).

        Returns:
            A boolean value indicating the success of the operation.
        """
        raise NotImplementedError

    async def arecv_message(self, timeout: float = None) -> bytes:
        """Asynchronously receive a message from the peer.

        Note: Must be overridden by sub-classes.
        Note: A 2-byte NBO length prefix is expected before the message data.

        Args:
            timeout: The amount of time to wait for this operation (in seconds).

        Returns:
            The message received from the peer on success,
            or empty bytes string on failure.
        """
        raise NotImplementedError


class TcpMessageStream(BaseMessageStream):
    """TCP message transport class.
    """
    def __init__(self, host, port, **kwargs):
        """Initialize a TcpMessageStream instance.

        Args:
            host - The hostname or address of the peer.
            port - The port number to connect on.
        """
        super().__init__(**kwargs)

        self.host = host
        self.port = port

        self._stream = None

    def is_closed(self) -> bool:
        """Returns a boolean value indicating if the underlying transport is closed.
        """
        return bool(self._stream is None or self._stream[1].transport.is_closing())

    def get_info(self, name):
        """Returns information about the underlying transport.

        Args:
            name: The transport-specific information to return.

        Returns:
            The requested information or None on error.
        """
        return self._stream[1].transport.get_extra_info(name) if self._stream is not None else None

    async def aconnect(self, timeout: float = None) -> bool:
        # Connect to the peer
        try:
            return await aio.wait_for(self._aconnect(), timeout)
        except aio.TimeoutError:
            return False

    async def adisconnect(self, timeout: float = None) -> bool:
        # Disconnect from the peer
        try:
            await aio.wait_for(self._adisconnect(), timeout)
            return True
        except aio.TimeoutError:
            return False

    async def asend(self, data: bytes, timeout: float = None) -> bool:
        # Send data to the peer
        try:
            return await aio.wait_for(self._asend_locked(data), timeout)
        except aio.TimeoutError:
            return False

    async def arecv(self, size: int, timeout: float = None) -> bytes:
        # Receive data from the peer
        try:
            return await aio.wait_for(self._arecv_locked(size), timeout)
        except aio.TimeoutError:
            return b''

    async def asend_message(self, message: bytes, timeout: float = None) -> bool:
        # Send a message to the peer
        try:
            return await aio.wait_for(self._asend_message(message), timeout)
        except aio.TimeoutError:
            return False

    async def arecv_message(self, timeout: float = None) -> bytes:
        # Receive a message from the peer
        try:
            return await aio.wait_for(self._arecv_message(), timeout)
        except aio.TimeoutError:
            return b''

    async def _aconnect(self) -> bool:
        # Grab the connection lock
        async with self._clock:
            # Connect to the peer if necessary
            if self.is_closed():
                try:
                    self._stream = await aio.open_connection(self.host, self.port)
                except Exception:
                    return False

            # Report successful connection to the peer
            return True

    async def _adisconnect(self):
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
            wait_closed = getattr(writer, 'wait_closed', None)
            if wait_closed is not None:
                await wait_closed()

    async def _asend_locked(self, data: bytes) -> bool:
        # Grab the write lock
        async with self._wlock:
            return await self._asend(data)

    async def _arecv_locked(self, size: int) -> bytes:
        # Grab the read lock
        async with self._rlock:
            return await self._arecv(size)

    async def _asend(self, data: bytes) -> bool:
        # Attempt to send data to the peer
        attempts = self.MAX_SEND_ATTEMPTS if self.auto_connect else 1
        for _ in range(attempts):
            # Connect to the peer if necessary
            if self.auto_connect and not await self._aconnect():
                continue

            try:
                # Write packet data to the transport stream
                writer = self._stream
                writer.write(data)
                await writer.drain()

                # Report successful transmission of the data
                return True

            except Exception:
                # Disconnect if an exception is raised
                await self._adisconnect()

        # Report failure after exhausting all retries
        return False

    async def _arecv(self, size: int) -> bytes:
        # Attempt to receive data from the peer
        try:
            # Read packet data from the transport stream
            reader = self._stream[0]
            return await reader.readexactly(size)

        except Exception:
            # Disconnect if an exception is raised
            await self._adisconnect()

        # Report failure if there is a connection error
        return b''

    async def _asend_message(self, message: bytes) -> bool:
        # Determine message size
        prefix = len(message)

        # Prepend message size prefix
        buffer = bytearray(prefix + 2)
        buffer[:2] = struct.pack('!H', prefix)
        buffer[2:] = message

        # Send message on transport stream
        return await self._asend_locked(buffer)

    async def _arecv_message(self) -> bytes:
        async with self._rlock:
            # Extract message size prefix
            try:
                prefix = struct.unpack('!H', await self._arecv(2))[0]
            except struct.error:
                return b''

            # Receive message from transport stream
            return await self._arecv(prefix)


class TlsMessageStream(TcpMessageStream):
    """TLS message transport class.
    """
    def __init__(self, host, port, authname, **kwargs):
        """Initialize a TlsMessageStream instance.

        Args:
            host - The hostname or address of the peer.
            port - The port number to connect on.
            authname - The name used to authenticate the peer.
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
                    self._stream = await aio.open_connection(
                        self.host, self.port,
                        ssl=self._context,
                        server_hostname=self.authname)

                except Exception:
                    return False

            # Report successful connection to the peer
            return True
