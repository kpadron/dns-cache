import asyncio as aio
import ssl
import struct


class BaseMessageStream:
    """Connection-based message transport base class.

    Pure Virtual Methods:
        async def aconnect() -> None
        async def adisconnect() -> None
        async def asend(data: bytes, timeout: float = None) -> bool
        async def arecv(size: int, timeout: float = None) -> bytes

    Attributes:
        MAX_SEND_ATTEMPTS: The maximum number of transmissions per send operation.
        CONNECTION_TIMEOUT: The maximum time to wait while establishing a message stream (in seconds).
    """
    MAX_SEND_ATTEMPTS = 2
    CONNECTION_TIMEOUT = 2.5

    def __init__(self, loop=None):
        """Initialize a BaseMessageStream instance.

        Args:
            loop: The async event loop to run on (defaults to current running loop).
        """
        self.loop = loop or aio.get_event_loop()

        self.clock = aio.Lock(loop=self.loop)
        self.rlock = aio.Lock(loop=self.loop)
        self.wlock = aio.Lock(loop=self.loop)

    def connect(self) -> None:
        """Synchronously connect to the peer.
        """
        self.loop.run_until_complete(self.aconnect())

    def disconnect(self) -> None:
        """Synchronously disconnect from the peer.
        """
        self.loop.run_until_complete(self.adisconnect())

    def send(self, data: bytes) -> bool:
        """Synchronously send data to the peer.

        Args:
            data: The raw data to send to the peer.

        Returns:
            A boolean value indicating the success of the operation.
        """
        return self.loop.run_until_complete(self.asend(data))

    def recv(self, size: int) -> bytes:
        """Synchronously receive data from the peer.

        Args:
            size: The maximum amount of data to receive (in bytes).

        Returns:
            The raw data received from the peer on success,
            or empty bytes string on failure.
        """
        return self.loop.run_until_complete(self.arecv(size))

    def send_message(self, message: bytes) -> bool:
        """Synchronously send a message to the peer.

        Note: A 2-byte NBO length prefix is added to the message before sending.

        Args:
            message: The message to send to the peer.

        Returns:
            A boolean value indicating the success of the operation.
        """
        return self.loop.run_until_complete(self.asend_message(message))

    def recv_message(self) -> bytes:
        """Synchronously receive a message from the peer.

        Note: A 2-byte NBO length prefix is expected before the message data.

        Returns:
            The message received from the peer on success,
            or empty bytes string on failure.
        """
        return self.loop.run_until_complete(self.arecv_message())

    async def aconnect(self) -> None:
        """Asynchronously connect to the peer.

        Note: Must be overridden by sub-classes.
        """
        raise NotImplementedError

    async def adisconnect(self) -> None:
        """Asynchronously disconnect from the peer.

        Note: Must be overridden by sub-classes.
        """
        raise NotImplementedError

    async def asend(self, data: bytes, timeout: float = None) -> bool:
        """Asynchronously send data to the peer.

        Args:
            data: The raw data to send to the peer.
            timeout: The amount of time to wait for this operation (in seconds).

        Returns:
            A boolean value indicating the success of the operation.

        Note: Must be overridden by sub-classes.
        """
        raise NotImplementedError

    async def arecv(self, size: int, timeout: float = None) -> bytes:
        """Asynchronously receive data from the peer.

        Args:
            size: The maximum amount of data to receive (in bytes).
            timeout: The amount of time to wait for this operation (in seconds).

        Returns:
            The raw data received from the peer on success,
            or empty bytes string on failure.

        Note: Must be overridden by sub-classes.
        """
        raise NotImplementedError

    async def asend_message(self, message: bytes, timeout: float = None) -> bool:
        """Asynchronously send a message to the peer.

        Note: A 2-byte NBO length prefix is added to the message before sending.

        Args:
            message: The message to send to the peer.
            timeout: The amount of time to wait for this operation (in seconds).

        Returns:
            A boolean value indicating the success of the operation.
        """
        # Send a message to the peer
        try:
            return await aio.wait_for(self.__asend_message(message), timeout, loop=self.loop)
        except aio.TimeoutError:
            return False

    async def arecv_message(self, timeout: float = None) -> bytes:
        """Asynchronously receive a message from the peer.

        Note: A 2-byte NBO length prefix is expected before the message data.

        Args:
            timeout: The amount of time to wait for this operation (in seconds).

        Returns:
            The message received from the peer on success,
            or empty bytes string on failure.
        """
        # Receive a message from the peer
        try:
            return await aio.wait_for(self.__arecv_message(), timeout, loop=self.loop)
        except aio.TimeoutError:
            return b''

    async def __asend_message(self, message: bytes) -> bool:
        # Determine message size
        prefix = len(message)

        # Prepend message size prefix
        buffer = bytearray(prefix + 2)
        buffer[:2] = struct.pack('!H', prefix)
        buffer[2:] = message

        # Send message on transport stream
        return await self.asend(buffer)

    async def __arecv_message(self) -> bytes:
        try:
            # Extract message size prefix
            prefix = struct.unpack('!H', await self.arecv(2))[0]
            
            # Receive message from transport stream
            return await self.arecv(prefix)

        except struct.error:
            # Failed to get message size prefix so return empty byte string
            return b''


class TcpMessageStream(BaseMessageStream):
    """TCP message transport class.
    """
    def __init__(self, host, port, **kwargs):
        super().__init__(**kwargs)
        self.host = host
        self.port = port
        self.stream = None

    def is_closed(self) -> bool:
        return self.stream is None or self.stream[1].is_closing()

    async def aconnect(self) -> None:
        # Grab the connection lock
        async with self.clock:
            # Connect to the peer if necessary
            if self.is_closed():
                self.stream = await aio.open_connection(
                    self.host, self.port, loop=self.loop)

    async def adisconnect(self) -> None:
        # Grab connection lock
        async with self.clock:
            # Disconnect from the peer if necessary
            if not self.is_closed():
                writer = self.stream[1]
                writer.close()
                await writer.wait_closed()

            # Forget about the old connection
            self.stream = None

    async def asend(self, data: bytes, timeout: float = None) -> bool:
        # Send data to the peer
        try:
            return await aio.wait_for(self.__asend(data), timeout, loop=self.loop)
        except aio.TimeoutError:
            return False

    async def arecv(self, size: int, timeout: float = None) -> bytes:
        # Receive data from the peer
        try:
            return await aio.wait_for(self.__arecv(size), timeout, loop=self.loop)
        except aio.TimeoutError:
            return b''

    async def __asend(self, data: bytes) -> bool:
        # Attempt to send data to the peer
        for _ in range(self.MAX_SEND_ATTEMPTS):
            try:
                # Grab the write lock
                async with self.wlock:
                    # Connect to the peer if necessary
                    await self.aconnect()

                    # Write packet data to the transport stream
                    writer = self.stream[1]
                    writer.write(data)
                    await writer.drain()

                    # Report successful transmission of the data
                    return True

            except Exception:
                # Disconnect if an exception is raised
                await self.adisconnect()

        # Report failure after exhausting all retries
        return False

    async def __arecv(self, size: int) -> bytes:
        # Attempt to receive data from the peer
        try:
            # Grab the read lock
            async with self.rlock:
                # Read packet data from the transport stream
                reader = self.stream[0]
                return await reader.read(size)

        except Exception:
            # Disconnect if an exception is raised
            await self.adisconnect()

        # Report failure if there is a connection error
        return b''


class TlsMessageStream(TcpMessageStream):
    """TLS message transport class.
    """
    def __init__(self, host, port, authname, **kwargs):
        super().__init__(host, port, **kwargs)
        self.authname = authname
        self.context = ssl.create_default_context()
        self.context.check_hostname = True

    async def aconnect(self) -> None:
        # Grab the connection lock
        async with self.clock:
            # Connect to the peer if necessary
            if self.is_closed():
                self.stream = await aio.open_connection(
                    self.host, self.port, loop=self.loop,
                    ssl=self.context, server_hostname=self.authname,
                    ssl_handshake_timeout=self.CONNECTION_TIMEOUT)
