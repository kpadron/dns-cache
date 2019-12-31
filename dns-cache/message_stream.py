import asyncio as aio
import logging
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
        MAX_SEND_RETRIES: The maximum number of retransmissions per send operation.
        CONNECTION_TIMEOUT: The maximum time to wait while establishing a message stream (in seconds).
    """
    MAX_SEND_RETRIES = 2
    CONNECTION_TIMEOUT = 2.5

    def __init__(self, peer, loop=None):
        """Initialize a BaseMessageStream instance.

        Args:
            peer: The hostname, address, or other relevant information of the connection peer.
            loop: The async event loop to run on (defaults to current running loop).
        """
        self.peer = peer
        self.stream = None
        self.loop = loop or aio.get_event_loop()

        self.clock = aio.Lock(loop=self.loop)
        self.rlock = aio.Lock(loop=self.loop)
        self.wlock = aio.Lock(loop=self.loop)

    def connect(self) -> None:
        """Synchronously connect to the peer.
        """
        self.loop.run_until_complete(self.aconnect())

    async def aconnect(self) -> None:
        """Asynchronously connect to the peer.

        Note: Must be overridden by sub-classes.
        """
        assert NotImplementedError

    def disconnect(self) -> None:
        """Synchronously disconnect from the peer.
        """
        self.loop.run_until_complete(self.adisconnect())

    async def adisconnect(self) -> None:
        """Asynchronously disconnect from the peer.

        Note: Must be overridden by sub-classes.
        """
        assert NotImplementedError

    def send(self, data: bytes) -> bool:
        """Synchronously send data to the peer.

        Args:
            data: The raw data to send to the peer.

        Returns:
            A boolean value indicating the success of the operation.
        """
        return self.loop.run_until_complete(self.asend(data))

    async def asend(self, data: bytes, timeout: float = None) -> bool:
        """Asynchronously send data to the peer.

        Args:
            data: The raw data to send to the peer.
            timeout: The amount of time to wait for this operation (in seconds).

        Returns:
            A boolean value indicating the success of the operation.

        Note: Must be overridden by sub-classes.
        """
        assert NotImplementedError

    def recv(self, size: int) -> bytes:
        """Synchronously receive data from the peer.

        Args:
            size: The maximum amount of data to receive (in bytes).

        Returns:
            The raw data received from the peer on success,
            or empty bytes string on failure.
        """
        return self.loop.run_until_complete(self.arecv(size))

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
        assert NotImplementedError

    def send_request(self, request: bytes) -> bool:
        """Synchronously send a message to the peer.

        Args:
            request: The message to send to the peer.

        Returns:
            A boolean value indicating the success of the operation.
        """
        return self.loop.run_until_complete(self.asend_request(request))

    async def asend_request(self, request: bytes, timeout: float = None) -> bool:
        """Asynchronously send a message to the peer.

        Args:
            request: The message to send to the peer.
            timeout: The amount of time to wait for this operation (in seconds).

        Returns:
            A boolean value indicating the success of the operation.
        """
        prefix = len(request)

        buffer = bytearray(prefix + 2)
        buffer[:2] = struct.pack('!H', prefix)
        buffer[2:] = request

        return await self.asend(buffer, timeout)

    def recv_response(self) -> bytes:
        """Synchronously receive a message from the peer.

        Returns:
            The message received from the peer on success,
            or empty bytes string on failure.
        """
        return self.loop.run_until_complete(self.arecv_response())

    async def arecv_response(self, timeout: float = None) -> bytes:
        """Asynchronously receive a message from the peer.

        Args:
            timeout: The amount of time to wait for this operation (in seconds).

        Returns:
            The message received from the peer on success,
            or empty bytes string on failure.
        """
        response = b''

        try:
            prefix = struct.unpack('!H', await self.arecv(2, timeout))[0]
            response = await self.arecv(prefix, timeout)

        except struct.error:
            pass

        finally:
            return response


class TcpMessageStream(BaseMessageStream):
    """TCP message transport class.
    """
    def __init__(self, host, port, **kwargs):
        super().__init__((host, port), **kwargs)

    def is_closed(self) -> bool:
        return self.stream is None or self.stream[1].is_closing()

    async def aconnect(self) -> None:
        # Grab the connection lock
        async with self.clock:
            # Connect to the peer if necessary
            if self.is_closed():
                self.stream = await aio.open_connection(
                    self.peer[0], self.peer[1], loop=self.loop)

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

    async def __asend(self, data: bytes) -> bool:
        # Attempt to send data to the peer
        for _ in range(self.MAX_SEND_RETRIES + 1):
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

            except Exception as exc:
                # Log error if we fail to send
                logging.error('TcpMessageStream::asend %r: %r' % (self.peer, exc))
                await self.adisconnect()

        # Report failure after exhausting all retries
        return False

    async def asend(self, data: bytes, timeout: float = None) -> bool:
        success = False

        # Send data to the peer
        try:
            success = await aio.wait_for(self.__asend(data), timeout, loop=self.loop)

        except aio.TimeoutError:
            pass

        finally:
            return success

    async def arecv(self, size: int, timeout: float = None) -> bytes:
        data = b''

        # Receive data from the peer
        try:
            # Grab the read lock
            async with self.rlock:
                # Read packet data from the transport stream
                reader = self.stream[0]
                data = await aio.wait_for(reader.read(size), timeout, loop=self.loop)

        except aio.TimeoutError:
            pass

        except Exception as exc:
            logging.error('TcpMessageStream::arecv %r: %r' % (self.peer, exc))
            await self.adisconnect()

        finally:
            return data


class TlsMessageStream(BaseMessageStream):
    """TLS message transport class.
    """
    def __init__(self, host, port, authname, **kwargs):
        super().__init__((host, port, authname), **kwargs)

        self.context = ssl.create_default_context()
        self.context.check_hostname = True

    def is_closed(self) -> bool:
        return self.stream is None or self.stream[1].is_closing()

    async def aconnect(self) -> None:
        # Grab the connection lock
        async with self.clock:
            # Connect to the peer if necessary
            if self.is_closed():
                self.stream = await aio.open_connection(
                    self.peer[0], self.peer[1], loop=self.loop,
                    ssl=self.context, server_hostname=self.peer[2],
                    ssl_handshake_timeout=self.CONNECTION_TIMEOUT)

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

    async def __asend(self, data: bytes) -> bool:
        # Attempt to send data to the peer
        for _ in range(self.MAX_SEND_RETRIES + 1):
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

            except Exception as exc:
                # Log error if we fail to send
                logging.error('TlsMessageStream::asend %r: %r' % (self.peer, exc))
                await self.adisconnect()

        # Report failure after exhausting all retries
        return False

    async def asend(self, data: bytes, timeout: float = None) -> bool:
        success = False

        # Send data to the peer
        try:
            success = await aio.wait_for(self.__asend(data), timeout, loop=self.loop)

        except aio.TimeoutError:
            pass

        finally:
            return success

    async def arecv(self, size: int, timeout: float = None) -> bytes:
        data = b''

        # Receive data from the peer
        try:
            # Grab the read lock
            async with self.rlock:
                # Read packet data from the transport stream
                reader = self.stream[0]
                data = await aio.wait_for(reader.read(size), timeout, loop=self.loop)

        except aio.TimeoutError:
            pass

        except Exception as exc:
            logging.error('TlsMessageStream::arecv %r: %r' % (self.peer, exc))
            await self.adisconnect()

        finally:
            return data
