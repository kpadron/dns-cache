import asyncio as aio
import struct
from abc import ABC, abstractmethod
from asyncio import BaseTransport
from typing import Awaitable, Optional, Tuple

__all__ = \
    (
        'AbstractStreamProtocol',
        'AbstractDatagramProtocol',
    )


class _BaseProtocol(aio.BaseProtocol):
    """Async DNS protocol base class."""

    __slots__ = \
        (
            '_loop',
            '_transport',
            '_connected',
            '_paused',
            '_drainer',
        )

    def __init__(self) -> None:
        """Initializes a _BaseProtocol instance."""
        self._loop = aio.get_event_loop()
        self._transport = None
        self._connected = False
        self._paused = False
        self._drainer = None

    @property
    def connected(self) -> bool:
        """Returns whether the connection is established."""
        return self._connected

    @property
    def paused(self) -> bool:
        """Returns whether the transport is paused for writing."""
        return self._paused

    def close(self) -> None:
        """Closes the transport."""
        if self._connected:
            self._transport.close()

    def connection_made(self, transport: BaseTransport) -> None:
        """Initializes the connection."""
        self._transport = transport
        self._connected = True

    def connection_lost(self, exc: Optional[Exception]) -> None:
        """Deinitializes the connection."""
        self._connected = False
        self._transport = None

        # Finalize drain waiters
        self.resume_writing()

    def pause_writing(self) -> None:
        """Pauses writing to the transport."""
        if self._paused:
            return

        if not self._connected:
            raise ConnectionError('not connected')

        assert self._connected
        self._paused = True

    def resume_writing(self) -> None:
        """Resumes writing to the transport."""
        if not self._paused:
            return

        self._paused = False

        drainer = self._drainer
        assert drainer is None or not drainer.done()

        if drainer is not None:
            drainer.set_result(None)
            self._drainer = None

    async def adrain_writes(self) -> Awaitable[None]:
        """Waits for buffered data to be flushed to the transport."""
        if not self._paused:
            return

        assert self._connected

        drainer = self._drainer
        assert drainer is None or not drainer.done()

        if drainer is None:
            drainer = self._loop.create_future()
            self._drainer = drainer

        await aio.shield(drainer)


class AbstractStreamProtocol(_BaseProtocol, aio.Protocol, ABC):
    """
    Stream based async DNS protocol abstract base class.

    Pure Virtual Methods:
        message_received: Called when a full DNS message is received.
        eof_received: Called when EOF is received from the peer.
    """

    __slots__ = \
        (
            '_buffer',
            '_closer',
        )

    def __init__(self) -> None:
        """Initializes a AbstractStreamProtocol instance."""
        super().__init__()

        self._buffer = bytearray()
        self._closer: Optional[aio.Handle] = None

    def write_message(self, message: bytes) -> None:
        """Writes a DNS message to the transport."""
        if not self._connected:
            raise ConnectionError('not connected')

        prefixed_message = struct.pack('!H', len(message)) + message
        self._transport.write(prefixed_message)

    def schedule_closer(self, delay: float = 3.0) -> None:
        """Schedules the closing of the transport."""
        if not self._connected:
            raise ConnectionError('not connected')

        closer = self._closer

        if closer is None:
            self._closer = self._loop.call_later(delay, self.close)

    def cancel_closer(self) -> None:
        """Cancels the scheduled closing of the transport."""
        closer = self._closer

        if closer is not None:
            closer.cancel()
            self._closer = None

    def connection_lost(self, exc: Optional[Exception]) -> None:
        super().connection_lost(exc)
        self._buffer.clear()
        self.cancel_closer()

    def data_received(self, data: bytes) -> None:
        """Receives data from the transport."""
        # Minimum size of a DNS message with a length prefix
        MIN_PREFIXED_SIZE = 14

        # Add new data to the buffer
        buffer = self._buffer
        buffer.extend(data)

        # Process DNS messages in the buffer
        while True:
            # Ensure the buffer holds at least a minimum DNS message
            buffer_size = len(buffer)
            if buffer_size < MIN_PREFIXED_SIZE:
                return

            # Peek the DNS message fields
            msg_size = struct.unpack_from('!H', buffer)[0] + 2

            # Verify that the reported message size is sane
            if msg_size < MIN_PREFIXED_SIZE:
                # Corrupted/Malicious DNS message stream
                self.close()
                return

            # Ensure we have the a full DNS message
            if buffer_size < msg_size:
                return

            # Remove the message from the buffer
            message = buffer[2:msg_size]
            del buffer[:msg_size]

            # Call the message_received callback
            self.message_received(message)

    @abstractmethod
    def eof_received(self) -> bool:
        """
        Handles receiving EOF from the transport.

        Returning false implicitly closes the transport.
        """
        raise NotImplementedError

    @abstractmethod
    def message_received(self, message: bytes) -> None:
        """Called when a full DNS message is received."""
        raise NotImplementedError


class AbstractDatagramProtocol(_BaseProtocol, aio.DatagramProtocol, ABC):
    """
    Datagram based async DNS protocol abstract base class.

    Pure Virtual Methods:
        datagram_received: Called when a full DNS message is received.
    """

    __slots__ = ()

    @abstractmethod
    def datagram_received(self, data: bytes, addr: Tuple[str, int]) -> None:
        """Receives a datagram from the transport."""
        raise NotImplementedError

    def error_received(self, exc: Exception) -> None:
        """Handles receiving errors from the transport."""
        pass
