import asyncio as aio
from abc import ABCMeta, abstractmethod
from asyncio import (BaseProtocol, BaseTransport, DatagramProtocol, Future,
                     Protocol)
from struct import Struct
from typing import Awaitable, MutableSequence, Optional, Tuple

__all__ = \
    (
        'AbstractStreamProtocol',
        'AbstractDatagramProtocol',
    )


class _BaseProtocol(BaseProtocol):
    """Async DNS protocol base class."""

    __slots__ = \
        (
            '_loop',
            '_transport',
            '_connected',
            '_paused',
            '_drainers',
        )

    def __init__(self) -> None:
        """Initializes a _BaseProtocol instance."""
        self._loop = aio.get_event_loop()
        self._transport: Optional[BaseTransport] = None
        self._connected = False
        self._paused = False
        self._drainers: MutableSequence[Future] = []

    @property
    def connected(self) -> bool:
        """Returns whether the connection is established."""
        return self._connected

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
        """Pauses writing to the connection."""
        assert self._connected
        self._paused = True

    def resume_writing(self) -> None:
        """Resumes writing to the connection."""
        self._paused = False

        for drainer in self._drainers:
            if not drainer.done():
                drainer.set_result(None)

        self._drainers.clear()

    async def _drain_writes(self) -> Awaitable[None]:
        """Waits for buffered data to be flushed to the connection."""
        if not self._paused:
            return

        assert self._connected

        drainer = self._loop.create_future()
        self._drainers.append(drainer)

        await drainer


class AbstractStreamProtocol(_BaseProtocol, Protocol, metaclass=ABCMeta):
    """
    Stream based async DNS protocol abstract base class.

    Pure Virtual Methods:
        _message_received: Called when a full DNS message is received.
        eof_received: Called when EOF is received from the peer.
    """

    __slots__ = '_buffer'

    _peeker = Struct('!H').unpack_from
    _peek = lambda s, p: s._peeker(p)[0]

    _prefixer = Struct('!H').pack
    _prefix = lambda s, p: s._prefixer(len(p)) + p

    def __init__(self) -> None:
        """Initializes a AbstractStreamProtocol instance."""
        super().__init__()

        self._buffer = bytearray()

    def data_received(self, data: bytes) -> None:
        """Receives data from the connection."""
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
            msg_size = self._peek(buffer)

            # Verify that the reported message size is sane
            msg_size += 2
            if msg_size < MIN_PREFIXED_SIZE:
                # Corrupted/Malicious DNS message stream
                self._transport.abort()
                return

            # Ensure we have the a full DNS message
            if buffer_size < msg_size:
                return

            # Remove the message from the buffer
            message = buffer[2:msg_size]
            del buffer[:msg_size]

            # Call the _message_received callback
            self._message_received(message)

    @abstractmethod
    def eof_received(self):
        """Handles receiving EOF from the connection."""
        raise NotImplementedError

    @abstractmethod
    def _message_received(self, message: bytes) -> None:
        """Called when a full DNS message is received."""
        raise NotImplementedError

    def _write_message(self, message: bytes) -> None:
        """Writes a message to the transport stream."""
        self._transport.write(self._prefix(message))


class AbstractDatagramProtocol(_BaseProtocol, DatagramProtocol, metaclass=ABCMeta):
    """
    Datagram based async DNS protocol abstract base class.
    
    Pure Virtual Methods:
        datagram_received: Called when a full DNS message is received.
    """

    __slots__ = ()

    @abstractmethod
    def datagram_received(self, data: bytes, addr: Tuple[str, int]) -> None:
        """Receives a datagram from the connection."""
        raise NotImplementedError

    def error_received(self, exc: Exception) -> None:
        """Handles receiving socket errors from the connection."""
        pass
