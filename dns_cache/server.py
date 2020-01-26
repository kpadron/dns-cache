from asyncio import Transport, TimerHandle
from typing import Optional, Tuple

from .packet import Packet
from .protocol import AbstractDatagramProtocol, AbstractStreamProtocol
from .resolver import AbstractResolver

__all__ = \
    (
        'TcpServer',
        'UdpServer',
    )


async def resolve_query(resolver: AbstractResolver, query: bytes) -> bytes:
    """Resolves a query using the provided resolver."""
    # Parse the query packet
    packet = Packet.parse(query)

    # TODO: Handle bad input queries

    # Handle valid queries
    if not packet.header.rcode:
        # Extract the question
        question = packet.get_question()

        # Resolve the question
        answer = await resolver.submit_question(question)

        # Set the answer
        packet.set_answer(answer)

    # Return the reply packet
    return packet.encode()


class TcpServer(AbstractStreamProtocol):
    """TCP DNS stub server class."""

    __slots__ = \
        (
            '_resolver',
            '_flushing',
            '_requests',
            '_closer',
        )

    IDLE_TIMEOUT = 5.0

    def __init__(self, resolver: AbstractResolver) -> None:
        """Initializes a TcpServer instance."""
        super().__init__()

        self._resolver = resolver
        self._flushing = False
        self._requests = 0
        self._closer: Optional[TimerHandle] = None

    def connection_made(self, transport: Transport) -> None:
        super().connection_made(transport)
        self._start_closer()

    def eof_received(self) -> bool:
        self._flushing = True
        self.data_received(b'')

        if self._requests <= 0:
            self._cancel_closer()
            return False

        return True

    def _message_received(self, message: bytes) -> None:
        async def aresolve_query() -> None:
            """Resolve a query using the resolver."""
            try:
                # Reset the idle timeout closer
                self._cancel_closer()

                # Resolve the query
                reply = await resolve_query(self._resolver, message)

                # Send the reply packet
                self._write_message(reply)

            finally:
                self._requests -= 1

                if self._requests <= 0:
                    if self._flushing:
                        self._close()
                    else:
                        self._start_closer()

        # Schedule query resolution
        self._loop.create_task(aresolve_query())
        self._requests += 1

    def _close(self) -> None:
        """Close the stream transport."""
        if self._connected:
            self._transport.close()

    def _start_closer(self) -> None:
        """Schedule the closing of the stream transport."""
        self._closer = self._loop.call_later(self.IDLE_TIMEOUT, self._close)

    def _cancel_closer(self) -> None:
        """Cancel the idle timeout closer."""
        if self._closer is not None:
            self._closer.cancel()


class UdpServer(AbstractDatagramProtocol):
    """UDP DNS stub server class."""

    __slots__ = '_resolver'

    def __init__(self, resolver: AbstractResolver) -> None:
        """Initializes a UdpServer instance."""
        super().__init__()

        self._resolver = resolver

    def datagram_received(self, message: bytes, addr: Tuple[str, int]) -> None:
        async def aresolve_query() -> None:
            """Resolve a query using the resolver."""
            # Resolve the query
            reply = resolve_query(self._resolver, message)

            # Send the reply packet
            self._transport.sendto(reply, addr)

        # Schedule query resolution
        self._loop.create_task(aresolve_query())
