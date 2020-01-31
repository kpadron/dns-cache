from asyncio import TimerHandle, Transport
from typing import Optional, Tuple

from .packet import Packet
from .protocol import AbstractDatagramProtocol, AbstractStreamProtocol
from .resolver import AbstractResolver

__all__ = \
    (
        'TcpServer',
        'UdpServer',
    )


async def aresolve_query(resolver: AbstractResolver, query: bytes) -> bytes:
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
        )

    def __init__(self, resolver: AbstractResolver) -> None:
        """Initializes a TcpServer instance."""
        super().__init__()

        self._resolver = resolver
        self._flushing = False
        self._requests = 0

    def connection_made(self, transport: Transport) -> None:
        super().connection_made(transport)
        self.schedule_closer()

    def eof_received(self) -> bool:
        self._flushing = True
        return bool(self._requests)

    def _message_received(self, message: bytes) -> None:
        async def aservice_message() -> None:
            """Resolve a query using the resolver."""
            try:
                # Reset the idle timeout closer
                self.cancel_closer()

                # Resolve the query
                reply = await aresolve_query(self._resolver, message)

                # Send the reply packet
                self.write_message(reply)

            finally:
                self._requests -= 1

                if not self._requests:
                    if self._flushing:
                        self.close()
                    else:
                        self.schedule_closer()

        # Schedule query resolution
        self._loop.create_task(aservice_message())
        self._requests += 1


class UdpServer(AbstractDatagramProtocol):
    """UDP DNS stub server class."""

    __slots__ = '_resolver'

    def __init__(self, resolver: AbstractResolver) -> None:
        """Initializes a UdpServer instance."""
        super().__init__()

        self._resolver = resolver

    def datagram_received(self, message: bytes, addr: Tuple[str, int]) -> None:
        async def aservice_message() -> None:
            """Resolve a query using the resolver."""
            # Resolve the query
            reply = await aresolve_query(self._resolver, message)

            # Send the reply packet
            self._transport.sendto(reply, addr)

        # Schedule query resolution
        self._loop.create_task(aservice_message())
