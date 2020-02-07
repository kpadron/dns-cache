from asyncio import TimerHandle, Transport
from typing import Optional, Tuple

from . import protocols
from .packet import Packet
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


class TcpServer(protocols.AbstractStreamProtocol):
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
        self._requests = set()

    def connection_made(self, transport: Transport) -> None:
        super().connection_made(transport)
        self.schedule_closer()

    def connection_lost(self, exc: Optional[Exception]) -> None:
        transport = self._transport
        requests = self._requests
        super().connection_lost(exc)

        # Ensure the tranport is closed
        transport.abort()

        # Finalize requests
        for request in requests:
            request.cancel()

        requests.clear()

    def eof_received(self) -> bool:
        self._flushing = True
        return bool(self._requests)

    def message_received(self, message: bytes) -> None:
        async def aservice_message() -> None:
            """Resolve a query using the resolver."""
            try:
                # Reset the idle timeout closer
                self.cancel_closer()

                # Resolve the query
                reply = await aresolve_query(self._resolver, message)

                # Send the reply packet
                self.write_message(reply)
                await self.adrain_writes()

            finally:
                self._requests.discard(request)

                if not self._requests and self._connected:
                    if self._flushing:
                        self.close()
                    else:
                        self.schedule_closer()

        # Schedule query resolution
        request = self._loop.create_task(aservice_message())
        self._requests.add(request)


class UdpServer(protocols.AbstractDatagramProtocol):
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
            await self.adrain_writes()

        # Schedule query resolution
        self._loop.create_task(aservice_message())
