import asyncio as aio
from asyncio import (BaseProtocol, DatagramProtocol, DatagramTransport,
                     Protocol, Transport)
from typing import Optional

from .resolver import AbstractResolver

__all__ = \
[
    'BaseServer',
    'UdpServer',
    'TcpServer',
]


class BaseServer(BaseProtocol, metaclass=ABCMeta):
    """DNS stub server base class.

    Uses a AbstractResolver instance to service client requests.
    """
    def __init__(self, resolver: AbstractResolver) -> None:
        """Initializes a BaseServer instance."""
        self._loop = aio.get_event_loop()
        self._resolver = resolver
        self._transport: Optional[Transport] = None

    def connection_made(self, transport: Transport) -> None:
        """"""
        self._transport = transport

    def connection_lost(self) -> None:
        """"""
        ...


class UdpServer(BaseServer, )
