import argparse as ap
import asyncio as aio
import logging

from dns_cache.resolver import AutoResolver, CachedResolver
from dns_cache.server import TcpServer, UdpServer
from dns_cache.tunnel import TlsTunnel

logging.basicConfig(format='[%(asctime)-15s] %(message)s', level=logging.INFO)

DEFAULT_SERVERS = \
    (
        ('1.1.1.1', 853, 'cloudflare-dns.com'),
        ('1.0.0.1', 853, 'cloudflare-dns.com'),
        ('2606:4700:4700::1111', 853, 'cloudflare-dns.com'),
        ('2606:4700:4700::1001', 853, 'cloudflare-dns.com'),
    )

DEFAULT_ADDRS = \
    (
        # ('localhost', 5053),
        ('127.0.0.1', 5053),
        # ('::1', 5053),
    )


def main() -> None:
    loop = aio.get_event_loop()

    local_addrs = DEFAULT_ADDRS
    upstream_servers = DEFAULT_SERVERS

    tunnels = [TlsTunnel(*args) for args in upstream_servers]
    resolver = AutoResolver(tunnels)

    tcp_factory = lambda: TcpServer(resolver)
    udp_factory = lambda: UdpServer(resolver)

    servers = []
    transports = []

    for (host, port) in local_addrs:
        tcp_awaitable = loop.create_server(tcp_factory, host, port)
        udp_awaitable = loop.create_datagram_endpoint(udp_factory, (host, port))

        gather_awaitable = aio.gather(tcp_awaitable, udp_awaitable)
        (server, (transport, _)) = loop.run_until_complete(gather_awaitable)

        servers.append(server)
        transports.append(transport)

    try:
        loop.run_forever()

    finally:
        for server in servers:
            server.close()

        for transport in transports:
            transport.close()

        for tunnel in tunnels:
            tunnel.close()

        for server in servers:
            loop.run_until_complete(server.wait_closed())

        loop.run_until_complete(loop.shutdown_asyncgens())
        loop.close()


if __name__ == '__main__':
    main()
