import argparse as ap
import asyncio as aio

from .resolver import CachedResolver
from .server import TcpServer
from .tunnel import TlsTunnel

DEFAULT_SERVERS = \
    (
        ('1.1.1.1', 853, 'cloudflare-dns.com'),
        ('1.0.0.1', 853, 'cloudflare-dns.com'),
        ('2606:4700:4700::1111', 853, 'cloudflare-dns.com'),
        ('2606:4700:4700::1001', 853, 'cloudflare-dns.com'),
    )

DEFAULT_ADDRS = \
    (
        ('127.0.0.1', 5053),
        ('::1', 5053),
    )


def main() -> None:
    loop = aio.get_event_loop()

    local_addrs = DEFAULT_ADDRS
    upstream_servers = DEFAULT_SERVERS

    tunnels = [TlsTunnel(*args) for args in upstream_servers]
    resolver = CachedResolver(tunnels)

    servers = []
    for (host, port) in local_addrs:
        server = loop.run_until_complete(loop.create_server(lambda: TcpServer(resolver), host, port))
        servers.append(server)

    try:
        loop.run_forever()

    finally:
        for server in servers:
            server.close()

        for server in servers:
            loop.run_until_complete(server.wait_closed())

        loop.run_until_complete(loop.shutdown_asyncgens())
        loop.close()


if __name__ == '__main__':
    main()
