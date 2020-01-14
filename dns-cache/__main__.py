import asyncio as aio
import random
import time

import dnslib as dl

import dns_packet as dp
import dns_resolver as dr
import dns_tunnel as dt

loop = aio.get_event_loop()

tunnels = \
[
    dt.TlsTunnel('1.1.1.1', 853, 'cloudflare-dns.com'),
    dt.TlsTunnel('1.0.0.1', 853, 'cloudflare-dns.com'),
    dt.TlsTunnel('2606:4700:4700::1111', 853, 'cloudflare-dns.com'),
    dt.TlsTunnel('2606:4700:4700::1001', 853, 'cloudflare-dns.com'),
]

hosts = ['google.com', 'python.org', 'example.com', 'reddit.com', 'steam.com']

num_queries = 30000
queries = [dp.Question(random.choice(hosts)) for i in range(num_queries)]

answers = []
times = []

s = None

r = dr.StubResolver(tunnels)

def test_resolve():
    global answers
    global times
    t = time.time()
    answers = s.resolve(queries)
    t = time.time() - t
    times.append(t)
    print(t * 1000, 'ms')

def test_resolver():
    global answers, times
    t = time.time()
    answers = r.resolve(queries)
    t = time.time() - t
    times.append(t)
    print(t * 1000, 'ms')

if __name__ == '__main__':
    times.clear()
    test_resolver()
    test_resolver()
    print('sleeping for 10 s')
    time.sleep(10)
    test_resolver()
    test_resolver()
    print('queries per second:', num_queries * 4 // sum(times))

    try:
        # r.resolve(queries[:5] + [7, 3, 4])
        pass
    except Exception as exc:
        print(exc)

    print()
    print(r)
    print('tunnels:', r.tunnels)
    print('counters:', r.counters)
    print('queries:', r.queries)

    for tn in tunnels:
        tn.disconnect()

    loop.run_until_complete(loop.shutdown_asyncgens())
    loop.close()
