import random
import time
import asyncio as aio

import dnslib as dl

import dns_tunnel as dt
import dns_resolver as dr

tunnels = \
[
    dt.TlsTunnel('1.1.1.1', 853, 'cloudflare-dns.com'),
    dt.TlsTunnel('1.0.0.1', 853, 'cloudflare-dns.com'),
    dt.TlsTunnel('2606:4700:4700::1111', 853, 'cloudflare-dns.com'),
    dt.TlsTunnel('2606:4700:4700::1001', 853, 'cloudflare-dns.com'),
]

hosts = ['google.com', 'python.org', 'example.com', 'reddit.com', 'steam.com']

num_queries = 10000
queries = [dl.DNSRecord.question(random.choice(hosts)) for i in range(num_queries)]
for (index, query) in enumerate(queries):
    query.header.id = index
    queries[index] = query.pack()

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
    with dt.TlsTunnel('1.1.1.1', 853, 'cloudflare-dns.com') as s:
        test_resolve()
        test_resolve()
        print('sleeping for 10 s')
        time.sleep(10)
        test_resolve()
        test_resolve()
        [dl.DNSRecord.parse(answer) for answer in answers]
        print('queries per second:', num_queries * 4 // sum(times))

        print()
        print(s)
        print('connected:', s.connected)
        print('queries:', s.has_queries, list(s.queries))
        print('answers:', s.has_answers, list(s.answers))

    times.clear()
    test_resolver()
    test_resolver()
    print('sleeping for 10 s')
    time.sleep(10)
    test_resolver()
    test_resolver()
    [dl.DNSRecord.parse(answer) for answer in answers]
    print('queries per second:', num_queries * 4 // sum(times))

    try:
        r.resolve(queries[:5] + [7, 3, 4])
    except Exception as exc:
        print(exc)

    print()
    print(r)
    print('tunnels:', r.tunnels)
    print('counters:', r.counters)
    print('queries:', r.queries)

    for tn in tunnels:
        tn.disconnect()
