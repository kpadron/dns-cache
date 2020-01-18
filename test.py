import itertools as it
import time
from unittest import TestCase, main

import dns_cache


class TestTcpTunnel(TestCase):
    def setUp(self):
        self.tunnel = dns_cache.tunnel.TcpTunnel('1.1.1.1', 53)

    def tearDown(self):
        del self.tunnel

    def test_connect_disconnect(self):
        self.assertTrue(self.tunnel.connect(), 'failed to connect')
        self.assertTrue(self.tunnel.connected, 'connected attribute is incorrect')
        self.assertIsNotNone(self.tunnel._listener, 'listener is not listening')

        time.sleep(1)

        self.tunnel.disconnect()
        self.assertFalse(self.tunnel.connected, 'connected attribute is incorrect')
        self.assertTrue(self.tunnel._listener.done(), 'listener is not done listening')

    def test_resolve_query(self):
        question = dns_cache.packet.Question('google.com')

        with self.tunnel as tunnel:
            packet = dns_cache.packet.Packet.parse(tunnel.resolve_query(question.to_query()))
            p_question = packet.get_question()
            p_answer = packet.get_answer()
            self.assertEqual(question, p_question, 'Questions do not match')
            self.assertEqual(p_answer.rcode, dns_cache.packet.NOERROR, f'Query failed {dns_cache.packet.RCODE[p_answer.rcode]}')

    def test_resolve_queries(self):
        hosts = ('google.com', 'spotify.com', 'reddit.com', 'steam.com', 'python.org')
        questions = []
        pass

class TestTlsTunnel(TestTcpTunnel):
    def setUp(self):
        self.tunnel = dns_cache.tunnel.TlsTunnel('1.1.1.1', 853, 'cloudflare-dns.com')


if __name__ == '__main__':
    main()
