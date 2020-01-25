import itertools as it
import logging
import random
import time
from unittest import TestCase, main

import dns_cache
from dns_cache.packet import NOERROR, RCODE, Answer, Packet, Question
from dns_cache.resolver import CachedResolver, StubResolver
from dns_cache.tunnel import TcpTunnel, TlsTunnel
from dns_cache.utility import LruCache

logging.basicConfig(format='[%(asctime)-15s] %(message)s', level=logging.INFO)
random.seed(0xDEADBEEF, 2)

TEST_SERVERS = \
    (
        ('1.1.1.1', 853, 'cloudflare-dns.com'),
        ('1.0.0.1', 853, 'cloudflare-dns.com'),
        ('2606:4700:4700::1111', 853, 'cloudflare-dns.com'),
        ('2606:4700:4700::1001', 853, 'cloudflare-dns.com'),
    )

TEST_DOMAINS = ('google.com', 'spotify.com', 'reddit.com', 'steam.com', 'python.org')
TEST_QUESTIONS = tuple(Question(domain) for domain in TEST_DOMAINS)
TEST_QUERIES = tuple(question.to_query(i) for (i, question) in enumerate(TEST_QUESTIONS))
TEST_SIZE = 50000


class TestTcpTunnel(TestCase):
    def setUp(self):
        self.tunnel = TcpTunnel('1.1.1.1', 53)

    def tearDown(self):
        del self.tunnel

    def test_connect_disconnect(self):
        self.tunnel.open(10)
        self.assertTrue(self.tunnel.connected, 'connected attribute is incorrect')

        self.tunnel.close()
        self.assertFalse(self.tunnel.connected, 'connected attribute is incorrect')

    def test_resolve_query(self, queries=TEST_QUERIES):
        with self.tunnel as tunnel:
            for query_packet in queries:
                answer_packet = tunnel.resolve_query(query_packet)
                self._check_answer_packet(query_packet, answer_packet)

    def test_submit_and_complete(self, queries=TEST_QUERIES):
        pending = []

        with self.tunnel as tunnel:
            for query_packet in queries:
                pending_answer = tunnel.submit_query(query_packet)
                pending.append((query_packet, pending_answer))

            for (query_packet, pending_answer) in pending:
                answer_packet = tunnel.complete_query(pending_answer)
                self._check_answer_packet(query_packet, answer_packet)

    def test_submit_and_complete_duplicates(self):
        duplicates = it.islice((question.to_query(i) for (i, question) in enumerate(it.cycle(TEST_QUESTIONS))), TEST_SIZE)
        self.test_submit_and_complete(duplicates)

    def _check_answer_packet(self, query_packet, answer_packet, rcode=NOERROR):
        self.assertTrue(query_packet, 'Query is empty')
        self.assertTrue(answer_packet, 'Answer is empty')
        request = Packet.parse(query_packet)
        response = Packet.parse(answer_packet)
        self.assertEqual(request.header.id, response.header.id, 'Query id does not match')
        self.assertEqual(request.get_question(), response.get_question(), 'Question does not match')
        self.assertEqual(response.header.rcode, rcode, f'Unexpected RCODE: {RCODE[response.header.rcode]}')


class TestTlsTunnel(TestTcpTunnel):
    def setUp(self):
        self.tunnel = TlsTunnel('1.1.1.1', 853, 'cloudflare-dns.com')


class TestStubResolver(TestCase):
    def setUp(self):
        self.tunnels = tuple((TlsTunnel(*args) for args in TEST_SERVERS))
        self.resolver = StubResolver(self.tunnels)

    def tearDown(self):
        del self.resolver
        for tunnel in self.tunnels:
            tunnel.close()
        
        del self.tunnels

    def test_resolve_question(self, questions=TEST_QUESTIONS):
        for question in questions:
            answer = self.resolver.resolve_question(question)
            self._check_answer(question, answer)
            print(answer)

    def test_resolve_questions(self, questions=TEST_QUESTIONS):
        answers = self.resolver.resolve(questions)
        self.assertEqual(len(questions), len(answers), 'Answers has unexpected length')
        for question, answer in zip(questions, answers):
            self._check_answer(question, answer)

    def test_resolve_questions_duplicates(self):
        duplicates = tuple(it.islice(it.cycle(TEST_QUESTIONS), TEST_SIZE))
        self.test_resolve_questions(duplicates)

    def _check_answer(self, question, answer, rcode=NOERROR):
        self.assertEqual(answer.rcode, rcode, f'Unexpected RCODE: {RCODE[answer.rcode]}')

class TestCachedResolver(TestStubResolver):
    def setUp(self):
        super().setUp()
        self.cache = LruCache(1000)
        self.resolver = CachedResolver(self.tunnels, self.cache)

    def tearDown(self):
        super().tearDown()
        del self.cache

if __name__ == '__main__':
    main()
