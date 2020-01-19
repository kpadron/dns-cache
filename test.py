import itertools as it
import random
import time
from unittest import TestCase, main

import dns_cache
from dns_cache.packet import Answer, Packet, Question, NOERROR, RCODE
from dns_cache.tunnel import TcpTunnel, TlsTunnel

random.seed(0xDEADBEEF, 2)

TEST_DOMAINS = ('google.com', 'spotify.com', 'reddit.com', 'steam.com', 'python.org')
TEST_QUESTIONS = tuple(Question(domain) for domain in TEST_DOMAINS)
TEST_SIZE = 1000


class TestTcpTunnel(TestCase):
    def setUp(self):
        self.tunnel = TcpTunnel('1.1.1.1', 53)

    def tearDown(self):
        del self.tunnel

    def test_connect_disconnect(self):
        self.assertTrue(self.tunnel.connect(), 'failed to connect')
        self.assertTrue(self.tunnel.connected, 'connected attribute is incorrect')

        self.tunnel.disconnect()
        self.assertFalse(self.tunnel.connected, 'connected attribute is incorrect')

    def _check_answer_packet(self, query_packet, answer_packet, rcode=NOERROR):
        self.assertTrue(query_packet, 'Query is empty')
        self.assertTrue(answer_packet, 'Answer is empty')
        request = Packet.parse(query_packet)
        response = Packet.parse(answer_packet)
        self.assertEqual(request.header.id, response.header.id, 'Query id does not match')
        self.assertEqual(request.get_question(), response.get_question(), 'Question does not match')
        self.assertEqual(response.header.rcode, rcode, f'Unexpected RCODE: {RCODE[response.header.rcode]}')

    def test_resolve_query(self, questions=TEST_QUESTIONS):
        with self.tunnel as tunnel:
            for (qid, question) in enumerate(questions):
                query_packet = question.to_query(qid)
                answer_packet = tunnel.resolve_query(query_packet)
                self._check_answer_packet(query_packet, answer_packet)

    def test_submit_and_complete(self, questions=TEST_QUESTIONS):
        pending = []

        with self.tunnel as tunnel:
            for (qid, question) in enumerate(questions):
                query_packet = question.to_query(qid)
                pending_answer = tunnel.submit_query(query_packet)
                pending.append((query_packet, pending_answer))

            for (query_packet, pending_answer) in pending:
                answer_packet = tunnel.complete_query(pending_answer)
                self._check_answer_packet(query_packet, answer_packet)

    def test_submit_and_complete_duplicates(self):
        duplicates = it.islice(it.cycle(TEST_QUESTIONS), TEST_SIZE)
        self.test_submit_and_complete(duplicates)

    def test_resolve_queries(self, questions=TEST_QUESTIONS):
        queries = [question.to_query(qid) for (qid, question) in enumerate(questions)]

        with self.tunnel as tunnel:
            answers = tunnel.resolve_queries(queries)

        self.assertEqual(len(queries), len(answers), 'Lengths are not the same')

        for (query_packet, answer_packet) in zip(queries, answers):
            self._check_answer_packet(query_packet, answer_packet)

    def test_resolve_queries_duplicates(self):
        questions = it.islice(it.cycle(TEST_QUESTIONS), TEST_SIZE)
        self.test_resolve_queries(questions)

class TestTlsTunnel(TestTcpTunnel):
    def setUp(self):
        self.tunnel = dns_cache.tunnel.TlsTunnel('1.1.1.1', 853, 'cloudflare-dns.com')


if __name__ == '__main__':
    main()
