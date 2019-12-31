import asyncio as aio
import random

import dns_packet as dp
import message_stream as ms


class DnsResolver:
    """A DNS stub resolver that forwards requests to upstream recursive servers.

    Attributes:
        MAX_RETRIES: The maximum number of upstream server queries per resolution.
        REQUEST_TIMEOUT: The maximum wait time per resolution (in seconds).
    """
    max_retries: int = 3
    request_timeout: float = 3.5

    def __init__(self, upstreams=(ms.TlsMessageStream('1.1.1.1', 853, 'cloudflare-dns.com'),), loop=None):
        """Initialize a DnsResolver instance.

        Args:
            upstreams: A sequence of BaseMessageStream instances used for communicating with upstream servers.
            loop: The async event loop to run on (defaults to current running loop).
        """
        # Initialize upstream server stream instances
        self.upstreams = upstreams

        # Set the current async event loop
        self.loop = loop or aio.get_event_loop()

        self.requests = {}
        self.responses = {}

        self._responses = {}
        self._events = {}

    def resolve(self, request: dp.Packet) -> dp.Packet:
        """Synchronously resolves a DNS request via forwarding to a upstream recursive server.

        Args:
            request: The DNS request packet to resolve.

        Returns:
            The DNS response packet.
        """
        return self.loop.run_until_complete(self.aresolve(request))

    async def aresolve(self, request: dp.Packet) -> dp.Packet:
        """Asynchronously resolves a DNS request via forwarding to a upstream recursive server.

        Args:
            request: The DNS request packet to resolve.

        Returns:
            The DNS response packet.
        """
        try:
            # Create skeleton DNS response
            response = request.reply()

            # Assign a query id to this request (used for tracking)
            query_id = self._queries % 65536
            self._queries += 1

            # Reset upstream RTTs to prevent drift
            if self._queries % 10000 == 0:
                logging.info('DotResolver::resolve: total_queries = %d' % (self._queries))
                for upstream in self._upstreams:
                    logging.info('DotResolver::resolve %r: avg_rtt = %f' % (upstream.address, upstream.rtt))
                    upstream.rtt = 0.0

            # Add request to active tracking
            self._events[query_id] = aio.Event(loop=self._loop)
            request.header.id = query_id

            for _ in range(DotResolver.max_retries + 1):
                # Select a upstream server to forward to
                upstream = self._select_upstream_rtt()

                # Forward a query packet to the upstream server
                rtt = self._loop.time()
                if await upstream.send_query(request.pack()):
                    break
            else:
                raise Exception('max retries reached')

            # Schedule the response to be processed
            self._loop.create_task(self._process_response(upstream))

            # Wait for request to be serviced
            await aio.wait_for(self._events[query_id].wait(), DotResolver.request_timeout, loop=self._loop)

            # Fill out response
            reply = self._responses[query_id]
            response.add_answer(*reply.rr)
            response.add_auth(*reply.auth)
            response.add_ar(*reply.ar)

        except Exception as exc:
            logging.error('DotResolver::resolve %r %d: %r' % (upstream.address, query_id, exc))
            response.header.rcode = getattr(dns.RCODE, 'SERVFAIL')

        finally:
            # Update RTT estimation for selected upstream server
            rtt = self._loop.time() - rtt
            upstream.rtt = 0.875 * upstream.rtt + 0.125 * rtt

            # Remove this request from tracking
            self._responses.pop(query_id, None)
            self._events.pop(query_id, None)

            return response

    async def _process_response(self, upstream: DotStream) -> None:
        try:
            # Receive an answer packet from the upstream server
            answer = await upstream.recv_answer()

            # An error occurred with the upstream connection
            if not answer:
                raise Exception('failed to receive DNS answer from upstream server')

            # Parse DNS answer packet into a response
            response = dns.DNSRecord.parse(answer)

            # Add response and signal response complete
            if response.header.id in self._events:
                self._responses[response.header.id] = response
                self._events[response.header.id].set()

        except Exception as exc:
            logging.error('DotResolver::_process_response %r: %r' % (upstream.address, exc))

    def _select_upstream_random(self) -> ms.BaseMessageStream:
        return random.choice(self.upstreams)
