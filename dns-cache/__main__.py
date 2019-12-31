import socket
import socketserver

import dns

class DnsRequestHandler(socketserver.DatagramRequestHandler):
    def handle(self):
        query = self.rfile.read()
        packet = dns.Packet(query)
        packet.header.qr ^= True

        print(packet)
        print(query.hex())

        self.wfile.write(packet.encode())


if __name__ == '__main__':
    with socketserver.UDPServer(('127.0.0.1', 5053), DnsRequestHandler) as server:
        server.serve_forever()
