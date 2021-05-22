from signal import signal, SIGINT

from scapy.layers.inet import IP, TCP
from scapy.sendrecv import sniff, send
from threading import Thread, Lock
import time
import sys

from cookie import cookie_check, cookie_create
from collector import DataCollector


def signalHandler(signum, frame):
    raise Exception("Shutdown")


class LoadBalancer:

    def __init__(self, vip, rip, isAttacked, filename):
        self.vip = vip
        self.rip = rip
        self.states = {}
        self.timeouts = {}
        self.defult_timeout = 10
        self.servers = {int(0x3333): '192.168.0.1'}
        self.key = int(0x11112222)
        self.isAttacked = isAttacked
        self.isRunning = False
        # handler
        self.lock = Lock()
        self.handler = Thread(target=self.update_timeouts)
        self.pause = 1
        # plot collector
        self.collector = DataCollector(filename)

    def update_timeouts(self):
        while self.isRunning:
            print(self.timeouts)
            try:
                t = time.time()
                with self.lock:
                    ll = list(self.timeouts.items())
                for k, v in ll:
                    if v + self.defult_timeout < t:
                        with self.lock:
                            self.states.pop(k)
                            self.timeouts.pop(k)
            except:
                print("Handler {}: error of timeout checking".format(getpid()))
            self.collector.add_point(len(self.states))
            time.sleep(self.pause)

    def start(self):
        try:
            self.isRunning = True
            self.handler.start()
            # receive packet
            sniff(iface='h2-eth0', prn=self.process_packet,
                  filter="tcp port 80 and host " + self.vip)
        except Exception as err:
            print(err)
            self.isRunning = False
            self.collector.terminate()
            self.handler.join()


    def process_packet(self, pkt):
        t0 = time.time()

        # get l3 layer
        pkt = pkt.payload
        # print("RCV", pkt.summary())
        # generate 4 tuple for hashing
        tuple_4 = str(pkt.src) + str(pkt.dst) + str(pkt.payload.sport) + str(pkt.payload.dport)
        # print(tuple_4)

        # check current connection in our states
        global response

        if tuple_4 in self.states.keys():
            # response = IP(src=self.rip, dst=self.servers[self.states[tuple_4]]) / pkt
            response = IP(src=self.rip, dst=self.servers[self.states[tuple_4]]) / \
                       IP(src=pkt.src, dst=pkt.dst) / \
                       TCP(sport=pkt.payload.sport, dport=pkt.payload.dport, seq=pkt.payload.seq,
                           ack=pkt.payload.ack, flags=pkt.payload.flags, window=pkt.payload.window,
                           options=pkt.payload.options) / \
                       pkt.payload.payload
            with self.lock:
                self.timeouts[tuple_4] = time.time()
            # coonection is closing
            if pkt.haslayer(TCP) and pkt.payload.flags == 'FA':
                with self.lock:
                    self.states.pop(tuple_4)
                    self.timeouts.pop(tuple_4)

        elif pkt.haslayer(TCP) and pkt.payload.flags == 'S':
            # 3333 is server identifier
            id = int(0x3333)
            if not self.isAttacked:
                with self.lock:
                    self.states[tuple_4] = id
                    self.timeouts[tuple_4] = time.time()
                # response = IP(src=self.rip, dst=self.servers[id]) / pkt
                response = IP(src=self.rip, dst=self.servers[id]) / \
                           IP(src=pkt.src, dst=pkt.dst) / \
                           TCP(sport=pkt.payload.sport, dport=pkt.payload.dport, seq=pkt.payload.seq,
                               ack=pkt.payload.ack, flags=pkt.payload.flags, window=pkt.payload.window,
                               options=pkt.payload.options)
            else:
                # add experiment option
                response = IP(src=self.rip, dst=self.servers[id]) / \
                           IP(src=pkt.src, dst=pkt.dst) / \
                           TCP(sport=pkt.payload.sport, dport=pkt.payload.dport, seq=pkt.payload.seq,
                               ack=pkt.payload.ack, flags=pkt.payload.flags, window=pkt.payload.window,
                               options=pkt.payload.options + [('Experiment',
                                                               (0x0348,
                                                                self.key >> 16,
                                                                self.key & int(0xFFFF),
                                                                id)),
                                                              ('NOP', 0)])
        elif self.isAttacked and pkt.haslayer(TCP) and pkt.payload.flags == 'A':
            # check cookie and get id
            print(hex(pkt[TCP].ack - 1))
            print(hex(cookie_create(pkt[IP], pkt[TCP], pkt[TCP].seq - 1, 0x3333, 0x11112222)))
            id = cookie_check(pkt[IP], pkt[TCP], self.key)
            if id and id in self.servers.keys():
                with self.lock:
                    self.states[tuple_4] = id & int(16 * '1', 2)
                    self.timeouts[tuple_4] = time.time()
                response = IP(src=self.rip, dst=self.servers[id]) / IP(src=pkt.src, dst=pkt.dst) / TCP(
                    sport=pkt.payload.sport, dport=pkt.payload.dport, seq=pkt.payload.seq, ack=pkt.payload.ack,
                    flags=pkt.payload.flags, window=pkt.payload.window,
                    options=pkt.payload.options) / pkt.payload.payload
            else:
                print("Not valid cookie:", pkt.summary())
                return
        else:
            print("No such connection and SYN or ACK flag isn't set:", pkt.summary())
            return
        # # send response
        # print("SND", response.summary())
        send(response)
        print(len(self.states))
        # print("Request processing time", time.time() - t0)


if __name__ == '__main__':
    signal(SIGINT, signalHandler)
    # configure lb mode
    defense = False
    rate = 'fast'
    if len(sys.argv) > 1 and sys.argv[1][0] == 't':
        defense = True
    if len(sys.argv) > 2:
    	rate = sys.argv[2]
    lb = LoadBalancer(vip='10.0.0.2', rip='192.168.0.2', isAttacked=defense, \
                      filename="results/{}{}.txt".format(rate, "-defense" if defense else ""))
    lb.start()
