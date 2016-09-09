#!/usr/bin/env python

# Manipulate sys.path to allow tests be run inside the build environment.
from __future__ import print_function
import os, sys, glob
scriptdir = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.dirname(glob.glob(scriptdir+'/../../../build-root/install*/vpp-api/lib64/vpp_api.so')[0]))
sys.path.append(os.path.dirname(glob.glob(scriptdir+'/../../../build-root/install*/vlib-api/vlibmemory/memclnt.py')[0]))
sys.path.append(os.path.dirname(glob.glob(scriptdir+'/../../../build-root/install*/vpp/vpp-api/vpe.py')[0]))
sys.path.append(glob.glob(scriptdir+'/../../../build-root/install*/plugins/vpp_papi_plugins')[0])
sys.path.append(glob.glob(scriptdir+'/../../../vpp-api/python/vpp_papi')[0])
sys.path.append('/vpp/nat64')
import unittest, sys, time, threading, struct, logging, Queue
import vpp_papi
from ipaddress import *
import glob, subprocess
import snat
from scapy.all import *

from resources.libraries.python.PacketVerifier import RxQueue, TxQueue

inside_interface = 'tap0'
outside_interface = 'tap1'
inside_vpp_mac = '\aa\bb\cc\dd\ee\00'
outside_vpp_mac = '\aa\bb\cc\dd\ee\01'

inside_host_ip = u'10.0.0.2'
outside_host_ip = u'130.67.0.2'

inside_vpp_ip = u'10.0.0.1'
outside_vpp_ip = u'130.67.0.1'

'''
#
# Sniffer
#
def threaded_sniff_target(q):
    sniff(count=0, filter = "ip", prn = lambda x : q.put(x))

def threaded_sniff():
    q = Queue.Queue()
    sniffer = threading.Thread(target = threaded_sniff_target, args = (q,))
    sniffer.daemon = True
    sniffer.start()
    return q

#
# Deal with VPP events
#
papi_event = threading.Event()
def papi_event_handler(result):
    print('Unknown message id:', result.vl_msg_id)


# Not used
def get_interface_info():
    for i in vpp_papi.sw_interface_dump(0, ''):
        print('Interface:', i.sw_if_index)
        if i.l2_address_length > 0:
            print('L2 address:', i.l2_address.decode(), i)

            #program = t.program.decode().rstrip('\x00')

    #self.assertEqual(r.retval, 0)
    #print('R:', r)

# Not used
def packet_cmp(inpkt, outpkt):
    print(inpkt.summary())
    print(outpkt.summary())

def print_sniff(q):
    while True:
        try:
            pkt = q.get(timeout = 1)
        except Queue.Empty:
            break
        print('Sniff queue:', pkt.summary())
'''

class TestPAPI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        #
        # Start main VPP process
        #
        '''
        cls.vpp_bin = glob.glob(scriptdir+'/../../../build-root/install-vpp*-native/vpp/bin/vpp')[0]
        print("VPP BIN:", cls.vpp_bin)
        cls.vpp = subprocess.Popen(["sudo", cls.vpp_bin, "unix", "{ nodaemon }"],
                                   stderr=subprocess.PIPE)
        #cls.vpp = subprocess.Popen(["sudo", cls.vpp_bin, "unix", "{ nodaemon }",
        #                            "api-segment", "{uid otroan gid otroan}"],
        #                           stderr=subprocess.PIPE)
        print('Started VPP')
        # For some reason unless we let VPP start up the API cannot connect.
        time.sleep(0.3)
        '''
        print("Connecting API")
        r = vpp_papi.connect("test_papi")
        print("R:", r)
        if r:
            print("Can't connect to VPP")
            ###cls.vpp.terminate()
            sys.exit(-1)


    @classmethod
    def tearDownClass(cls):
        r = vpp_papi.disconnect()
        print('Terminating VPP...')
        #print(cls.vpp.terminate())


    def setUp(self):
        #
        # Configure VPP
        #
        r = vpp_papi.tap_connect(0, inside_interface, inside_vpp_mac, 0, 0)
        print('R:', r)
        self.assertEqual(r.retval, 0)

        ifindex_in = r.sw_if_index
        r = vpp_papi.tap_connect(0, outside_interface, outside_vpp_mac, 0, 0)
        self.assertEqual(r.retval, 0)
        ifindex_out = r.sw_if_index
        print('R:', r)

        os.system('ip addr add ' + inside_host_ip + '/24 dev ' + inside_interface)
        os.system('ip addr add ' + outside_host_ip + '/24 dev ' + outside_interface)

        r = vpp_papi.sw_interface_set_flags(ifindex_in, 1, 1, 0)
        self.assertEqual(r.retval, 0)
        print('R:', r)

        r = vpp_papi.sw_interface_set_flags(ifindex_out, 1, 1, 0)
        self.assertEqual(r.retval, 0)
        print('R:', r)

        address = ip_address(inside_vpp_ip).packed
        r = vpp_papi.sw_interface_add_del_address(ifindex_in, 1, 0,
                                                  0, 24, address)
        self.assertEqual(r.retval, 0)
        print('R:', r)

        address = ip_address(outside_vpp_ip).packed
        r = vpp_papi.sw_interface_add_del_address(ifindex_out, 1, 0,
                                                  0, 24, address)
        print('R:', r)
        self.assertEqual(r.retval, 0)

        address = ip_address(u'0.0.0.0').packed
        next_hop = ip_address(outside_host_ip).packed
        r = vpp_papi.ip_add_del_route(ifindex_out, 0, 0, 5, 0, 0, 1, 1, 0, 0,
                                      0, 0, 0, 0, 0, 0, address, next_hop)
        print('R:', r)
        self.assertEqual(r.retval, 10) # Why 10?

        address = ip_address(outside_vpp_ip).packed
        r = snat.snat_add_address_range(1, address, address)
        self.assertEqual(r.retval, 0)
        print('R:', r)

        r = snat.snat_interface_add_del_feature(1, 1, ifindex_in)
        self.assertEqual(r.retval, 0)
        print('R:', r)

        r = snat.snat_interface_add_del_feature(1, 0, ifindex_out)
        self.assertEqual(r.retval, 0)
        print('R:', r)

        #self.q = threaded_sniff()
        #time.sleep(1)

    def tearDown(self):
        None
    #
    # The tests themselves
    #

    #
    # Basic request / reply
    #
    def test_tcp_session(self):
        inside_rxq = RxQueue('tap0')
        inside_txq = TxQueue('tap0')
        outside_rxq = RxQueue('tap1')
        outside_txq = TxQueue('tap1')

        in2out_pkt = Ether(dst='00:00:00:00:00:00')/IP(src='10.0.0.2', dst='1.1.1.1')/TCP(dport=80)
        inside_txq.send(in2out_pkt)

        recv_pkt = outside_rxq.recv(2)

        out2in_pkt = Ether(dst='00:00:00:00:00:00')/IP(src='1.1.1.1', dst='130.67.0.1')/TCP(sport=80, dport=recv_pkt.sport)
        outside_txq.send(out2in_pkt)

        recv_pkt2 = inside_rxq.recv(2)
        recv_pkt2 = inside_rxq.recv(2)
        recv_pkt2 = inside_rxq.recv(2)
        recv_pkt2 = inside_rxq.recv(2)

'''
        while True:
            try:
                recv_pkt = self.q_inside.get(timeout = 1)
            except Queue.Empty:
                break

            print('Outside In:', out2in_pkt.summary())
            print('Outside In:', recv_pkt.summary())
'''
'''

        for i in range(10,20):
            send_pkt = Ether(dst='00:00:00:00:00:00')/IP(src='10.0.0.10', dst='1.1.1.1')/TCP(dport=i)
            sendp(send_pkt,iface='tap0')
            recv_pkt = self.q.get(timeout = 1)
            packet_cmp(send_pkt, recv_pkt)
            time.sleep(1)



        for src in ip_network(u'10.0.0.0/29'):
            send_pkt = Ether(dst='00:00:00:00:00:00')/IP(src=str(src), dst='1.1.1.1')/TCP(dport=i)
            sendp(send_pkt,iface='tap0')
            recv_pkt = self.q.get(timeout = 1)
            packet_cmp(send_pkt, recv_pkt)
            time.sleep(1)
'''

if __name__ == '__main__':
    unittest.main()
