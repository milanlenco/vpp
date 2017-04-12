#!/usr/bin/env python

import socket
import unittest
import struct
import inspect
import os
import platform
import sys

from framework import VppTestRunner
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet import IPerror, TCPerror, UDPerror, ICMPerror
from scapy.layers.l2 import Ether, ARP
from scapy.data import IP_PROTOS
from util import ppp
from memif import MEMIFTestCase, MEMIFApi, MEMIF2, MEMIF3
from extra_vpp import ExtraVpp, RemoteClass, PicklablePacket

#@unittest.skip("DONE")
class MEMIFTestCase_s(MEMIFTestCase):
    """ Single MEMIF instance tests

    testing basic memif creating and deleting
    """
    def test_memif_create(self):
        """ Create memif

        memif created in setUp() method in MEMIFTestCase class (memif.py)
        check if memifs list is not empty
        """
        self.assertTrue(MEMIFApi.dump_memif(self))

    def test_memif_delete(self):
        """ Delete memif

        clearing memif instance(s)
        check if memifs list is empty
        """
        MEMIFTestCase_s.clear_memif_config(self)
        self.assertFalse(MEMIFApi.dump_memif(self))

    def test_memif_admin_up_down(self):
        """ Admin up/down """
        memifs = MEMIFApi.dump_memif(self)
        self.assertTrue(memifs)
        if memifs:
            master_if_index = memifs[0].sw_if_index
            #admin up
            self.vapi.sw_interface_set_flags(master_if_index, admin_up_down=1)
            self.assertEqual(MEMIFApi.dump_memif(self,
                master_if_index).admin_up_down,1)
            #admin down
            self.vapi.sw_interface_set_flags(master_if_index, admin_up_down=0)
            self.assertEqual(MEMIFApi.dump_memif(self,
                master_if_index).admin_up_down,0)

    def tearDown(self):
        for memif in MEMIFApi.dump_memif(self):
            MEMIFApi.delete_memif(self, memif.sw_if_index)
        super(MEMIFTestCase_s, self).tearDown()

#@unittest.skip("asd")
class MEMIFTestCase_m(MEMIFTestCase):
    """ MEMIF tests

    testing memif:
        link establishment
        packet stream
    """

    def verify_capture_m_s(self, capture):
        """
        Verify ICMP packet capture vpp1(master)->vpp2(slave)

        :param capture: Captured packets
        """
        self.assertTrue(capture)
        for p in capture:
            try:
                self.assertEqual(p[IP].src, self.pg0.remote_ip4)
                self.assertEqual(p[IP].dst,
                    self.vpp2.pg1.remote_ip4.get_remote_value())
                self.assertEqual(p[ICMP].id, 1)
                self.assertEqual(p[ICMP].type, 8)
            except:
                self.logger.error(
                    ppp("Unexpected or invalid packet: ",p))


    def verify_capture_s_m(self, capture):
        """
        Verify ICMP packet capture vpp2(slave)->vpp1(master)

        :param capture: Captured packets
        """
        self.assertTrue(capture)
        for p in capture:
            try:
                self.assertEqual(p[IP].src,
                     self.vpp2.pg1.remote_ip4.get_remote_value())
                self.assertEqual(p[IP].dst, self.pg0.remote_ip4)
                self.assertEqual(p[ICMP].id, 2)
                self.assertEqual(p[ICMP].type, 8)
            except:
                self.logger.error(
                    ppp("Unexpected or invalid packet: ", p))

    def verify_capture_m(self, capture, counts):
        """
        Verify ICMP packet capture vpp2(slave)->vpp1(master) && vpp3(slave)->vpp1(master)

        :param capture: Captured packets
        :param counts: List containing number of packets sent
        """
        self.assertTrue(capture)
        c2=c3=0
        count = sum(counts)
        for p in capture:
            try:
                if p[ICMP].id == 2:
                    self.assertEqual(p[IP].src,
                        self.vpp2.pg1.remote_ip4.get_remote_value())
                    self.assertEqual(p[IP].dst, self.pg0.remote_ip4)
                    self.assertEqual(p[ICMP].type, 8)
                    c2 += 1
                elif p[ICMP].id == 3:
                    self.assertEqual(p[IP].src,
                        self.vpp3.pg1.remote_ip4.get_remote_value())
                    self.assertEqual(p[IP].dst, self.pg0.remote_ip4)
                    self.assertEqual(p[ICMP].type, 8)
                    c3 += 1
                else:
                    self.logger.error(
                        ppp("Unexpected or invalid packet: ", p))
                    self.fail("Unexpected or invalid packet")
            except:
                self.logger.error(
                    ppp("Unexpected or invalid packet: ", p))

        if c2 + c3 == count:
            self.logger.error(
                ppp("Unexpected or invalid packet: ", p))
            self.fail("Unexpected or invalid packet")


    def create_stream_vpp2(self, count):
        """
        Create packets to stream vpp2->vpp1

        :param count: Number of packets to be created
        """
        packets = []
        for i in range(count):
            #info = self.create_packet_info(1, 2)
            #payload = self.info_to_payload(info)
            #p = self.create_icmp(self, src_if, dst_if)
            p = (Ether(dst=self.vpp2.pg1.local_mac.get_remote_value(),
                 src=self.vpp2.pg1.remote_mac.get_remote_value()) /
                IP(src=self.vpp2.pg1.remote_ip4.get_remote_value(),
                 dst=self.pg0.remote_ip4,
                ttl=64) /
                ICMP(id=2, type='echo-request'))
            #info.data = p.copy()
            packets.append(p)

        return packets

    def create_stream(self, count):
        """
        Create packets to stream vpp1->vpp2

        :param count: Number of packets to be created
        """
        packets = []
        for i in range(count):
            #info = self.create_packet_info(1, 2)
            #payload = self.info_to_payload(info)
            #p = self.create_icmp(self, src_if, dst_if)
            p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
                IP(src=self.pg0.remote_ip4,
                dst=self.vpp2.pg1.remote_ip4.get_remote_value(), ttl=64) /
                ICMP(id=1, type='echo-request'))
            #info.data = p.copy()
            packets.append(p)

        return packets

    def create_stream_vpp3(self, count):
        """
        Create packets to stream vpp3->vpp1

        :param count: Number of packets to be created
        """
        packets = []
        for i in range(count):
            p = (Ether(dst=self.vpp3.pg1.local_mac.get_remote_value(),
                src=self.vpp3.pg1.remote_mac.get_remote_value()) /
                IP(src=self.vpp3.pg1.remote_ip4.get_remote_value(),
                dst=self.pg0.remote_ip4, ttl=64) /
                ICMP(id=3, type='echo-request'))
            packets.append(p)
        return packets

    def start_pg(self, counts):
        """
        Set up and start packet generator
        sending packets from vpp2(slave) and vpp3(slave) to vpp1(master)

        :param counts: List containing number of packets to be created
        """
        self.pg0.enable_capture()
        for count in counts:
            packets2 = self.create_stream_vpp2(count)
            packets3 = self.create_stream_vpp3(count)
            self.vpp2.pg1.add_stream(packets2)
            self.vpp3.pg1.add_stream(packets3)
            self.vpp2.pg1.enable_capture()
            self.vpp3.pg1.enable_capture()
            self.vpp2.pg_start()
            self.vpp3.pg_start()

    def connect_memif(self):
        """ link establishment
        connects two memifs vpp1(master)<->vpp2(slave)
        """

        memifs_index = [MEMIFApi.dump_memif(self)[0].sw_if_index]
        self.vapi.sw_interface_add_del_address(
            memifs_index[0], socket.inet_pton(socket.AF_INET, '192.168.1.1'), 24)
        self.vapi.sw_interface_set_flags(memifs_index[0], admin_up_down=1)


        memifs_index.append(MEMIFApi.create_memif(self.vpp2, 15, 'slave',
             '/tmp/vpp.sock', 512, 4096, 'aa:bb:cc:22:33:44'))
        self.vpp2.logger.info("created memif sw_if_index: %d" % memifs_index[1])

        self.vpp2.vapi.sw_interface_add_del_address(
                memifs_index[1], socket.inet_pton(socket.AF_INET, '192.168.1.2'), 24)
        self.vpp2.vapi.sw_interface_set_flags(memifs_index[1], admin_up_down=1)

        #Wait
        self.sleep(4, "waiting for memif connection to establish")
        MEMIFApi.log_memif_config(self)
        MEMIFApi.log_memif_config(self.vpp2)

        return memifs_index

    def connect_memif_3ifs(self):
        """ link establishment

        (memif0)vpp1(master)<->(meif0)vpp2(slave)
        (memif1)vpp1(master)<->(meif0)vpp3(slave)

        returns: memifs_index
                0: vpp1 memif0 (master)
                1: vpp2 memif0 (slave)
                2: vpp1 memif1 (master)
                3: vpp3 memif0 (slave)
        """
        #vpp1 memif0
        memifs_index = [MEMIFApi.dump_memif(self)[0].sw_if_index]
        self.vapi.sw_interface_add_del_address(
            memifs_index[0], socket.inet_pton(socket.AF_INET, '192.168.1.1'), 24)
        self.vapi.sw_interface_set_flags(memifs_index[0], admin_up_down=1)

        #vpp2 memif0
        memifs_index.append(MEMIFApi.create_memif(self.vpp2, 15, 'slave',
             '/tmp/vpp.sock', 512, 4096, 'aa:bb:cc:22:33:44'))
        self.vpp2.logger.info("created memif sw_if_index: %d" % memifs_index[1])

        self.vpp2.vapi.sw_interface_add_del_address(
                memifs_index[1], socket.inet_pton(socket.AF_INET, '192.168.1.2'), 24)
        self.vpp2.vapi.sw_interface_set_flags(memifs_index[1], admin_up_down=1)

        #Wait for link
        self.sleep(4, "waiting for memif connection to establish")
        MEMIFApi.log_memif_config(self)
        MEMIFApi.log_memif_config(self.vpp2)

        #vpp1 memif1
        memifs_index.append(MEMIFApi.create_memif(self, 16, 'master',
             '/tmp/vpp.sock', 512, 4096, 'aa:bb:cc:33:44:55'))
        self.logger.info("created memif sw_if_index: %d" % memifs_index[2])

        self.vapi.sw_interface_add_del_address(
                memifs_index[2], socket.inet_pton(socket.AF_INET, '192.168.2.1'), 24)
        self.vapi.sw_interface_set_flags(memifs_index[2], admin_up_down=1)

        #vpp3 memif0
        memifs_index.append(MEMIFApi.create_memif(self.vpp3, 16, 'slave',
             '/tmp/vpp.sock', 512, 4096, 'aa:bb:cc:44:55:66'))
        self.vpp3.logger.info("created memif sw_if_index: %d" % memifs_index[3])

        self.vpp3.vapi.sw_interface_add_del_address(
                memifs_index[3], socket.inet_pton(socket.AF_INET, '192.168.2.2'), 24)
        self.vpp3.vapi.sw_interface_set_flags(memifs_index[3], admin_up_down=1)

        #Wait for link
        self.sleep(4, "waiting for memif connection to establish")
        MEMIFApi.log_memif_config(self)
        MEMIFApi.log_memif_config(self.vpp3)

        return memifs_index


    def add_route(self):
        """ add routing for vpp1<->vpp2 setup """
        self.vapi.cli('ip route add 169.54.1.0/24 via 192.168.1.2')
        self.vpp2.vapi.cli('ip route add 172.16.1.0/24 via 192.168.1.1')
        #self.vapi.ip_add_del_route('169.54.1.0', 24, '192.168.1.2')
        #self.vpp2.vapi.ip_add_del_route('172.16.1.0', 24, '192.168.1.1')

    def add_route_3ifs(self):
        """ add routing for vpp1<->vpp2 vpp1<->vpp3 setup """
        self.vapi.cli('ip route add 169.54.1.0/24 via 192.168.1.2')
        self.vapi.cli('ip route add 169.55.1.0/24 via 192.168.2.2')
        #self.vapi.ip_add_del_route('169.54.1.0', 24, '192.168.1.2')
        #self.vapi.ip_add_del_route('169.55.1.0', 24, '192.168.2.2')
        self.vpp2.vapi.cli('ip route add 172.16.1.0/24 via 192.168.1.1')
        self.vpp3.vapi.cli('ip route add 172.16.1.0/24 via 192.168.2.1')
        #self.vpp2.vapi.ip_add_del_route('172.16.1.0', 24, '192.168.1.1')
        #self.vpp3.vapi.ip_add_del_route('172.16.1.0', 24, '192.168.2.1')

    #@unittest.skip("DONE")
    def test_memif_connect(self):
        """ Establish link

        assert link up
        ping (memif0)vpp2

        """

        memifs_index = self.connect_memif()

        # Test VPP 1
        master = MEMIFApi.dump_memif(self, memifs_index[0])
        self.assertIsNotNone(master)
        self.assertEqual(master.admin_up_down, 1)
        self.assertEqual(master.link_up_down, 1)

        # Test VPP 2
        slave = MEMIFApi.dump_memif(self.vpp2, memifs_index[1])
        self.assertIsNotNone(slave)
        self.assertEqual(slave.admin_up_down, 1)
        self.assertEqual(slave.link_up_down, 1)

        retval = self.vapi.cli("ping 192.168.1.2").split('\n')[-2].split(' ')
        self.assertNotEqual(int(retval[1]), 0)
        self.assertTrue((int(retval[1]) == int(retval[3]))
            or (int(retval[1]) == (int(retval[3]) + 1)))

        MEMIFApi.delete_memif(self, memifs_index[0])
        MEMIFApi.delete_memif(self.vpp2, memifs_index[1])

    #@unittest.skip("DONE")
    def test_memif_traffic_01_slave_master(self):
        """ ICMP packet stream slave -> master """
        memifs_index = self.connect_memif()
        self.vpp2.vapi.cli("ping 192.168.1.1")
        count = 5
        self.add_route()
        packets = self.create_stream_vpp2(count)
        self.vpp2.pg1.add_stream(packets)
        self.vpp2.pg1.enable_capture()
        self.pg0.enable_capture()
        self.vpp2.pg_start()
        capture = self.pg0.get_capture(expected_count=(count))
        self.vpp2.pg1.assert_nothing_captured()
        self.verify_capture_s_m(capture)

    #@unittest.skip("DONE")
    def test_memif_traffic_02_master_slave(self):
        """ ICMP packet stream master -> slave """
        memifs_index = self.connect_memif()
        self.vpp2.vapi.cli("ping 192.168.1.1")
        count = 5
        self.add_route()
        packets = self.create_stream(count)
        self.pg0.add_stream(packets)
        self.vpp2.pg1.enable_capture()
        self.pg0.enable_capture()
        self.pg_start()
        capture = self.vpp2.pg1.get_capture(expected_count=(count))
        self.assertTrue(capture)
        self.verify_capture_m_s(capture)
        self.pg0.assert_nothing_captured()

    #@unittest.skip("depends on prev")
    def test_memif_ps_m(self):
        """ ICMP packet stream from multiple slaves """
        memifs_index = self.connect_memif_3ifs()
        self.vpp3.set_request_timeout(10)
        self.vpp2.set_request_tiomeout(10)
        self.vpp2.vapi.cli('ping 192.168.1.1')
        self.vpp3.vapi.cli('ping 192.168.2.1')

        self.add_route_3ifs()

        self.vpp3.set_request_timeout(2)
        self.vpp2.set_request_tiomeout(2)

        count1 = 3
        count2 = 2
        self.start_pg([count1, count2])
        capture = self.pg0.get_capture(expected_count=count1*2 + count2*2)
        self.vpp2.pg1.assert_nothing_captured()
        self.vpp3.pg1.assert_nothing_captured()

        self.verify_capture_m(capture, [count1, count2])


    def assert_link_up_down(self, memifs, link_up_down=1):
        """ check if link is up/down and verify with ping """
        for memif in memifs:
            self.assertIsNotNone(memif)
            self.assertEqual(memif.link_up_down, link_up_down)
        
        if link_up_down:
            retval = self.vapi.cli("ping 192.168.1.2").split('\n')[-2].split(' ')
            self.assertNotEqual(int(retval[1]), 0)
            self.assertTrue((int(retval[1]) == int(retval[3]))
                or (int(retval[1]) == (int(retval[3]) + 1)))
        else:
            retval = self.vapi.cli("ping 192.168.1.2").split('\n')[-2].split(' ')
            self.assertNotEqual(int(retval[1]), 0)
            self.assertEqual(int(retval[3]), 0)



    #@unittest.skip("DONE")
    def test_reconnect_01(self):
        """ Break connection then reconnect (Admin up/down)"""
        memifs_index = self.connect_memif()
        self.vpp2.set_request_timeout(10)
        master = MEMIFApi.dump_memif(self, memifs_index[0])
        slave = MEMIFApi.dump_memif(self.vpp2, memifs_index[1])

        self.assert_link_up_down([master, slave])

        self.vapi.sw_interface_set_flags(memifs_index[0], admin_up_down=0)
        self.sleep(4, "waiting for disconection")
        master = MEMIFApi.dump_memif(self, memifs_index[0])
        slave = MEMIFApi.dump_memif(self.vpp2, memifs_index[1])
        self.assert_link_up_down([master, slave], 0)

        self.vapi.sw_interface_set_flags(memifs_index[0], admin_up_down=1)
        self.sleep(4, "waiting for connection")
 
        master = MEMIFApi.dump_memif(self, memifs_index[0])
        slave = MEMIFApi.dump_memif(self.vpp2, memifs_index[1])

        self.assert_link_up_down([master, slave])
        self.vpp2.vapi.sw_interface_set_flags(memifs_index[1], admin_up_down=0)
        self.sleep(4, "waiting for disconection")

        master = MEMIFApi.dump_memif(self, memifs_index[0])
        slave = MEMIFApi.dump_memif(self.vpp2, memifs_index[1])
        self.assert_link_up_down([master, slave], 0)
        self.vpp2.vapi.sw_interface_set_flags(slave.sw_if_index, admin_up_down=1)
        self.sleep(4, "waiting for connection")

        master = MEMIFApi.dump_memif(self, memifs_index[0])
        slave = MEMIFApi.dump_memif(self.vpp2, memifs_index[1])

        self.assert_link_up_down([master, slave])

    #@unittest.skip("DONE")
    def test_reconnect_02(self):
        """ Break connection then reconnect (create/delete memif)"""
        self.vpp2.setTestFunctionInfo(self._testMethodName,self._testMethodDoc)

        memifs_index = self.connect_memif()
        master = MEMIFApi.dump_memif(self, memifs_index[0])
        slave = MEMIFApi.dump_memif(self.vpp2, memifs_index[1])
        self.assertEqual(slave.link_up_down, 1)
        self.assertEqual(master.link_up_down, 1)

        retval = self.vapi.cli("ping 192.168.1.2").split('\n')[-2].split(' ')
        self.assertNotEqual(int(retval[1]), 0)
        self.assertTrue((int(retval[1]) == int(retval[3]))
            or (int(retval[1]) == (int(retval[3]) + 1)))


        MEMIFApi.delete_memif(self.vpp2, memifs_index[1])
        master = MEMIFApi.dump_memif(self, memifs_index[0])
        self.assertEqual(master.link_up_down, 0)
        retval = self.vapi.cli("ping 192.168.1.2").split('\n')[-2].split(' ')
        self.assertNotEqual(int(retval[1]), 0)
        self.assertEqual(int(retval[3]), 0)
        memifs_index[1] = MEMIFApi.create_memif(self.vpp2, 15, 'slave',
             '/tmp/vpp.sock', 512, 4096, 'aa:bb:cc:22:33:44')
        self.vpp2.logger.info("created memif sw_if_index: %d" % memifs_index[1])

        self.vpp2.vapi.sw_interface_add_del_address(
                memifs_index[1], socket.inet_pton(socket.AF_INET, '192.168.1.2'), 24)
        self.vpp2.vapi.sw_interface_set_flags(memifs_index[1], admin_up_down=1)
        self.sleep(4, "Wait for memif connection")
        
        master = MEMIFApi.dump_memif(self, memifs_index[0])
        slave = MEMIFApi.dump_memif(self.vpp2, memifs_index[1])
        self.assertEqual(slave.link_up_down, 1)
        self.assertEqual(master.link_up_down, 1)
        
        retval = self.vapi.cli("ping 192.168.1.2").split('\n')[-2].split(' ')
        self.assertNotEqual(int(retval[1]), 0)
        self.assertTrue((int(retval[1]) == int(retval[3]))
            or (int(retval[1]) == (int(retval[3]) + 1)))

        MEMIFApi.delete_memif(self, memifs_index[0])

        slave = MEMIFApi.dump_memif(self.vpp2, memifs_index[1])
        self.assertEqual(slave.link_up_down, 0)
        retval = self.vpp2.vapi.cli("ping 192.168.1.1").split('\n')[-2].split(' ')
        self.assertNotEqual(int(retval[1]), 0)
        self.assertEqual(int(retval[3]), 0)

        memifs_index[0] = MEMIFApi.create_memif(self, 15, 'master',
             '/tmp/vpp.sock', 512, 4096, 'aa:bb:cc:11:22:33')
        self.logger.info("created memif sw_if_index: %d" % memifs_index[0])

        self.vapi.sw_interface_add_del_address(
                memifs_index[0], socket.inet_pton(socket.AF_INET, '192.168.1.1'), 24)
        self.vapi.sw_interface_set_flags(memifs_index[0], admin_up_down=1)
        self.sleep(4, "Wait for memif connection")

        master = MEMIFApi.dump_memif(self, memifs_index[0])
        slave = MEMIFApi.dump_memif(self.vpp2, memifs_index[1])
        self.assertEqual(slave.link_up_down, 1)
        self.assertEqual(master.link_up_down, 1)

        retval = self.vpp2.vapi.cli("ping 192.168.1.1").split('\n')[-2].split(' ')
        self.assertNotEqual(int(retval[1]), 0)
        self.assertTrue((int(retval[1]) == int(retval[3]))
            or (int(retval[1]) == (int(retval[3]) + 1)))



    def setUp(self):
        self.vpp2.setUp()
        super(MEMIFTestCase_m, self).setUp()

    @classmethod
    def setUpClass(cls):
        super(MEMIFTestCase_m, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(MEMIFTestCase_m, cls).tearDownClass()

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)

