#!/usr/bin/env python

import socket
import unittest
import struct
import inspect
import os
import platform

from framework import VppTestRunner
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet import IPerror, TCPerror, UDPerror, ICMPerror
from scapy.layers.l2 import Ether, ARP
from scapy.data import IP_PROTOS
from util import ppp
from memif import MEMIFTestCase, MEMIFApi, MEMIF2
from extra_vpp import ExtraVpp, RemoteClass
from picklable_packet import PicklablePacket

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
		Verify packet capture
		
		:param src_if: Inside interface
		:param dst_if: Outside interface
		:param capture: Captured packets
		"""
		packet_info = None
		#TODO: test && improve ICMP verification
		self.assertTrue(capture)
		for p in capture:
			try:
				self.assertEqual(p[IP].src, self.pg0.remote_ip4)
				self.assertEqual(p[IP].dst,
					self.vpp2.pg1.remote_ip4.get_remote_value())
				self.assertEqual(p[ICMP].id, 69)
				self.assertEqual(p[ICMP].type, 8)
			except:
				self.logger.error(
					ppp("Unexpected or invalid packet: ",p))
	

	def verify_capture_s_m(self, capture):
		"""
		Verify packet capture
		
		:param src_if: Inside interface
		:param dst_if: Outside interface
		:param capture: Captured packets
		"""
		packet_info = None
		#TODO: test && improve ICMP verification
		self.assertTrue(capture)
		for p in capture:
			try:
				self.assertEqual(p[IP].src,
					 self.vpp2.pg1.remote_ip4.get_remote_value())
				self.assertEqual(p[IP].dst, self.pg0.remote_ip4)
				self.assertEqual(p[ICMP].id, 69)
				self.assertEqual(p[ICMP].type, 8)
			except:
				self.logger.error(
					ppp("Unexpected or invalid packet: ",p))


	def create_stream_vpp2(self, count):
		"""
		Create packets to stream
		
		:param src_if: Inside interface
		:param dst_if: Outside interface
		:param src_if_ip: Inside interface ip(4)
		:param dst_if_ip: Outside interface ip(4)
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
				ICMP(id=69, type='echo-request'))
			#info.data = p.copy()
			packets.append(p)
		
		return packets
	
	def create_stream(self, count):
		"""
		Create packets to stream
		
		:param src_if: Inside interface
		:param dst_if: Outside interface
		:param src_if_ip: Inside interface ip(4)
		:param dst_if_ip: Outside interface ip(4)
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
				ICMP(id=69, type='echo-request'))
			#info.data = p.copy()
			packets.append(p)
		
		return packets

	def connect_memif(self):
		""" link establishment """
		self.vpp2.setTestFunctionInfo(self._testMethodName,self._testMethodDoc)
		self.vpp2.setUp()


		memifs_index = [MEMIFApi.dump_memif(self)[0].sw_if_index]	
		self.vapi.sw_interface_add_del_address(
			memifs_index[0], socket.inet_pton(socket.AF_INET, '192.168.1.1'), 24)
		self.vapi.sw_interface_set_flags(memifs_index[0], admin_up_down=1)


		memifs_index.append(MEMIFApi.create_memif(self.vpp2, 15, 'slave',
			 '/tmp/vpp.sock'))
		self.vpp2.logger.info("created memif sw_if_index: %d" % memifs_index[1])
        	
		self.vpp2.vapi.sw_interface_add_del_address(
        		memifs_index[1], socket.inet_pton(socket.AF_INET, '192.168.1.2'), 24)
        	self.vpp2.vapi.sw_interface_set_flags(memifs_index[1], admin_up_down=1)

		#Wait
		self.sleep(4, "waiting for memif connection to establish")
		MEMIFApi.log_memif_config(self)
		MEMIFApi.log_memif_config(self.vpp2)
		
		return memifs_index


	#@unittest.skip("DONE")
	def test_memif_connect(self):
		""" Establish link """

		memifs_index = MEMIFTestCase_m.connect_memif(self)		

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
		
		MEMIFApi.delete_memif(self, memifs_index[0])
		MEMIFApi.delete_memif(self.vpp2, memifs_index[1])		

		
	def add_route(self):	
		print(self.vapi.ppcli('ip route add 169.54.1.0/24 via 192.168.1.2'))
		print(self.vpp2.vapi.ppcli('ip route add 172.16.1.0/24 via 192.168.1.1'))
	
	#@unittest.skip("DONE")
	def test_memif_traffic_02_slave_master(self):	
		""" ICMP packet stream slave -> master """
		memifs_index = MEMIFTestCase_m.connect_memif(self)
		count = 5
		self.add_route()
		print('Vpp1:')
		print(self.vapi.ppcli("show int"))
		print(self.vapi.ppcli("show int address"))
		print('Vpp2:')
		print(self.vpp2.vapi.ppcli("show int"))
		print(self.vpp2.vapi.ppcli("show int address"))
		packets = self.create_stream_vpp2(count)
		self.vpp2.pg1.add_stream_vpp2(packets)
		self.vpp2.pg1.enable_capture()
		self.pg0.enable_capture()
		self.vpp2.pg_start()
		capture = self.pg0.get_capture(expected_count=(count))
		self.vpp2.pg1.assert_nothing_captured()
		self.verify_capture_s_m(capture)
		
		MEMIFApi.delete_memif(self, memifs_index[0])
		MEMIFApi.delete_memif(self.vpp2, memifs_index[1])		


	#@unittest.skip("DONE")
	def test_memif_traffic_01_master_slave(self):
		""" ICMP packet stream master -> slave """
		memifs_index = MEMIFTestCase_m.connect_memif(self)
		
		count = 5
		#self.add_route()
		print('Vpp1:')
		print(self.vapi.ppcli("show int"))
		print(self.vapi.ppcli("show int address"))
		print('Vpp2:')
		print(self.vpp2.vapi.ppcli("show int"))
		print(self.vpp2.vapi.ppcli("show int address"))
		packets = self.create_stream(count)
		self.pg0.add_stream(packets)
		self.sleep(5,"1")
		self.vpp2.pg1.enable_capture()
		self.sleep(5,"2")
		self.pg0.enable_capture()
		self.sleep(5, "3")
		self.pg_start()
		self.sleep(5, "4")
		capture = self.vpp2.pg1.get_capture(expected_count=(count))
		if capture:
			n_cap = []
			for p in capture:
				if isinstance(p, PicklablePacket):
					p = p()
					n_cap.append(p)
			self.verify_capture_m_s(n_cap)
		self.pg0.assert_nothing_captured()
	
		MEMIFApi.delete_memif(self, memifs_index[0])
		MEMIFApi.delete_memif(self.vpp2, memifs_index[1])		

	@unittest.skip("depends on prev")
	def test_memif_ps_m(self):
		""" ICMP packet stream from multiple slaves simultaneously """


	#@unittest.skip("IN PROGRESS")
	def test_reconnect(self):
		""" Break connection then reconnect """
		memifs_index = MEMIFTestCase_m.connect_memif(self)
		
		master = MEMIFApi.dump_memif(self, memifs_index[0])
		slave = MEMIFApi.dump_memif(self.vpp2, memifs_index[1])
		self.assertIsNotNone(master)
		self.assertEqual(master.link_up_down, 1)
		self.assertIsNotNone(slave)
		self.assertEqual(slave.link_up_down, 1)
		"""
		VPP2
		"""		
		#TODO: send packet to be sure

		self.vapi.sw_interface_set_flags(master.sw_if_index, admin_up_down=0)
		self.sleep(4, "waiting for disconection")
		
		master = MEMIFApi.dump_memif(self, memifs_index[0])
		slave = MEMIFApi.dump_memif(self.vpp2, memifs_index[1])
		self.assertEqual(master.admin_up_down, 0)
		self.assertEqual(master.link_up_down, 0)		
		self.assertEqual(slave.link_up_down, 0)		
		
		self.vapi.sw_interface_set_flags(master.sw_if_index, admin_up_down=1)
		self.sleep(4, "waiting for connection")
 		
		master = MEMIFApi.dump_memif(self, memifs_index[0])
		slave = MEMIFApi.dump_memif(self.vpp2, memifs_index[1])
		self.assertEqual(master.admin_up_down, 1)
		self.assertEqual(master.link_up_down, 1)
		self.assertEqual(slave.link_up_down, 1)
		
		
		self.vpp2.vapi.sw_interface_set_flags(slave.sw_if_index, admin_up_down=0)
		self.sleep(4, "waiting for disconection")

		master = MEMIFApi.dump_memif(self, memifs_index[0])
		slave = MEMIFApi.dump_memif(self.vpp2, memifs_index[1])
		self.assertEqual(slave.admin_up_down, 0)
		self.assertEqual(slave.link_up_down, 0)		
		self.assertEqual(master.link_up_down, 0)		
		
		self.vpp2.vapi.sw_interface_set_flags(slave.sw_if_index, admin_up_down=1)
		self.sleep(4, "waiting for connection")

		master = MEMIFApi.dump_memif(self, memifs_index[0])
		slave = MEMIFApi.dump_memif(self.vpp2, memifs_index[1])
 		self.assertEqual(slave.admin_up_down, 1)
		self.assertEqual(slave.link_up_down, 1)
		self.assertEqual(master.link_up_down, 1)
		
		MEMIFApi.delete_memif(self, memifs_index[0])
		MEMIFApi.delete_memif(self.vpp2, memifs_index[1])		

		#TODO: send packet to be sure
		"""	
		self.vapi.sw_interface_add_del_address(
			master.sw_if_index, socket.inet_pton(socket.AF_INET,
				'192.168.1.1'), 24, del_all=1)
		self.sleep(4, "waiting for disconnection")
		
		master = MEMIFApi.dump_memif(self, memifs_index[0])
		slave = MEMIFApi.dump_memif(self.vpp2, memifs_index[1])
		self.assertEqual(master.link_up_down, 0)
		self.assertEqual(slave.link_up_down, 0)

		self.vapi.sw_interface_add_del_address(
			master.sw_if_index, socket.inet_pton(socket.AF_INET,
				'192.168.1.1'), 24)

		self.sleep(4, "waiting for connection")
		
		master = MEMIFApi.dump_memif(self, memifs_index[0])
		slave = MEMIFApi.dump_memif(self.vpp2, memifs_index[1])
		self.assertEqual(master.link_up_down, 1)
		self.assertEqual(slave.link_up_down, 1)
		"""


		"""
		VPP2
		self.vapi.sw_interface_add_del_address(
		slave.sw_if_index, socket.inet_pton(socket.AF_INET,
				'192.168.2.1'), 24, 0, 0)
		self.sleep(2, "waiting for disconnection")
		self.assertEqual(slave.link_up_down, 0)
		self.assertEqual(master.link_up_down, 0)

		self.vapi.sw_interface_add_del_address(
		slave.sw_if_index, socket.inet_pton(socket.AF_INET,
				'192.168.2.1'), 24)

		self.sleep(2, "waiting for connection")
		self.assertEqual(slave.link_up_down, 0)
		self.assertEqual(master.link_up_down, 1)
		"""

		#TODO: send packet to be sure
		#self.vpp2.tearDown()


	@classmethod
	def setUpClass(cls):
		super(MEMIFTestCase_m, cls).setUpClass()		


	@classmethod
	def tearDownClass(cls):
		print('tear down vpp1')
		super(MEMIFTestCase_m, cls).tearDownClass()


if __name__ == '__main__':
	unittest.main(testRunner=VppTestRunner)
