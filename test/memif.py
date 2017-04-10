#!/usr/bin/env python

import socket
import unittest
import struct
import inspect
import sys

from framework import VppTestCase
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet import IPerror, TCPerror, UDPerror, ICMPerror
from scapy.layers.l2 import Ether, ARP
from scapy.data import IP_PROTOS
from util import ppp
from extra_vpp import ExtraVpp, RemoteClass
from vpp_pg_interface import VppPGInterface


class MEMIF2(ExtraVpp):
	

	@classmethod
	def setUpClass(cls):
		super(MEMIF2, cls).setUpClass()
		try:		
			intf = VppPGInterface(cls, 1)
			setattr(cls, intf.name, intf)
			cls.pg_interfaces = [intf]
			cls.create_loopback_interfaces([0])
			cls.loopback0 = cls.lo_interfaces[0]
			cls.loopback0.config_ip4()
			cls.loopback0.admin_up()
			for i in cls.pg_interfaces:
				i.set_ip4('169.54','08')
				i.config_ip4()
				i.configure_ipv4_neighbors()
				i.admin_up()
				i.resolve_arp()
			#cls.icmp_id = 6305			
			
		except Exception:
			super(MEMIF2, cls).tearDownClass()
			raise
		

	def tearDown(self):
		print('memif.py MEMIF2 tear down')
		super(MEMIF2, self).tearDown()
		if not self.vpp_dead:
			self.logger.info(self.vapi.cli("show interfaces address"))
			self.logger.info(self.vapi.cli("show memif"))


	
	

class MEMIFApi(object):
	
	@staticmethod
	def create_memif(vpp, key=0, role='slave', socket='',
		ring_size=0, buffer_size=0, hw_addr='00:00:00:00:00:00'):
		"""
		Create Memif interface
		:param vpp: VPPTestCase instance
		:param key: 64bit integer used to authenticate and match opposite sides
			of the connection
		:param role: role of the interface in the connection (master/slave)
		:param socket: filename of the socket to be used for connection
			establishment
		:returns: sw_if_index
		"""
		role_id = (1 if role == 'slave' else 0)
		reply = vpp.vapi.memif_create(role_id, key, socket, ring_size, buffer_size, hw_addr)
		return reply.sw_if_index	
	

	@staticmethod
	def delete_memif(vpp, sw_if_index):
		vpp.vapi.memif_delete(sw_if_index)


	@staticmethod
	def dump_memif(vpp, sw_if_index=None):
		memifs = vpp.vapi.memif_dump()
		if sw_if_index is None:
			return memifs
		else:
			for memif in memifs:
				if memif.sw_if_index == sw_if_index:
					return memif
		return None

	@staticmethod
	def log_memif_config(vpp):
		dump = vpp.vapi.memif_dump()
		for memif in dump:
			if_name = memif.if_name.rstrip('\0')
			vpp.logger.info('%s: sw_if_index %d mac %s',
				if_name, memif.sw_if_index,
				':'.join([('%0.2x' % ord(i)) for i in memif.hw_addr]))
			vpp.logger.info('%s: key %d socket %s role %s',
				if_name, memif.key, memif.socket_filename.rstrip('\0'),
				'slave' if memif.role else 'master')
			vpp.logger.info('%s: ring_size %d buffer_size %d',
				if_name, memif.ring_size, memif.buffer_size)
			vpp.logger.info('%s: state %s link %s',
				if_name,
				'up' if memif.admin_up_down else 'down',
				'up' if memif.link_up_down else 'down')
	
	
	

class MEMIFTestCase(VppTestCase):
	""" parent class for memif test cases """
	
	@classmethod
	def setUpClass(cls):
		cls.vpp2 = RemoteClass(MEMIF2)
		cls.vpp2.start_remote()
		cls.vpp2.setUpClass()
		super(MEMIFTestCase, cls).setUpClass()
		try:			
			cls.create_pg_interfaces(range(1))
			cls.create_loopback_interfaces([0])
			cls.loopback0 = cls.lo_interfaces[0]
			cls.loopback0.config_ip4()
			cls.loopback0.admin_up()
			for i in cls.pg_interfaces:
				i.config_ip4()
				i.configure_ipv4_neighbors()
				i.admin_up()
				i.resolve_arp()
			#cls.icmp_id = 6305			
			
		except Exception:
			super(MEMIFTestCase, cls).tearDownClass()
			raise


	@staticmethod
	def create_icmp(vpp, src_if, dst_if, ttl=64):
        	"""
        	Create ICMP packet

        	:param vpp: VPPTestCase instance
        	:param in_if: Inside interface
        	:param out_if: Outside interface
        	:param ttl: TTL of the generated packet
        	"""
        	p = (Ether(dst=src_if.local_mac, src=src_if.remote_mac) /
        	     IP(src=src_if.remote_ip4, dst=dst_if.remote_ip4, ttl=ttl) /
        	     ICMP(id=src_if.sw_if_index, type='echo-request'))
        	return p


	@staticmethod
	def create_UDPp(self, src_if, dst_if):
        	"""
        	Create UDP packet

        	:param src_if: Inside interface
        	:param dst_if: Outside interface
        	"""
		p = (Ether(dst=src_if.local_mac, src=src_if.remote_mac) /
			IP(src=src_if.remote_ip4, dst=dst_if.remote_ip4) /
			UDP(sport=1234, dport=5678) /
			Raw(payload))
		return p
	

	@staticmethod
	def clear_memif_config(self):
		""" Clear Memif configuration """
		# VPP 1
		for memif in MEMIFApi.dump_memif(self):
			self.logger.info("Deleting memif sw_if_index: %d" % memif.sw_if_index)
			MEMIFApi.delete_memif(self, memif.sw_if_index)
			MEMIFApi.log_memif_config(self)
	
		# VPP 2
		for memif in MEMIFApi.dump_memif(self.vpp2):
			self.logger.info("Deleting memif sw_if_index: %d" % memif.sw_if_index)
			MEMIFApi.delete_memif(self.vpp2, memif.sw_if_index)
			MEMIFApi.log_memif_config(self.vpp2)


	def setUp(self):
		"""
		Create memory interface
		"""
		super(MEMIFTestCase, self).setUp()
		master_if_index = MEMIFApi.create_memif(self, 15, 'master',
			'/tmp/vpp.sock', 512, 4096, 'aa:bb:cc:11:22:33')
		self.logger.info("Created memif sw_if_index: %d" % master_if_index)
		self.vpp2.set_request_timeout(10)


	def tearDown(self):
		"""
		Delete memory interface
		"""
        	super(MEMIFTestCase, self).tearDown()
		"""
        	if not self.vpp_dead:
        	    self.logger.info(self.vapi.cli("show interfaces address"))
        	    self.logger.info(self.vapi.cli("show memif"))
		self.vpp2.tearDown()
		if not self.vpp_dead and not self.vpp2.vpp_dead.get_remote_value():
			self.clear_memif_config()
		"""

	@classmethod
	def tearDownClass(cls):
		print('memif.py vpp1 tear down class')
		cls.vpp2.tearDownClass()
		cls.vpp2.quit_remote()
		cls.vpp2.join()
        	super(MEMIFTestCase, cls).tearDownClass()




