#!/usr/bin/env python

from scapy.layers.l2 import Ether

class PicklablePacket:
	def __init__(self, p):
		self.bytes = bytes(p)
		self.time = p.time

	def __call__(self):
		p = Ether(self.bytes)
		p.time = self.time
		return p
