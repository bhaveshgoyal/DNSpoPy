import pcap
import dpkt
import dnet

sock = dnet.ip()
pc = pcap.pcap()
print dir(pc)
print pc.name
for timestamp, packet in pc:
#		print timesta'mp
	eth = dpkt.ethernet.Ethernet(packet)
	ip  = eth.data
	udp = ip.data
	dns = dpkt.dns.DNS(udp.data)
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
