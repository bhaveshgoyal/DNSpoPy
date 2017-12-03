#import pcap
#import dpkt
#import dnet
from collections import defaultdict
from scapy.all import *
from scapy.all import send as ssend
import netifaces
import getopt
import datetime

conf.sniff_promisc=True
pcap_specified = False
detection_map = defaultdict(list)

def detect_poison(pkt):
	global pcap_specified
	if IP in pkt:
		ip_src = pkt[IP].src
		ip_dst = pkt[IP].dst
		if pkt.haslayer(DNSRR):
			if (str(pkt[DNS].id) + str(pkt[DNS].qd.qname) in detection_map.keys()):
				date = datetime.datetime.fromtimestamp(pkt.time)
				print str(date) + " DNS Poisoning attempt"
				print "TXID 0x" + str(pkt[DNS].id) + " Request " + str(pkt[DNS].qd.qname)
				print "Answer 1 ",
				list_a1 = []
				for i in range(pkt[DNS].ancount):
                			dnsrr = pkt[DNS].an[i]
					list_a1.append(dnsrr.rdata)
				print list_a1
				print "Answer 2",
				if len(detection_map[str(pkt[DNS].id) + str(pkt[DNS].qd.qname)]) > 1:
					print detection_map[str(pkt[DNS].id) + str(pkt[DNS].qd.qname)][1:]
				else:
					print detection_map[str(pkt[DNS].id) + str(pkt[DNS].qd.qname)]
				print "\n"
				
			else:
				detection_map[str(pkt[DNS].id) + str(pkt[DNS].qd.qname)] = ["Non A type Response"]
				for i in range(pkt[DNS].ancount):
                			dnsrr = pkt[DNS].an[i]
					detection_map[str(pkt[DNS].id) + str(pkt[DNS].qd.qname)].append(str(dnsrr.rdata))
		
def main():
	global pcap_specified
	interface = netifaces.gateways()['default'][netifaces.AF_INET][1]
	try:
		opt, exp = getopt.getopt(sys.argv[1:], "i:r:", ["interface", "tracefile"])
	
	except getopt.GetoptError as err:
		print "DNSpoPy: Usage Error:",
		print str(err)  # will print something like "option -a not recognized"
		sys.exit(2)
	
	for o, a in opt:
		if o in ("-i", "--interface"):
			interface = a
			print "interface: " + a
		elif o in ("-r", "--tracefile"):
			pcap_specified = True
			print "Reading from Tracefile: " + a + "\n"
			trace_file = a
		else:
			assert False, "Option not recognized"
	if pcap_specified:
		sniff(offline=trace_file, filter = "port 53", prn = detect_poison, store = 0)
	else:
		sniff(iface = interface, filter = "port 53", prn = detect_poison, store = 0)
	

if __name__ == "__main__":
	main()

