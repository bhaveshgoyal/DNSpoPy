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
		if pkt.haslayer(DNSRR) and len(pkt[Ether]) > 60 and len(pkt[UDP]) > 8:
			key = str(pkt[DNS].id) + str(pkt[DNS].qd.qname) + str(pkt[IP].sport) + ">" + str(pkt[IP].dst) + ":" + str(pkt[IP].dport)
			if key in detection_map.keys() and str(pkt[IP].payload is not detection_map[key][0]):
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
				if len(detection_map[key]) > 2:
					print detection_map[key][2:]
				else:
					print detection_map[key][1]
				print "\n"
				
			else:
				detection_map[key] = [str(pkt[IP].payload), "Non A type Response"]
				for i in range(pkt[DNS].ancount):
                			dnsrr = pkt[DNS].an[i]
					detection_map[key].append(str(dnsrr.rdata))
		
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
	fexp = 'port 53'
	if len(exp) > 0:
		fexp += ' and ' + ' '.join(exp)
	print "Detecting poisoning attempts on interface: " + str(interface)
#	try:
	if pcap_specified:
		sniff(offline= trace_file, filter = fexp, prn = detect_poison, store = 0)
	else:
		sniff(iface = str(interface), filter = fexp, prn = detect_poison, store = 0)
#	except:
#		print "DNSpoPy: Invalid arguments to sniffer module"
#		return

if __name__ == "__main__":
	main()

