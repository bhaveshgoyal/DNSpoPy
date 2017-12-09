# DNSpoPy
Python based on-path DNS packet injector and passive DNS poisoning detector.

### To run:
```
The program is build over top of scapy library to sniff DNS data. Please ensure that you have the same installed before building the source.
It is recommended to run the program in a python virtual environment, even though it should work perfectly fine otherwise too. The program is compatible with Python v2.x

Setup a virtual environment:
virtualenv venv
source venv/bin/activate

Ensure you have all the pydependencies installed
pip install --upgrade pip
pip install scapy
pip install netifaces

Injection Module: python dnsinject.py -i [interface] -h [hostnames <to be hijacked>] [optional-expression]
Detection Module: python dnsdetect.py -i [interface] -r [trace-file <to be analyzed>] [optional-expression]

```

[expression] should be a valid BPF filter that specifies a subset of DNS traffic to be dumped. If not specified, the modules perform a live capture of entire DNS traffic in promiscuous mode packets.
If any of the other parameters are not specified, the program makes use of system defaults.

The injection module prints every valid DNS request that it captures along with a summary of spoofed response sent to the origin IP. The detection module on the other hand gives a snapshot of any poisoning attempts that it detects using its detection algorithm with the query domain and the duplicated and original responses.


---
**A Brief Note on implementation:**

The program makes use of python builtin function getopt to parse the optional command line arguments given as input by the user.

The arguments are stored and validated using error detection performed from return values provided by calls to the scapy and I/O library. This allows the program to invalidate any objectionable user input.

If the user does not specify any interface, the program opens a session on the default device using netifaces library. After a couple of checks for the valid interface and input files (if given) the program starts capturing until interrupted and registers a callback to a handler definition for every packet it receives.

The packet handler dissects the packet for its type and uses header offsets defined in lib/defs.h to typecast the IP/ARP packets to be processed further.

In dnsinjection module: The program checks if the captured packet is a valid DNS query using the packet header fields and makes use of the same to craft the spoofed packet. The module sets the checksum to None (so that scapy could recalculate the same for the spoofed packet), checks if the domain is in the hostnames file(if specified) and then builds a valid spoofed packet. For crafting the packet, the module switches the source and destination ip and ports inside the header, makes a dns response using specified response address(attacker's local machine address if poison file not specified), sets the header fields such as TTL, Answer count and trasmits the packet over the network. *Note*, the injection module only performs a spoofing for A type query requests.

In dnsdetection  module: The program performs the same checks for the input as performed by injection module and registers a call back to the detection module for the sniff function. The detection algorithm works as follows: The program maintains a dynamic mapping of zero day observed reponse requests and analyzes the incoming responses against the collected data at the same time, adding to the the detection map if the same has not been observed yet. To ensure that mutual exclusion between two entries, the key mappping is built using the query's transaction ID, query name, source port, destination ip:port pairs in a fixed ordering. This reduces the probability of any two non colliding packets to collide to very low. Additionally, to handle the case when a legitimate server might resend the reponse in case the response was malformed, the algorithm only makes an entry when the response packet size is considered to be valid and above the minimum Ethernet and UDP header size. Moreover to avoid detection of duplicating packets the packets are only marked as poisoned if the IP payload of two packets are different.
---
**Note:** It has reported that the BPF filter expression doesn't work with the current pip version of scapy. This is a well known bug as of this date. The same has been resolved in the latest scapy built but hasn't been pushed to pip yet. You could build the same using official scapy source @https://github.com/secdev/scapy

**Testing Environment**

```
Python specifications:
Python 2.7.12
pip 9.0.1

Dependencies: 
scapy - Version: 2.3.3
netifaces - Version: 0.10.6

OS specifications:
-Darwin 17.0.0 x86_64
(macOS High Sierra)

-Linux parallels-vm 4.10.0-28-generic 16.04.2-Ubuntu_x64

```
**Sample Output**

DnsInjection Sample:
```
bagl ❯❯❯  python dnsinject.py -h hostnames
Trying to read cache poisoning data from file hostnames ...
Poison Map: {'bar.examp1e.com.': '10.5.6.7', 'foo.examp1e.com.': '10.6.6.6', 'paypal.com.': '10.6.7.8'}
Sniffing on packets on interface: enp0s5
10.211.55.4 -> 216.146.35.35 : (facebook.com.)
facebook.com.
.
Sent 1 packets.
Sent: IP / UDP / DNS Ans "10.211.55.3" 

10.211.55.4 -> 216.146.35.35 : (twitter.com.)
twitter.com.
.
Sent 1 packets.
Sent: IP / UDP / DNS Ans "10.211.55.3" 

10.211.55.4 -> 216.146.35.35 : (foo.examp1e.com.)
foo.examp1e.com.
Preparing spoofed packet
.
Sent 1 packets.
Sent: IP / UDP / DNS Ans "10.6.6.6" 

---
Queries:

bagl ❯❯❯  dig facebook.com

; <<>> DiG 9.10.3-P4-Ubuntu <<>> facebook.com
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 24161
;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0
;; WARNING: recursion requested but not available

;; QUESTION SECTION:
;facebook.com.			IN	A

;; ANSWER SECTION:
facebook.com.		330	IN	A	10.211.55.3

;; Query time: 82 msec
;; SERVER: 216.146.35.35#53(216.146.35.35)
;; WHEN: Fri Dec 08 18:52:24 EST 2017
;; MSG SIZE  rcvd: 58

bagl ❯❯❯  dig twitter.com

; <<>> DiG 9.10.3-P4-Ubuntu <<>> twitter.com
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 5136
;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0
;; WARNING: recursion requested but not available

;; QUESTION SECTION:
;twitter.com.			IN	A

;; ANSWER SECTION:
twitter.com.		330	IN	A	10.211.55.3

;; Query time: 34 msec
;; SERVER: 216.146.35.35#53(216.146.35.35)
;; WHEN: Fri Dec 08 18:52:34 EST 2017
;; MSG SIZE  rcvd: 56

bagl ❯❯❯  dig foo.examp1e.com

; <<>> DiG 9.10.3-P4-Ubuntu <<>> foo.examp1e.com
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 65275
;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0
;; WARNING: recursion requested but not available

;; QUESTION SECTION:
;foo.examp1e.com.		IN	A

;; ANSWER SECTION:
foo.examp1e.com.	330	IN	A	10.6.6.6

;; Query time: 33 msec
;; SERVER: 216.146.35.35#53(216.146.35.35)
;; WHEN: Fri Dec 08 18:53:07 EST 2017
;; MSG SIZE  rcvd: 64
```
Detection:

```
bagl ❯❯❯  python dnsdetect.py -r test\_cap
Reading from Tracefile: test\_cap

Detecting poisoning attempts on interface: enp0s5
2017-12-08 18:52:24.321407 DNS Poisoning attempt
TXID 0x24161 Request facebook.com.
Answer 1  ['31.13.71.36']
Answer 2 ['10.211.55.3']


2017-12-08 18:52:29.084139 DNS Poisoning attempt
TXID 0x15029 Request paypal.com.
Answer 1  ['10.6.7.8']
Answer 2 ['64.4.250.33', '64.4.250.32']


2017-12-08 18:52:34.994133 DNS Poisoning attempt
TXID 0x5136 Request twitter.com.
Answer 1  ['104.244.42.65', '104.244.42.129']
Answer 2 ['10.211.55.3']


2017-12-08 18:52:39.424911 DNS Poisoning attempt
TXID 0x11301 Request ntp.ubuntu.com.
Answer 1  ['91.189.89.199', '91.189.94.4', '91.189.91.157', '91.189.89.198']
Answer 2 ['10.211.55.3']


2017-12-08 18:52:39.457597 DNS Poisoning attempt
TXID 0x60502 Request ntp.ubuntu.com.
Answer 1  ['10.211.55.3']
Answer 2 ['2001:67c:1560:8003::c7', '2001:67c:1560:8003::c8']


2017-12-08 18:53:00.980225 DNS Poisoning attempt
TXID 0x23211 Request foo.example.com.
Answer 1  []
Answer 2 ['10.211.55.3']


2017-12-08 18:53:08.255217 DNS Poisoning attempt
TXID 0x65275 Request foo.examp1e.com.
Answer 1  []
Answer 2 ['10.6.6.6']

```

