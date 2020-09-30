#!/usr/bin/python

import os
import sys

if os.getuid() !=0:
    print """
ERROR: This script requires root privileges. 
       Use 'sudo' to run it.
"""
    quit()

from scapy.all import *

try:
    ip_dst = sys.argv[1]
except:
    ip_dst = "192.168.1.2"

try:
    count = int(sys.argv[2], base=0)
except:
    count=1
    
print "Sending %d IP packet(s) to %s" % (count, ip_dst)
p = (Ether(dst="00:11:22:33:44:55", src="00:aa:bb:cc:dd:ee")/
     IP(src="10.11.12.13", dst=ip_dst)/
     UDP(sport=7,dport=7)/
     "This is a test")
sendp(p, iface="veth1", count=count) 
