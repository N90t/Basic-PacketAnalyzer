
# Name : NetworkPacket-Source.Destiniation-Analyzer
# Author : Mohan Reddy. B

#!/usr/bin/python3
from scapy.all import *
from prettytable import PrettyTable
from collections import Counter


#Read the packets from file, You can also use sniff or pcapreader function accordingly
packets = rdpcap('/mnt/d/PCAP Files/pcap_02.pcap')    #Change as per the location of the file

#List to hold SourceIPs
srcIP=[]

#Read each packet and append to the srcIP list.
for pkt in packets:
    if IP in pkt:
        try:
            srcIP.append(pkt[IP].src)
        except:
            pass

#Create an empty list to hold the count of logs
count=Counter()

#Create a list of IP and how many times they appeared
for ip in srcIP:
    count[ip] += 1

#Create header
table= PrettyTable(["IP", "Count"])

#Add records to table
for ip, count in count.most_common():
    table.add_row([ip, count])

print(table)

