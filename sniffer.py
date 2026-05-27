from scapy.all import *
def packet_callback(packet):
    print(packet.summary())
sniff(prn=packet_callback,store=False,count=5)