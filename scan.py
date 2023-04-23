from scapy.all import *
from threading import Thread
import os
i = 1
def change_channel(netowrk_interface):
    global i
    while 1:
        time.sleep(3)
        os.system(f"iwconfig {netowrk_interface} channel {i}")
        i = (i+1)%13+1

networks = dict()
users = dict()

def print_packet(pkt):
    if pkt.haslayer(Dot11):
        dot_layer = pkt.getlayer(Dot11)
        if dot_layer.addr2 and dot_layer.payload.name == "802.11 Beacon":
            networks[dot_layer.addr2] = (pkt[Dot11Elt].info.decode(),i)
            print(networks)
        elif pkt.type == 2:
            DS = pkt.FCfield & 0x3
            to_DS = DS & 0x1 != 0
            from_DS = DS & 0x2 != 0
            if not to_DS and from_DS:
                users[pkt.addr3] = pkt.addr2
                print(users,i) 

            elif to_DS and not from_DS:
                users[pkt.addr2] = pkt.addr1
                print(users,i)  
x = Thread(target=change_channel, args=('',))
x.start()

sniff(iface = '',prn = print_packet)
x.join()
