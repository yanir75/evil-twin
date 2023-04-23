from scapy.all import *
def beacon_packet(sender,ssid):
    iface = ''   

    dot11 = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff',
    addr2=sender, addr3=sender)
    beacon = Dot11Beacon()
    essid = Dot11Elt(ID='SSID',info=ssid, len=len(ssid))

    frame = RadioTap()/dot11/beacon/essid

    sendp(frame, iface=iface, inter=0.100, loop=1)
beacon_packet('',"")