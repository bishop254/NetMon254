# from scapy.all import *
# a = " "
# os.system("tshark -T fields -e frame.time -e data.data -w Eavesdrop_Data.pcap > Eavesdrop_Data.txt -F pcap -c 1000")
# data = "Eavesdrop_Data.pcap"
# a = rdpcap(data)
# sessions = a.sessions()
# print (sessions)

# from scapy import *
# from scapy.sendrecv import sniff

# def sniffer(ip):
#     filter_str = "icmp and host " + ip
#     packets=sniff(filter=filter_str,count=2)
#     f = open('cap1.pcap',"a")
#     f.write(str(packets))

from scapy.all import *
a = " "
os.system("tshark -T fields -e frame.time -e data.data -w cap1.pcap > Eavesdrop_Data.txt -F pcap -c 100")
data = "cap1.pcap"
a = rdpcap(data)
sessions = a.sessions()
print (sessions)