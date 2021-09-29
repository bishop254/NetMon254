from itertools import count
from scapy import fields
from scapy.all import *
import pandas as pd
import numpy as np
import binascii
import seaborn as sns
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP
import matplotlib.pyplot as plt

sns.set(color_codes=True)
pcap = sniff(count=150)
wrpcap('cap1.pcap', pcap)

# pcap = pcap + rdpcap('cap1.pcap')
print(pcap)

eth_frame = pcap[101]
ip_pack = eth_frame.payload
segment = ip_pack.payload
data = segment.payload

print(eth_frame.summary())
print(ip_pack.summary())
print(segment.summary())
print(data.summary())

eth_frame.show()

print(type(eth_frame))
print(type(ip_pack))
print(type(segment))

eth_type = type(eth_frame)
ip_type = type(ip_pack)
tcp_type = type(segment)

print('Ethernet', pcap[eth_type])
print('IP', pcap[ip_type])
print('TCP', pcap[tcp_type])
print('UDP', pcap[UDP])

ip_fields = [field.name for field in IP().fields_desc]
tcp_fields = [field.name for field in TCP().fields_desc]
udp_fields = [field.name for field in UDP().fields_desc]

dataframe_fields = ip_fields + ['time'] + tcp_fields + ['payload', 'payload_raw', 'payload_hex']

df = pd.DataFrame(columns=dataframe_fields)
for packet in pcap[IP]:
    field_values = []
    for field in ip_fields:
        if field == 'options':
            field_values.append(len(packet[IP].fields[field]))
        else:
            field_values.append(packet[IP].fields[field])
    field_values.append(packet.time)
    
    layer_type = type(packet[IP].payload)
    for field in tcp_fields:
        try:
            if field == 'options':
                field_values.append(len(packet[layer_type].fields[field]))
            else:
                field_values.append(packet[layer_type].fields[field])
        except:
            field_values.append(None) 
    
    field_values.append(len(packet[layer_type].payload))
    field_values.append(packet[layer_type].payload.original)
    field_values.append(binascii.hexlify(packet[layer_type].payload.original))
    
    df_append = pd.DataFrame([field_values], columns=dataframe_fields)
    df = pd.concat([df, df_append], axis=0)
    
df = df.reset_index()
df = df.drop(columns='index')

print(df.iloc[0])
print(df.shape) 
print(df.head())      
print(df['src'])

print('Top src addr')
print(df['src'].describe(), '\n')

print('Top dest addr')
print(df['dst'].describe(), '\n')

frequent_addr = df['src'].describe()['top']

print('Who is the top address speaking to...')
print(df[df['src'] == frequent_addr]['dst'].unique(), '\n')

print('Who is the top address speaking to...(dst ports)')
print(df[df['src'] == frequent_addr]['dport'].unique(), '\n')

print('Who is the top address speaking to...(src port)')
print(df[df['src'] == frequent_addr]['sport'].unique(), '\n')

print('Unique src addr')
print(df['src'].unique())

print('Unique dst addr')
print(df['dst'].unique())


src_addr = df.groupby("src")['payload'].sum()
src_addr.plot(kind='barh', title='Address Sending payloads', figsize=(8,5))
plt.show()

dst_addr = df.groupby("dst")['payload'].sum()
dst_addr.plot(kind='barh', title='Dest addr (bytes recv)', figsize=(8,5))
plt.show()

source_payloads = df.groupby("sport")['payload'].sum()
source_payloads.plot(kind='barh',title="Source Ports (Bytes Sent)",figsize=(8,5))
plt.show()

destination_payloads = df.groupby("dport")['payload'].sum()
destination_payloads.plot(kind='barh',title="Destination Ports (Bytes Received)",figsize=(8,5))
plt.show()

frequent_address_df = df[df['src'] == frequent_addr]
x = frequent_address_df['payload'].tolist()
sns.barplot(x="time", y="payload", data=frequent_address_df[['payload','time']],
            label="Total", color="b").set_title("History of bytes sent by most frequent address")
plt.show()