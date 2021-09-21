import pandas as pd
from steelscript.wireshark.core.pcap import PcapFile, TSharkFields

pcap = PcapFile('/home/kc/Projects/DogiPy/cap1.pcap')
# pcap.info()

# print(pcap.starttime)
# print(pcap.endtime)
# print(pcap.numpackets)

# pdf = pcap.query(['frame.time_epoch', 'ip.src', 'ip.dst', 'ip.len', 'ip.proto'],
#                  starttime=pcap.starttime,
#                  duration='1min',
#                  as_dataframe=True)
# pdf = pdf[~(pdf['ip.len'].isnull())]
# print(len(pdf), 'packets loaded')

tf = TSharkFields.instance()
tf.find(protocol='tcp', name_re='port')