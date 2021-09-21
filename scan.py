from pyscan import Pyscan
from tkinter import *
import ifcfg
import json
from functools import partial
import socket
from netdisco.discovery import NetworkDiscovery
from scapy import interfaces
import scapy
from scapy.all import *
from scapy.layers.l2 import ARP, Ether
from scapy.layers.inet import ICMP, IP, TCP, traceroute
import nmap


class Scan():
    def __init__(self, master):
        self.master = master
    
    def getIp(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return (ip)

    def getNetwAddr(self):
        ip = self.getIp()
        ipList = ip.split(".")
        ipList.pop()
        sep = '.'
        ipNew = sep.join(ipList)
        ipNew = ipNew + ".0"
        return str(ipNew)
    
    def arpscan(self):
        try:
            global scanWindow   
            scanWindow = Toplevel()
            scanWindow.title('Devices in the network...')
            scanWindow.geometry('600x400+350+150')
            scanWindow.resizable(True, True)
            
            ip = self.getNetwAddr() + '/24'
            request = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip)
            ans, unasw = srp(request, timeout=1, retry=1)
            result = []
            
            for sent, recv in ans:
                result.append({'IP': recv.psrc, 'MAC': recv.hwsrc})       
            
            
            for i in range(len(result)):
                ipAddr = result[i]['IP']
                       
                portScan = Pyscan(self.master)
                scanPortsButton = Button(scanWindow, text='Scan ' + ipAddr, command=partial(portScan.actualScan, ipAddr)).pack()
                

                scanLabel = Label(scanWindow, text='IP Addr : ' + (result[i]['IP']) + '\n' 'MAC : ' + (result[i]['MAC']) + '\n')
                scanLabel.pack()
              
            exitButton = Button(scanWindow, text='Go Back...', command=scanWindow.destroy).pack(side='bottom')
            
        except PermissionError as e:
            errorLabel = Label(scanWindow, text=str(e) + '\n Restart the Application with root privileges').pack()
     