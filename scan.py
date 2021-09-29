import json
import socket
from functools import partial
from tkinter import *
from tkinter import ttk
from PIL import ImageTk, Image

import ifcfg
import nmap
import scapy
from netdisco.discovery import NetworkDiscovery
from scapy import interfaces
from scapy.all import *
from scapy.layers.inet import ICMP, IP, TCP, traceroute
from scapy.layers.l2 import ARP, Ether

from pyscan import Pyscan


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
    
    def arpS(self):
        global ip, request, ans, unasw, result
        
        ip = self.getNetwAddr() + '/24'
        request = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip)
        ans, unasw = srp(request, timeout=1, retry=1)
        result = []
        
        for sent, recv in ans:
            result.append({'IP': recv.psrc, 'MAC': recv.hwsrc})   
            
        packetWdw.destroy()
        self.arpscan()
            
    
    def arpscan(self):
        try:
            global scanWindow, bg
            scanWindow = Toplevel()
            scanWindow.title('Devices in the network...')
            scanWindow.geometry('600x400+350+150')
            scanWindow.resizable(True, True)
            # scanWindow.config(background='black')
            
            bg = ImageTk.PhotoImage(Image.open("bck1.jpg"))
            
            my_canv = Canvas(scanWindow, width=600, height=400)
            my_canv.pack(fill=BOTH, expand=True, pady=10, padx=10)
            my_canv.create_image(0,0, image=bg, anchor=NW)
            
            
            for i in range(len(result)):
                ipAddr = result[i]['IP']
                       
                portScan = Pyscan(self.master)
                scanPortsButton = Button(my_canv, text='Scan ports of ' + ipAddr , command=partial(portScan.actualScan, ipAddr)).pack(pady=10, padx=10)
                
                scanLabel = Label(my_canv, text='IP Addr : ' + (result[i]['IP']) + '\n' 'MAC : ' + (result[i]['MAC']))
                scanLabel.pack()
                
            exitButton = Button(my_canv, text='Go Back...', command=scanWindow.destroy).pack(side='bottom')
            
        except PermissionError as e:
            errorLabel = Label(scanWindow, text=str(e) + '\n Restart the Application with root privileges').pack()
            
    def actualScan(self):
        global packetWdw, myProg   
        packetWdw = Toplevel()
        packetWdw.title('Sniffed Packets...')
        packetWdw.geometry('200x100+550+250')
        packetWdw.resizable(True, True)
        labelx = Label(packetWdw, text='Loading your screen...').pack(pady=10)
        
        myProg = ttk.Progressbar(packetWdw, orient=HORIZONTAL, length=254, mode='indeterminate')
        myProg.pack(pady=20, padx=10)
        
        myProg.start(5)   
        
        thr1 = threading.Thread(target=self.arpS)
        thr1.start()     
