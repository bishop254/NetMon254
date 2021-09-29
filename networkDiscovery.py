import threading
from tkinter import *
from tkinter import ttk
import time
import socket
import struct  # for pckt-sniff route
import textwrap
from threading import Thread
import random


from scapy.sendrecv import sniff
from scapy.utils import wrpcap  # for pckt-sniff route

class Scan2:
    def __init__(self, master):
        self.master = master
        
    def sniff_main(self):
        global dstArr, srcArr, protArr
        
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        count = 0
        
        dstArr = []
        srcArr = []
        protArr = []
        
        while (count < 20):
            count = count + 1    
            raw_data, addr = conn.recvfrom(65536)
            dst_mac, src_mac, eth_proto, data = self.eth_frame(raw_data)
            # print(self.eth_frame(raw_data)) 
            dstArr.append(dst_mac)
            srcArr.append(src_mac)
            protArr.append(eth_proto) 

            # print (f"\n Ethernet frame: \n")
            # print('Destination: {}, Source:{}, Protocol:{}'.format(dst_mac, src_mac, eth_proto))
        
        packetWdw.after(100, self.main_sniff)
    
    def main_sniff(self):
        packetWdw.destroy()
        
        global packetWindow   
        packetWindow = Toplevel()
        packetWindow.title('Sniffed Packets...')
        packetWindow.geometry('700x500+350+150')
        packetWindow.resizable(True, True)
        packetFrame = Frame(packetWindow, padx=10, pady=10)
        canvas = Canvas(packetFrame, height=700, width=500)
        scrollBar = Scrollbar(packetFrame, orient='vertical', command=canvas.yview)
        scrollFrame = Frame(canvas)
        
        scrollFrame.bind(   
            "<Configure>",
            lambda e: canvas.configure(
                scrollregion=canvas.bbox('all')
            )
        )
        
        canvas.create_window((0,0), window=scrollFrame, anchor='nw')
        canvas.configure(yscrollcommand=scrollBar.set)
        
        for i in range(len(dstArr)):
            label1 = Label(scrollFrame, text='Destination MAC :  ' + str(dstArr[i])).pack()
            label2 = Label(scrollFrame, text='Source MAC :  ' + str(srcArr[i])).pack()
            label3 = Label(scrollFrame, text='Protocol Number :  ' + str(protArr[i])).pack() 
            label4 = Label(scrollFrame, text='_____________').pack()
            # label5 = Label(scrollFr)
        
        # capture = sniff(iface='wlo1' , count=100)
        # wrpcap('cap1.pcap', capture)
        
        packetFrame.pack()
        canvas.pack(side='left', fill='both', expand=True)
        scrollBar.pack(side='right', fill='y')
        exitButton = Button(packetFrame, text='Go Back...', command=packetWindow.destroy).pack(side='top')

    def eth_frame(self, data):
        dst_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
        return self.get_mac(dst_mac), self.get_mac(src_mac), socket.htons(proto), data[14:]

    def get_mac(self, byte_addr):
        byte_str = map('{:02x}'.format, byte_addr)
        mac_addr = ':'.join(byte_str).upper()
        return mac_addr
    
    def mainMeth(self):
        global packetWdw, myProg   
        packetWdw = Toplevel()
        packetWdw.title('Sniffed Packets...')
        packetWdw.geometry('200x100+550+250')
        packetWdw.resizable(True, True)
        labelx = Label(packetWdw, text='Loading your screen...').pack(pady=10)
        
        myProg = ttk.Progressbar(packetWdw, orient=HORIZONTAL, length=254, mode='indeterminate')
        myProg.pack(pady=20, padx=10)
        
        myProg.start(5)   
        
        thr1 = threading.Thread(target=self.sniff_main)
        thr1.start()
              
            
        
        