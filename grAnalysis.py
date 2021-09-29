#!/usr/bin/python

import binascii
from itertools import count
from tkinter import *
from tkinter import ttk
from PIL import Image, ImageTk
import pandas as pd
from scapy import fields
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns

class GraphAnalysis():
    def __init__(self, master):
        self.master = master
    
    def mainAnalysis(self):
        print('Starting capture of pcap data')
        global pcap
        sns.set(color_codes=True)
        pcap = sniff(count=20)
        wrpcap('cap1.pcap', pcap)
        packetWdw.destroy()
        
        thr2 = threading.Thread(target=self.mainAnalysis2)
        thr2.start()
        
    def mainAnalysis2(self):
        global scanWindow   
        scanWindow = Toplevel()
        scanWindow.title('Graphical analysis page')
        scanWindow.geometry('800x600+350+150')
        scanWindow.resizable(True, True)
        scanWindow.attributes('-zoomed', True)
        
        myFrame1  = LabelFrame(scanWindow , text='Packet Analysis', padx=10, pady=10, width=100, height=100)
        myFrame1.pack(side='right')
        exitButton = Button(myFrame1, text='Exit to Main program', command=scanWindow.destroy).pack(anchor=NW)
        
        canvas = Canvas(scanWindow, width=750, height=950)
        
        print('Capture done... started analysing packets')
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

        frequent_addr = df['src'].describe()['top']

        src_addr = df.groupby("src")['payload'].sum()
        src_addr.plot(kind='barh', title='Address Sending payloads', figsize=(8,5))
        pic1 = plt.show()
        canvas.create_image(0,0, anchor=NW,image=pic1)

        dst_addr = df.groupby("dst")['payload'].sum()
        dst = dst_addr.plot(kind='barh', title='Dest addr (bytes recv)', figsize=(8,5))
        # plt.show()
        canvas.create_image(0,10, anchor=NW,image=plt.show())

        source_payloads = df.groupby("sport")['payload'].sum()
        source_payloads.plot(kind='barh',title="Source Ports (Bytes Sent)",figsize=(8,5))
        # plt.show()
        canvas.create_image(0,30, anchor=NW,image=plt.show())

        destination_payloads = df.groupby("dport")['payload'].sum()
        destination_payloads.plot(kind='barh',title="Destination Ports (Bytes Received)",figsize=(8,5))
        # plt.show()
        canvas.create_image(0,40, anchor=NW,image=plt.show())

        frequent_address_df = df[df['src'] == frequent_addr]
        x = frequent_address_df['payload'].tolist()
        sns.barplot(x="time", y="payload", data=frequent_address_df[['payload','time']],
                    label="Total", color="b").set_title("History of bytes sent by most frequent address")
        # plt.show()
        canvas.create_image(0,50, anchor=NW, image=plt.show())
        
        scrollBar = Scrollbar(scanWindow, orient='vertical', command=canvas.yview)
        scrollFrame = Frame(canvas)
        
        scrollFrame.bind(
            "<Configure>",
            lambda e: canvas.configure(
                scrollregion=canvas.bbox('all')
            )
        )
        
        canvas.create_window((0,0), window=scrollFrame, anchor='nw')
        canvas.configure(yscrollcommand=scrollBar.set)

        scrollBar.pack(side='left', fill='y') 
        canvas.pack(side='left', fill='both', expand=True)
        
        
        
        # global scanWindow   
        # scanWindow = Toplevel()
        # scanWindow.title('Trace route page')
        # scanWindow.geometry('800x600+350+150')
        # scanWindow.resizable(True, True)
        # scanWindow.attributes('-zoomed', True)
        
        # myFrame1  = LabelFrame(scanWindow , text='Packet Analysis', padx=10, pady=10, width=100, height=100)
        # myFrame1.pack(side='right')
        # exitButton = Button(myFrame1, text='Exit to Main program', command=scanWindow.destroy).pack(anchor=W)
        
        # global img
        # img = ImageTk.PhotoImage(Image.open("/home/kc/Projects/DogiPy/one.gif"))
        # canvas = Canvas(scanWindow, width=750, height=950)
        
        # canvas.create_image(20, 20, anchor=NW, image=img)
        # scrollBar = Scrollbar(scanWindow, orient='vertical', command=canvas.yview)
        # scrollFrame = Frame(canvas)
        
        # scrollFrame.bind(
        #     "<Configure>",
        #     lambda e: canvas.configure(
        #         scrollregion=canvas.bbox('all')
        #     )
        # )
        
        # canvas.create_window((0,0), window=scrollFrame, anchor='nw')
        # canvas.configure(yscrollcommand=scrollBar.set)

        # scrollBar.pack(side='left', fill='y') 
        # canvas.pack(side='left', fill='both', expand=True)

    def mainAnalysisMeth(self):
        global packetWdw, myProg   
        packetWdw = Toplevel()
        packetWdw.title('Sniffed Packets...')
        packetWdw.geometry('200x100+550+250')
        packetWdw.resizable(True, True)
        labelx = Label(packetWdw, text='Loading your screen...').pack(pady=10)
        
        myProg = ttk.Progressbar(packetWdw, orient=HORIZONTAL, length=254, mode='indeterminate')
        myProg.pack(pady=20, padx=10)
        
        myProg.start(5)   
        
        thr1 = threading.Thread(target=self.mainAnalysis)
        thr1.start()