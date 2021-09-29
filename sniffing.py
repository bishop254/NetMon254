import collections
import threading
from tkinter import *
from tkinter import ttk

import scapy.all as scapy
from scapy import packet

from scan import Scan
from PIL import ImageTk, Image


class Sniff():
    def __init__(self, master):
        self.master = master
    
    def startBtn(self):
        print('Sniffing started')
        labelStart = Label(my_canvas, text='Sniffing started').pack(padx=5, pady=5)
        
        global should_we_stop, subdomain
        global thread
        
        netwAddr = Scan(self.master)
        subD = netwAddr.getNetwAddr()
        subD = subD.split('.')
        subD.pop()
        sep = '.'
        subdomain = sep.join(subD)
    
        if (thread is None) or (not thread.is_alive()):
            should_we_stop = False
            thread = threading.Thread(target=self.sniffing)
            thread.start()

    def stopBtn(self):
        global should_we_stop
        print('Sniffing stopped')
        labelStart = Label(my_canvas, text='Sniffing stopped...').pack(padx=5, pady=5)
        should_we_stop = True
        
    def stopSniffing(self, x):
        
        global should_we_stop
        return should_we_stop
    
    def sniffing(self):
        scapy.sniff(prn=self.findIps, stop_filter=self.stopSniffing)
    
    def findIps(self, packet):
        global srcIpDict, treev, subdomain
        # print(packet.show())
        
        
        if 'IP' in packet:
            srcIp = packet['IP'].src
            dstIp = packet['IP'].dst
            
            if srcIp[0:len(subdomain)] == subdomain:
                if srcIp not in srcIpDict:
                    srcIpDict[srcIp].append(dstIp)
                    
                    row = treev.insert('', index=END, text=srcIp)
                    treev.insert(row, index=END, text=dstIp)
                    treev.pack(fill=X)
                
                else:
                    if dstIp not in srcIpDict[srcIp]:
                        srcIpDict[srcIp].append(dstIp)
                        
                        cur_item = treev.focus()
                        if (treev.item(cur_item)['text'] == srcIp):
                            treev.insert(cur_item, index=END, text=dstIp)
                        print(srcIp, dstIp)
    def mainSniff(self):
        try:
            global scanWindow, thread, should_we_stop, srcIpDict, treev, bg, my_canvas
            scanWindow = Toplevel()
            scanWindow.title('Sniff packets in real-time')
            scanWindow.geometry('600x400')
            scanWindow.resizable(True, True)
            
            bg = ImageTk.PhotoImage(Image.open("bck9.jpg"))

            my_canvas = Canvas(scanWindow, width=600, height=400)
            my_canvas.pack(fill=BOTH, expand=True, padx=10, pady=10)

            my_canvas.create_image(0,0, image=bg, anchor=NW)
            
            thread = None
            should_we_stop = True
            subdomain = ''
            
            srcIpDict = collections.defaultdict(list)

            Label1 = Label(my_canvas, text='Packet Tracer').pack(padx=5, pady=5)
            Label2 = Label(my_canvas, text='Click start to begin sniffing...').pack(padx=5, pady=5)
            Label2 = Label(my_canvas, text='Ensure to stop sniffing before you close the window').pack(padx=5, pady=5)

            treev = ttk.Treeview(my_canvas, height=400)
            treev.column('#0')

            button_frame = Frame(my_canvas)
            btn1 = Button(button_frame, text='Start sniff', command=self.startBtn).pack(side=LEFT)
            btn2 = Button(button_frame, text='Stop sniff', command=self.stopBtn).pack(side=LEFT)
            exitBtn = Button(button_frame, text='Exit to main program', command=scanWindow.destroy).pack(side=LEFT)

            button_frame.pack(side=BOTTOM, padx=5, pady=5)

        except TypeError as e:
            print(e)