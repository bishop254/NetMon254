import json
from functools import partial
from tkinter import *

import ifcfg
from PIL import Image, ImageTk

from grAnalysis import GraphAnalysis
from networkDiscovery import Scan2
from scan import Scan
from scapii import Scapii
from scapyTraceroute import ScapyTraceRoute
from sniffing import Sniff
from speed import SpeedTest
from whoisURL import WhoisLook

root = Tk()
root.geometry('800x500+200+100')
root.attributes('-zoomed', True)
# root.config(bg='black')

bg = ImageTk.PhotoImage(Image.open("bck10.jpg"))

my_canvas = Canvas(root, width=900, height=500)
my_canvas.pack(fill=BOTH, expand=True, padx=10, pady=10)

my_canvas.create_image(0,0, image=bg, anchor=NW)

class DevInterfaces():
    def __init__(self, master):
        self.master = master
        master.title('Network Monitoring Tool')
    
        self.button1 = Button(master, text='Search for available network adapter information', command=self.openInterfaces)
        btn1_wndw = my_canvas.create_window(50,40, anchor='nw', window=self.button1)
        
        scan1 = Scan(master)
        self.button2 = Button(master, text='Search Other Devices on the Network', command=scan1.actualScan)
        btn2_wndw = my_canvas.create_window(50,90, anchor='nw', window=self.button2)

        scan2 = Scan2(master)
        self.button21 = Button(master, text='Sniff Packets on the Network', command=scan2.mainMeth)
        btn2_wndw = my_canvas.create_window(50,140, anchor='nw', window=self.button21)

        scan3 = ScapyTraceRoute(master)         
        self.button3 = Button(master, text='Trace route to a website/IP', command=scan3.trace)
        btn3_wndw = my_canvas.create_window(50,190, anchor='nw', window=self.button3)
       
        scan4 = Sniff(master)         
        self.button4 = Button(master, text='Sniff Packets in real-time', command=scan4.mainSniff)
        btn4_wndw = my_canvas.create_window(50,240, anchor='nw', window=self.button4)
      
        scan5 = SpeedTest(master)
        self.button5 = Button(master, text='Speed test', command=scan5.mainSpeed)
        btn5_wndw = my_canvas.create_window(50,290, anchor='nw', window=self.button5)
     
        scan6 = GraphAnalysis(master)
        self.button6 = Button(master, text='Perform analysis on packets', command=scan6.mainAnalysisMeth)
        btn6_wndw = my_canvas.create_window(50,340, anchor='nw', window=self.button6)

        scan7 = WhoisLook(master)
        self.button7 = Button(master, text='Check if a website is registered(whois-lookup)', command=scan7.whoisScan)
        btn7_wndw = my_canvas.create_window(50,390, anchor='nw', window=self.button7)
        

    def openInterfaces(self):
        self.button1.config(state=DISABLED)
        global top
        top = Toplevel()
        top.title('Device Interface Info')
        top.geometry('500x500+50+100')
        top.resizable(True, True)
        top.attributes('-zoomed', True)
        
        dev = ifcfg.interfaces()  # gets network adapter information
        devNames = []  # list to store network adapter names
        devObj = []  # list to store detailed information about all adapter

        # get all network adapter names and add them to a list
        for x in dev:
            devNames.append(x)

        # get all adapter information and save it to a list
        for x in range(len(devNames)):
            temp = devNames[x]
            devObj.append(dev[temp])
        
        myFrame  = LabelFrame(top , text='Main Program', padx=10, pady=10, width=100, height=100)
        myFrame.pack(side='left')
        myFrame1  = LabelFrame(top , text='Main Program', padx=10, pady=10, width=100, height=100)
        myFrame1.pack(side='right')
        
        def openDevInfo(num):
            global devInfoLevel
            devInfoLevel = Toplevel()
            devInfoLevel.title('Additional Device Information')
            devInfoLevel.geometry('500x300+350+150')
            devInfoLevel.resizable(True, True)
            
            addInfoLabel = Label(devInfoLevel, text='INET : ' + str(devObj[num]['inet']), pady=2, padx=2).pack(side='top')
            addInfoLabe1 = Label(devInfoLevel, text='INET4 : ' + str(devObj[num]['inet4']), pady=2, padx=2).pack(side='top')
            addInfoLabel2 = Label(devInfoLevel, text='ETHER : ' + str(devObj[num]['ether']), pady=2, padx=2).pack(side='top')
            addInfoLabel3 = Label(devInfoLevel, text='INET6 : ' + str(devObj[num]['inet6']), pady=2, padx=2).pack(side='top')
            addInfoLabel4 = Label(devInfoLevel, text='NETMASK : ' + str(devObj[num]['netmask']), pady=2, padx=2).pack(side='top')
            addInfoLabel5 = Label(devInfoLevel, text='DEVICE : ' + str(devObj[num]['device']), pady=2, padx=2).pack(side='top')
            addInfoLabel6 = Label(devInfoLevel, text='FLAGS : ' + str(devObj[num]['flags']), pady=2, padx=2).pack(side='top')
            addInfoLabel7 = Label(devInfoLevel, text='MTU : ' + str(devObj[num]['mtu']), pady=2, padx=2).pack(side='top')

            exitButton = Button(devInfoLevel, text='Go Back...', command=devInfoLevel.destroy).pack(side='bottom')
        
        for num in range(len(devObj)):
            myLabel1 = Label(myFrame, borderwidth=10, fg='white', bg='black', text='INTERFACE NAME : \n \n' + devObj[num]['device']).pack()
            myLabel2 = Label(myFrame, borderwidth=5, fg='black', bg='white', text='IP ADDRESS : \n ' + str(devObj[num]['inet4'])).pack()
            myLabel3 = Label(myFrame, borderwidth=5, fg='white', bg='black', text='MAC ADDRESS : \n ' + str(devObj[num]['ether'])).pack()
            addInfoButton = Button(myFrame, fg='white', bg='grey', text='Additional Device Data', command=partial(openDevInfo, num)).pack()
            myLabel = Label(myFrame, text='_________________').pack(padx=5, pady=5)
           

        interfaceButton = Button(myFrame1, command=self.close, text='Exit to Main Page')
        interfaceButton.pack()
         
    def close(self):
        self.button1.config(state=ACTIVE)
        top.destroy()
 
int1 = DevInterfaces(root)

root.mainloop()
