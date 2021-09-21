from speed import SpeedTest
from sniffing import Sniff
from scapyTraceroute import ScapyTraceRoute
from scapii import Scapii
from networkDiscovery import Scan2
from scan import Scan
from tkinter import *
import ifcfg
import json
from functools import partial

root = Tk()
root.geometry('400x500+200+100')
root.attributes('-zoomed', True)


class DevInterfaces():
    
    def __init__(self, master):
        self.master = master
        master.title('Network Monitoring Tool')
    
        self.button1 = Button(master, text='Search for available network adapter information', command=self.openInterfaces)
        self.button1.pack()
        
        scan1 = Scan(master)
        self.button2 = Button(master, text='Search Other Devices on the Network', command=scan1.arpscan)
        self.button2.pack()
        
        scan2 = Scan2(master)
        self.button2 = Button(master, text='Sniff Packets on the Network', command=scan2.main_sniff)
        self.button2.pack()

        scan3 = ScapyTraceRoute(master)         
        self.button3 = Button(master, text='Trace route to google', command=scan3.trace)
        self.button3.pack()   
        
        scan4 = Sniff(master)         
        self.button4 = Button(master, text='Sniff Packets', command=scan4.mainSniff)
        self.button4.pack() 
        
        scan5 = SpeedTest(master)
        self.button4 = Button(master, text='Speed test', command=scan5.cmdLine)
        self.button4.pack()        
    
    def openInterfaces(self):
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
            self.button1['state'] = 'disabled'    

            # response = Scapii(myFrame1)
            # myLabel4 = Label(myFrame1, text=devObj[num]['device'] + ' : \t' + str(response.cmdLine(devObj[num]['device']))).pack()
            # print(response.cmdLine(devObj[num]['device']))
            
        interfaceButton = Button(myFrame1, command=self.close, text='Exit to Main Page')
        interfaceButton.pack()
         
    def close(self):
        self.button1['state'] = 'active'
        top.destroy()
 
int1 = DevInterfaces(root)

root.mainloop()