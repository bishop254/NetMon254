from scapy.all import *
from tkinter import *


class Pyscan():
    def __init__(self, master):
        self.master = master
        self.openPorts = []
        self.filteredPorts = []
        self.common_ports = { 21, 22, 23, 25, 53, 69, 80, 88, 109, 110, 123, 137, 138, 139, 143, 156, 161, 389, 443, 445, 500, 546, 547, 587, 660, 995, 993, 2086, 2087, 2082, 2083, 3306, 8443, 10000 }

        
    def is_up(self, ip):
        icmp = IP(dst=ip)/ICMP()
        resp = sr1(icmp, timeout=10)
        if resp == None:
            return False
        else:
            return True
        
    def probe_port(self, ip, port, result=1):
        src_port = RandShort()
        try:
            p = IP(dst=ip)/TCP(sport=src_port, dport=port, flags='F')
            resp = sr1(p, timeout=2)
            if(str(type(resp)) == "<type 'Nonetype'>"):
                result = 1
            elif(resp.haslayer(TCP)):
                if resp.getlayer(TCP).flags == 0x14:
                    result = 0
                elif( int(resp.getlayer(ICMP).type) == 3 and int(resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
                    result = 2
        
        except Exception as e:
            pass
        return result
    
    def actualScan(self, ip):
        global scanWindow   
        scanWindow = Toplevel()
        scanWindow.title('Common Ports scan...')
        scanWindow.geometry('500x300+350+150')
        scanWindow.resizable(True, True)
        self.openPorts = []
        self.filteredPorts = []
    
        if self.is_up(ip):
            for port in self.common_ports:
                # label1 = Label(scanWindow, text=port).pack()
                print(port)
                response = self.probe_port(ip, port)
                if response == 1:
                    self.openPorts.append(port)
                elif response == 2:
                    self.filteredPorts.append(port)
            
            if len(self.openPorts) != 0:
                label2 = Label(scanWindow, text='Possible open or filtered ports: ' + str(self.openPorts)).pack()
                print('Possible open or filtered ports: ')
                print(self.openPorts)
            if len(self.filteredPorts) != 0:
                label3 = Label(scanWindow, text='Possible filtered ports: ' + str(self.filteredPorts)).pack()                
                print('Possible filtered ports: ')
                print(self.filteredPorts)
            if (len(self.openPorts) == 0) and (len(self.filteredPorts) == 0):
                label4 = Label(scanWindow, text='No open ports found').pack()
                print('Sorry... no open ports found...')
            
        else:
            label5 = Label(scanWindow, text='Host is down').pack()
            print('Host is down') 
        
        exitButton = Button(scanWindow, text='Go Back...', command=scanWindow.destroy).pack(side='top')

    
    
    