import subprocess
from tkinter import *
from subprocess import *


class SpeedTest:
    def __init__(self, master):
        self.master = master
    
    def cmdLine(self):
        
        resp1 = subprocess.run(["sudo", "speedtest-cli"], capture_output=True)
        
        global scanWindow   
        scanWindow = Toplevel()
        scanWindow.title('Devices in the network...')
        scanWindow.geometry('600x400+350+150')
        scanWindow.resizable(True, True)
        
        label1 = Label(scanWindow, text=resp1.stdout).pack()
            
        return (resp1.stdout)

                    
        