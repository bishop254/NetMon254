import subprocess
from tkinter import *
from subprocess import *
from tkinter import ttk
import threading
from PIL import ImageTk, Image

class SpeedTest:
    def __init__(self, master):
        self.master = master
    
    def cmdLine(self):
        
        resp1 = subprocess.run(["sudo", "speedtest-cli"], capture_output=True)
        packetWdw.destroy()
        
        global scanWindow, bg   
        
        scanWindow = Toplevel()
        scanWindow.title('Devices in the network...')
        scanWindow.geometry('600x400+350+150')
        scanWindow.resizable(True, True)

        bg = ImageTk.PhotoImage(Image.open("bck10.jpg"))

        my_canvas = Canvas(scanWindow, width=600, height=400)
        my_canvas.pack(fill=BOTH, expand=True, padx=10, pady=10)       
        
        my_canvas.create_image(0,0, image=bg, anchor=NW)
        my_canvas.create_text(0,0, text=resp1.stdout, fill='white')
        # label1 = Label(my_canvas, text=resp1.stdout).pack()
            
        

    def mainSpeed(self):
        global packetWdw, myProg   
        packetWdw = Toplevel()
        packetWdw.title('Sniffed Packets...')
        packetWdw.geometry('200x100+550+250')
        packetWdw.resizable(True, True)
        labelx = Label(packetWdw, text='Loading your screen...').pack(pady=10)
        
        myProg = ttk.Progressbar(packetWdw, orient=HORIZONTAL, length=254, mode='indeterminate')
        myProg.pack(pady=20, padx=10)
        
        myProg.start(5)   
        
        thr1 = threading.Thread(target=self.cmdLine)
        thr1.start()
                           
        