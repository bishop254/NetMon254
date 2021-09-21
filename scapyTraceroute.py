from functools import partial
from os import name
from scapy.all import *
from tkinter import *
from PIL import ImageTk, Image
 
class ScapyTraceRoute():
    def __init__(self, master):
        self.master = master
        
    def trace(self):
        traceVal = StringVar()
        
        try:
            global scanWindow   
            scanWindow = Toplevel()
            scanWindow.title('Trace route page')
            scanWindow.geometry('400x300+350+150')
            scanWindow.resizable(True, True)
            
            def saveVar(label, entry):
                global name
                name = traceVal.get()
                print(name)
                newTraceLabel =  Label(scanWindow, text='Carrying out tasks in the background...').pack(anchor=CENTER)
                scanWindow.destroy()
                self.trace2()
            
            newTraceLabel = Label(scanWindow, text='Enter URL or IP address to trace the route').pack()
            newTraceInput = Entry(scanWindow, textvariable=traceVal).pack()
            newTraceButton = Button(scanWindow, text='Click to run custom scan...', command=partial(saveVar, newTraceLabel, newTraceInput)).pack(anchor=N)
            
        except:
            pass
    
    def trace2(self):
        try:
            global scanWindow   
            scanWindow = Toplevel()
            scanWindow.title('Trace route page')
            scanWindow.geometry('800x600+350+150')
            scanWindow.resizable(True, True)
            scanWindow.attributes('-zoomed', True)
            
            resp2, unasw2 = traceroute([str(name)], maxttl=16)
            resp2.graph(format='gif', target='one.gif')
            
            myFrame1  = LabelFrame(scanWindow , text='Main Program', padx=10, pady=10, width=100, height=100)
            myFrame1.pack(side='right')
            exitButton = Button(myFrame1, text='Exit to Main program', command=scanWindow.destroy).pack(anchor=W)
            
            global img
            img = ImageTk.PhotoImage(Image.open("/home/kc/Projects/DogiPy/one.gif"))
            canvas = Canvas(scanWindow, width=750, height=950)
            
            canvas.create_image(20, 20, anchor=NW, image=img)
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
                        
        except PermissionError as e:
            errorLabel = Label(scanWindow, text=e)
            errorLabel.pack()

        
            
            
            
            
