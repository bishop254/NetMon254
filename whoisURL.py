import threading
import whois
from tkinter import *
from tkinter import ttk
from functools import partial


# def is_registered(domain_name):
#     try:
#         w = whois.whois(domain_name)
#     except Exception:
#         return False
#     else:
#         return bool(w.domain_name)

# domains = [
#     "thepythoncode.com",
#     "google.com",
#     "github.com",
#     "unknownrandomdomain.com",
#     "www.laikipia.ac.ke",
#     "portal.laikipia.ac.ke",
#     "facebook.com"
# ]

# for domain in domains:
#     print('\n', '.................', '\n')
#     print(domain, 'is registered.' if is_registered(domain) else 'is not registered')
    
#     if is_registered(domain):
#         whois_info = whois.whois(domain)
#         print('Domain registrar: ', whois_info.registrar)
#         print('WHOIS Server: ', whois_info.whois_server)
#         print("Domain creation date:", whois_info.creation_date)
#         print("Expiration date:", whois_info.expiration_date)
class WhoisLook():
    def __init__(self, master):
        self.master = master
        
    def is_registered(self, domain_name):
        try:
            w = whois.whois(domain_name)
            print(w)
        except Exception:
            return False
        else:
            print(w.domain_name)
            return bool(w.domain_name)
        
    def whoisScan(self):
        global scanWindow   , traceVal
        scanWindow = Toplevel()
        scanWindow.title('WHOIS Lookup...')
        scanWindow.geometry('400x300+350+150')
        scanWindow.resizable(True, True)

        traceVal = StringVar()
        newTraceInput = Entry(scanWindow, textvariable=traceVal).pack()
        newTraceButton = Button(scanWindow, text='Click to run custom scan...', command=partial(self.saveVar, newTraceInput)).pack(anchor=N) 
               
    def saveVar(self, entry):
        global name
        name = traceVal.get()
        name = str(name)
        print(name)
        scanWindow.destroy()
        
        thr1 = threading.Thread(target=self.is_registered(name))
        thr1.start()