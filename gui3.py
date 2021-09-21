# import tkinter as tk
# from tkinter import ttk

# from scapy import themes

# class App(tk.Tk):
#     def __init__(self):
#         super().__init__()
        
#         #root window
#         self.title('Demo')
#         self.geometry('500x400')
#         self.style = ttk.Style(self)
        
#         # label
#         label = ttk.Label(self, text='Name : ')
#         label.grid(column=0, row=0, padx=10, pady=10, sticky='w')
        
#         # entry
#         textbox = ttk.Entry(self)
#         textbox.grid(column=1, row=0, padx=10, pady=10, sticky='w')
        
#         # button
#         btn = ttk.Button(self, text='Show')
#         btn.grid(column=2, row=0, padx=10, pady=10, sticky='w')
        
#         # radio button
#         self.selected_theme = tk.StringVar()
#         themes_frame = ttk.Labelframe(self, text='Themes')
#         themes_frame.grid(padx=10, pady=10, ipadx=20, ipady=20, sticky='w')
        
#         for theme_name in self.style.theme_names():
#             rb = ttk.Radiobutton(
#                 themes_frame,
#                 text=theme_name,
#                 value=theme_name,
#                 variable=self.selected_theme,
#                 command=self.change_theme
#             )
#             rb.pack(expand=True, fill='both')
        
#     def change_theme(self):
#         self.style.theme_use(self.selected_theme.get())

# if __name__ == '__main__':
#     app = App()
#     app.mainloop()


from graphics import *
from scapy.all import *
from collections import Counter

def main():
    filename = str(input("What is the name of the file? "))

    # sets packet source IPAs to sources, sourcenum also has # of occurrences
    IP.payload_guess = []
    sources = list((p[IP].src) for p in PcapReader(filename) if IP in p)
    sourcenum = collections.Counter(sources)
    print (sourcenum)

    def makegraph():
        howmany = sum(1 for x in sourcenum.values())
        width = 1000/howmany

        # creates graph window with white background
        win = GraphWin("Packets Sent From Certain Addresses", 1080, 360)
        win.setBackground("white")
        Line(Point(80, 330), Point(1080, 330)).draw(win)
        Line(Point(80, 0), Point(80, 330)).draw(win)

        # creates y axis labels
        Text(Point(40, 330), " 0k pkts").draw(win)
        Text(Point(40, 280), " 3k pkts").draw(win)
        Text(Point(40, 230), " 6k pkts").draw(win)
        Text(Point(40, 180), " 9k pkts").draw(win)
        Text(Point(40, 130), " 12k pkts").draw(win)
        Text(Point(40, 80), " 15k pkts").draw(win)
        Text(Point(40, 30), " 18k+ pkts").draw(win)

        # create text and bar for each IPA
        a = 80
        subaddr = 1          
        for ipa in sourcenum:
            whooheight = sourcenum.get(str(ipa))			
            hooheight = whooheight/(18000/292)
            hoheight = 330-hooheight
            print (hoheight)	        

            if hoheight >= 30:
                hoopyheight = hoheight
            else:
                hoopyheight = 30

            bar = Rectangle(Point(a, 330), Point(a + width, hoopyheight))
            bar.setFill("blue")
            bar.draw(win)
            Text(Point(a + width/2, 345), ipa).draw(win)
            Text(Point(a + width/2, hoopyheight-15), str(whooheight) + " packets").draw(win)
            a += width

        input("Press <Enter> to quit")
        win.close()

        makegraph()

if __name__ == "__main__":
    main()