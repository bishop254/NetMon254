import tkinter as tk
from tkinter import ttk
from tkinter.messagebox import showinfo

import subprocess
from subprocess import *

# root = tk.Tk()
# root.title('Tree-view')
# root.geometry('650x350')

# columns = ['#1', '#2', '#3']

# tree = ttk.Treeview(root, columns=columns, show='headings')

# tree.heading('#1', text='First-name')
# tree.heading('#2', text='Last-name')
# tree.heading('#3', text='Email')

# contacts = []
# for n in range(1,100):
#     contacts.append((f'first {n}', f'last {n}', f'email{n}@xxx.com'))
    
# for contact in contacts:
#     tree.insert('', tk.END, values=contact)

# def item_selected(event):
#     for selected_item in tree.selection():
#         item = tree.item(selected_item)
#         record = item['values']
#         showinfo(title='Information', message=','.join(record))

# tree.bind('<<TreeviewSelect>>', item_selected)

# tree.grid(row=0, column=0, sticky='nsew')

# scrollbar = ttk.Scrollbar(root, orient=tk.VERTICAL, command=tree.yview)
# tree.configure(yscroll=scrollbar.set)
# scrollbar.grid(row=0, column=1, sticky='ns')

# root.mainloop()

# create root window
root = tk.Tk()
root.title('Treeview Demo - Hierarchical Data')
root.geometry('400x200')

# configure the grid layout
root.rowconfigure(0, weight=1)
root.columnconfigure(0, weight=1)


# create a treeview
tree = ttk.Treeview(root)
tree.heading('#0', text='Departments', anchor='w')

resp1 = subprocess.run(["sudo", "iwlist", 'wlo1', "scanning"], capture_output=True)
resp2 = subprocess.run(["sudo", "iwlist", 'wlo1', "rate"], capture_output=True)
# return (resp1.stdout, resp2.stdout)

arr1 = []
arr1.append(resp1.stdout)
print(arr1)

# adding data
tree.insert('', tk.END, text='Peers', iid=0, open=False)
tree.insert('', tk.END, text='Rate', iid=1, open=False)
tree.insert('', tk.END, text='AP', iid=2, open=False)
tree.insert('', tk.END, text='Channel', iid=3, open=False)
tree.insert('', tk.END, text='Bitrate', iid=4, open=False)

# adding children of first node
tree.insert('', tk.END, text=str(resp1.stdout), iid=5, open=True)
tree.insert('', tk.END, text=resp2.stdout, iid=6, open=False)
tree.move(5, 0, 0)
tree.move(6, 1, 1)

# place the Treeview widget on the root window
tree.grid(row=0, column=0, sticky='nsew')

# run the app
root.mainloop()