import tkinter
from tkinter import filedialog
from tkinter import scrolledtext
from tkinter import ttk
import scapy.all as scp
import communication
import gui
import pcap_analyze


def draw(data):
    textfield.insert('end', data)
    canvas.update()


def ask_file():
    communication.zero()
    if pcap_analyze.file.closed:
        pcap_analyze.file = open(pcap_analyze.file.name)
    textfield.config(state='normal')
    textfield.delete('1.0', tkinter.END)
    order = 1
    # choosing .pcap file
    file_path = tkinter.filedialog.askopenfilename(filetypes=[('pcap files', '*.pcap')])
    if file_path == '':
        return
    canvas.title(file_path)
    file = scp.rdpcap(file_path)
    # sending frames for analyse
    for frame in file:
        frame = scp.bytes_hex(frame)
        pcap_analyze.analyze(order, frame)
        order += 1
        gui.text = ''
    draw(pcap_analyze.ip_result())
    pcap_analyze.addr_list = []
    pcap_analyze.count_list = []
    communication.arp = []
    pcap_analyze.file.close()


# Searching for frame according number
def search():
    to_search = search_insert.get()
    if to_search:
        found = textfield.search(to_search, '1.0', stopindex=tkinter.END)
        if found:
            textfield.see(found)


# creating GUI
canvas = tkinter.Tk()
canvas.geometry("900x700")

textfield = tkinter.scrolledtext.ScrolledText(canvas, width=80, height=35, font=('monaco', 11))
textfield.pack(side=tkinter.TOP)

bar = tkinter.Frame(canvas)
bar.pack(side=tkinter.TOP)

insert_button = tkinter.Button(bar, text='Vyber súbor', command=ask_file)
insert_button.pack(side=tkinter.LEFT)

search_insert = tkinter.Entry(bar)
search_insert.pack(side=tkinter.LEFT, padx=2)

search_button = tkinter.Button(bar, text='Skoč', command=search)
search_button.pack(side=tkinter.LEFT, padx=(0, 200))

text_var = tkinter.StringVar
com_choose = ttk.Combobox(bar, textvariable=text_var)
com_choose.pack(side=tkinter.LEFT)
com_choose['values'] = ('HTTP', 'HTTPS', 'TELNET',
                        'SSH', 'FTP RIADIACE', 'FTP DÁTOVÉ',
                        'TFTP', 'ICMP', 'ARP')
com_choose.current(0)

com_button = tkinter.Button(bar, text='Píš', command=communication.write_com)
com_button.pack(side=tkinter.LEFT)


def start():
    tkinter.mainloop()
