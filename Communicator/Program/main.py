import controller
import tkinter
from tkinter import filedialog as fd


class Gui:
    info = None
    path = None
    checked = 0

    def gui(self):
        # window settings
        window = tkinter.Tk()
        window.geometry('540x700')
        window.configure(background='white')
        window.title('Communicator')

        # window components

        # grid
        frame = tkinter.Frame(window)
        frame.grid(row=0)

        frame2 = tkinter.Frame(window)
        frame2.grid(row=1, pady=20)

        frame3 = tkinter.Frame(window, bg='white')
        frame3.grid(row=2, pady=20)

        # configure the grid
        frame3.columnconfigure(0, weight=6)
        frame3.columnconfigure(1, weight=3)

        frame.columnconfigure(0, weight=1)
        frame.columnconfigure(1, weight=3)
        frame.columnconfigure(2, weight=1)
        frame.columnconfigure(3, weight=3)
        frame.columnconfigure(4, weight=1)

        # server_ip
        server_ip_label = tkinter.Label(frame, text="Server IP:")
        server_ip_label.grid(column=0, row=0, padx=5, pady=3)

        server_ip_entry = tkinter.Entry(frame)
        server_ip_entry.insert(tkinter.END, '192.168.0.189')
        server_ip_entry.grid(column=1, row=0, padx=5, pady=3)

        # server_port
        server_port_label = tkinter.Label(frame, text="Server PORT:")
        server_port_label.grid(column=2, row=0, padx=5, pady=3)

        server_port_entry = tkinter.Entry(frame)
        server_port_entry.insert(tkinter.END, 65432)
        server_port_entry.grid(column=3, row=0, padx=5, pady=3)

        # client_ip
        client_ip_label = tkinter.Label(frame, text="Client IP:")
        client_ip_label.grid(column=0, row=2, padx=5, pady=3)

        client_ip_entry = tkinter.Entry(frame)
        client_ip_entry.insert(tkinter.END, '192.168.0.186')
        client_ip_entry.grid(column=1, row=2, padx=5, pady=3)

        # client_port
        client_port_label = tkinter.Label(frame, text="Client PORT:")
        client_port_label.grid(column=2, row=2, padx=5, pady=3)

        client_port_entry = tkinter.Entry(frame)
        client_port_entry.insert(tkinter.END, 65432)
        client_port_entry.grid(column=3, row=2, padx=5, pady=3)

        #   fragment label
        fragment_label = tkinter.Label(frame, text="Fragment size:")
        fragment_label.grid(column=0, row=3, padx=5, pady=3)

        fragment_entry = tkinter.Entry(frame)
        fragment_entry.insert(tkinter.END, 1000)
        fragment_entry.grid(column=1, row=3, padx=5, pady=3)

        #   sliding window label
        sw_label = tkinter.Label(frame, text="SW size:")
        sw_label.grid(column=2, row=3, padx=5, pady=3)

        sw_entry = tkinter.Entry(frame)
        sw_entry.grid(column=3, row=3, padx=5, pady=3)

        save_button = tkinter.Button(frame, text='Load', width=12,
                                     command=lambda: [client_controller.start(self, client_ip_entry.get(),
                                                                              client_port_entry.get(),
                                                                              fragment_entry.get()),
                                                      server_controller.start(self, server_ip_entry.get(),
                                                                              server_port_entry.get(),
                                                      client_ip_entry.get(),
                                                      client_port_entry.get(),
                                     )])
        save_button.grid(column=4, row=0, pady=3)

        connect_btn = tkinter.Button(frame, text='Communicate!', height=2,
                                     command=lambda: [client_controller.communicate()])
        connect_btn.grid(column=4, row=1, pady=3, rowspan=3)

        end_button = tkinter.Button(frame, text='End', width=12,
                                    command=lambda: client_controller.end_communication())
        end_button.grid(column=4, row=4, pady=3)

        path_button = tkinter.Button(frame, text='Path to save files', width=12,
                                     command=lambda: [server_controller.file_path(fd.askdirectory())])
        path_button.grid(column=0, row=4, pady=3)

        self.path = tkinter.Label(frame)
        self.path.grid(column=1, row=4, pady=3)

        # text area
        self.info = tkinter.Text(frame2, width=60, borderwidth=1, relief="solid")
        self.info.grid()

        # buttons
        send_input = tkinter.Text(frame3, width=45, height=4, borderwidth=1, relief="solid")
        send_input.grid(column=0, row=0)

        send_btn = tkinter.Button(frame3, text='Send', width=10, height=3,
                                  command=lambda: [client_controller.get_input(send_input.get("1.0", "end")),
                                                   self.info.insert(tkinter.END, '\n'+send_input.get("1.0", "end")),
                                                   send_input.delete("1.0", "end")])
        send_btn.grid(column=1, row=0, padx=20)

        file_btn = tkinter.Button(frame3, text='File', width=10,
                                  command=lambda: client_controller.get_file(fd.askopenfilename()))
        file_btn.grid(column=1, row=1, padx=20)

        self.checked = tkinter.IntVar()
        checkbox_label = tkinter.Label(frame3, text="Mistake:").grid(column=1, row=2, padx=20)
        checkbox = tkinter.Checkbutton(frame3, text="Mistake", variable=self.checked).grid(column=1, row=2, padx=20)


        window.mainloop()

    def upload_message(self, text):
        self.info.insert(tkinter.END, text)

    def askfile(self):
        return fd.askdirectory()


if __name__ == "__main__":
    client_controller = controller.ClientController()
    server_controller = controller.ServerController(client_controller)
    Gui().gui()
