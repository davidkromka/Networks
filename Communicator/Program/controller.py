import threading
import client
import server


class ClientController:
    cl = None

    def start(self, gui, ip, port, fragment):
        self.cl = client.Client(ip, port, fragment, self)
        self.gui = gui

    def write(self, text):
        self.gui.upload_message(text+'\n')

    def send(self, message, file):
        if not self.cl.connected:
            return -1
        self.cl.make_fragment(message, file)

    def get_input(self, entry):
        if entry != '\n':
            entry = entry[:-1]
            self.send(bytes(entry, "utf-8"), False)

    def get_file(self, name):
        if not name:
            return
        entry = open(name, 'rb').read()
        size = len(entry)
        self.write(f'//Názov a cesta k odoslanému súboru: {name}, veľkosť súboru: {size} B.')
        self.send(bytes(name, "utf-8"), True)
        self.send(entry, True)

    def get_answer(self, message):
        self.cl.answers.append(message)
        if not self.cl.connected:
            self.cl.connect_cycle()
        elif 7 in message[1]:
            self.cl.ending()

    def communicate(self):
        if not self.cl.connected:
            self.cl.bind()
        else:
            self.write('Najprv sa odpojte')

    def end_communication(self):
        if self.cl.connected:
            self.cl.end_communication()
        else:
            self.write('//Nie je pripojený')


class ServerController:
    info = None
    gui = None

    def __init__(self, client):
        self.client = client

    def start(self, gui, ip, port, s_ip, s_port):
        self.gui = gui
        self.se = server.Server(ip, port, self, s_ip, s_port)
        threading.Thread(target=self.se.server, daemon=True).start()

    def write(self, text):
        self.gui.upload_message(text)

    def file_path(self, path):
        if path:
            self.gui.upload_message(f'Adresa na ukladanie súborov: {path}')
            self.se.path = path

    def askfile(self):
        return self.gui.askfile()

    def server_answer(self, message):
        self.client.get_answer(message)
