import socket
import threading
import zlib
import time


class Client:
    to_send = []
    connected = False
    is_name = True
    answers = []
    recently_sent = None
    fail = True
    phase = 0
    up = None
    stop_thread = False
    start = time.time()
    keep_count = 0
    count = 0

    def __init__(self, ip, port, fragment, control):
        self.ip = ip
        self.port = int(port)
        if int(fragment) < 1461:
            self.fragment = int(fragment)
        else:
            self.fragment = 1461
        self.control = control
        self.seq = 0
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def header(self, check, flags, size):  # seq 3B, check 4B, flags 1B, size 3B
        # 00000001 - SYN
        # 00000010 - ACK
        # 00000100 - NACK
        # 00001000 – FRA
        # 00010000 - END
        # 00100000 - UP
        # 01000000 - TYP
        # 10000000 – FIN
        seq = self.seq.to_bytes(3, 'big')
        if self.seq < 2 ** 24 - 1:
            self.seq += 1
        else:
            self.seq = 0
        check = check.to_bytes(4, 'big')
        flag = ''
        for i in range(8):
            if i in flags:
                flag += '1'
            else:
                flag += '0'
        flag = int(flag, 2).to_bytes(1, 'big')
        size = size.to_bytes(3, 'big')
        header = seq + check + flag + size
        return header

    def connecting(self):
        if not self.answers:
            return -1
        if 0 in self.answers[0][1] and len(self.answers[0][1]) == 1 and self.phase == 0:  # got syn, send syn ack
            self.to_send.append(self.header(0, [6, 7], 0))
            self.client()
            self.phase = 1
        elif 1 in self.answers[0][1] and len(self.answers[0][1]) == 1 and self.phase == 1:  # got ack, connectet
            self.connected = True
            self.up = threading.Thread(target=self.keepalive, daemon=True).start()
            self.control.write('//Successfully connected')
        elif 0 in self.answers[0][1] and 1 in self.answers[0][1] and self.phase == 1:  # got syn ack, send ack
            self.to_send.append(self.header(0, [6], 0))
            self.client()
            self.connected = True
            self.up = threading.Thread(target=self.keepalive, daemon=True).start()
            self.control.write('//Successfully connected')
        self.answers.clear()
        return 0

    def make_fragment(self, message, file):
        size = len(message)
        if size > self.fragment:
            count = 0
            for i in range(0, size, self.fragment):
                count += 1
                data = message[i:i + self.fragment]
                check = zlib.crc32(data)
                flags = [4]
                if i >= size - self.fragment:
                    flags.append(3)
                    self.control.write(f'Správa bola rozdelená na {count} fragmentov s veľkosťou {self.fragment} B.')
                if file is True:
                    flags.append(1)
                    if self.is_name:
                        flags.append(2)
                header = self.header(check, flags, size)
                self.to_send.append(header + data)
        else:
            check = zlib.crc32(message)
            flags = []
            if file:
                flags.append(1)
                if self.is_name:
                    flags.append(2)
            header = self.header(check, flags, size)
            self.to_send.append(header + message)
        if file:
            if self.is_name:
                self.is_name = False
            else:
                self.is_name = True
        self.client()

    def send(self, message):
        self.start = time.time()
        self.s.sendto(message, (self.ip, self.port))
        self.check(message)

    def check(self, entry):
        wait = time.time()
        count = 0
        while self.connected and time.time() - wait < 6:
            count += 1
            if len(self.answers) != 0:
                if int.from_bytes(entry[0:3], 'big') == self.answers[0][0]:
                    self.start = time.time()
                    if 1 in self.answers[0][1]:
                        del self.answers[0]
                        return
                    elif 2 in self.answers[0][1]:
                        del self.answers[0]
                        self.control.write('//Chyba vo fragmente, posielam znova')
                        self.send(self.recently_sent)
                    self.answers.clear()
                    if self.count > 5:
                        self.count = 0
                        self.connected = False
                        self.phase = 0
                        self.control.write('//Disconnected')
            if time.time() - wait > 3:
                if self.count > 5:
                    self.count = 0
                    self.connected = False
                    self.phase = 0
                    self.control.write('//Disconnected')
                    return
                self.count += 1
                self.control.write('//Timeout, posielam znova')
                self.send(self.recently_sent)
                return
        return

    def keepalive(self):
        while not self.stop_thread and self.connected:
            if time.time() - self.start > 10:
                self.keep_count += 1
                entry = self.header(0, [2], 0)
                self.recently_sent = entry
                self.send(entry)
                start = time.time()
            else:
                self.keep_count = 0

    def client(self):
        while self.to_send:
            entry = self.to_send.pop(0)
            # make mistake in fragment
            if self.connected:
                self.recently_sent = entry
            if self.control.gui.checked.get():
                if self.fail and len(entry) > 11:
                    entry = entry[:11] + (entry[11] - 1).to_bytes(1, 'big') + entry[12:]
                    self.fail = False
                else:
                    self.fail = True
            self.send(entry)
        return

    def bind(self):
        # SYN begin conversation
        self.to_send.append(self.header(0, [7], 0))
        self.client()
        self.phase = 1

    def connect_cycle(self):
        start = time.time()
        while not self.connected:
            time.sleep(0.01)
            if self.connecting() == 0:
                break
            if time.time() - start > 5:
                self.phase = 0
                break
        return

    def end_communication(self):
        entry = self.header(0, [0], 0)
        self.s.sendto(entry, (self.ip, self.port))
        while True:
            if self.answers:
                if 1 in self.answers[0][1]:
                    del self.answers[0]
                    self.phase = 0
                    self.connected = False
                    self.control.write('//Disconnected')
                    return

    def ending(self):
        self.connected = False
        del self.answers[0]
        self.phase = 0
        self.control.write('//Disconnected')
        self.send(self.header(0, [6], 0))
        return
