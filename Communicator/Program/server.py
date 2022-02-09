import socket
import threading
import zlib


class Server:
    file_name = ''
    file = b''
    to_analyze = False
    path = None
    phase = 0
    received = []
    fragment_count = 0
    fragment_size = 0

    def __init__(self, ip, port, control, s_ip, s_port):
        self.ip = ip  # IP address of server
        self.port = int(port)  # Port to listen on
        self.control = control
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.bind((self.ip, self.port))
        self.s_ip = s_ip
        self.s_port = s_port

    def server(self):
        while True:
            data, addr = self.s.recvfrom(1472)  # buffer size
            self.received.append(data)
            self.analyze()

    def make_flags(self, flags):
        flag = ''
        for i in range(8):
            if i in flags:
                flag += '1'
            else:
                flag += '0'
        return int(flag, 2).to_bytes(1, 'big')

    def answer(self, seq, check, flags, size):
        self.s.sendto(seq + check + flags + size, (self.s_ip, int(self.s_port)))

    def info(self, message):
        self.control.server_answer(message)
        return

    def analyze(self):
        while self.received:
            message = self.received.pop(0)
            seq = int.from_bytes(message[0:3], 'big')
            check = int.from_bytes(message[3:7], 'big')
            flag = int.from_bytes(message[7:8], 'big')
            size = int.from_bytes(message[8:11], 'big')
            flags = []
            for i in range(0, 32):
                if ((flag >> i) & 1) != ((0 >> i) & 1):
                    flags.append(i)
            # here we have all informations from header
            # check if data is in
            if len(message) == 11:
                if 5 in flags and len(flags) == 1:
                    self.answer(message[0:3], message[3:7], self.make_flags([6]), message[8:11])
                else:
                    self.info([seq, flags])
                continue
            # validate check and answer
            if zlib.crc32(message[11:]) == check:
                self.answer(message[0:3], message[3:7], self.make_flags([6]), message[8:11])
            else:
                self.control.write('//Chyba vo fragmente, žiadam poslať znova.')
                self.answer(message[0:3], message[3:7], self.make_flags([5]), message[8:11])
                continue
            # processing data
            if 3 in flags:  # is fragment
                self.fragment_count += 1
                self.fragment_size += len(message[11:])
                if 5 in flags and 6 in flags:
                    self.file_name += (message[11:].decode("utf-8")).split('/')[-1]
                    continue
                else:
                    self.file += message[11:]
                if 4 in flags: # last fragment
                    size = len(self.file)
                    if 6 in flags:
                        if not self.path:
                            self.path = self.control.askfile()
                        f = open(self.path+'/'+self.file_name, 'wb')
                        f.write(self.file)
                        f.close()
                        self.control.write(f'Prijatý súbor: {self.path}/{self.file_name}')
                        self.file = b''
                        self.file_name = ''
                    else:
                        self.control.write(self.file)
                    self.control.write(f'Počet fragmentov: {self.fragment_count}, veľkosť správy: {size} B, '
                                       f'priemerná veľkosť fragmentu: {self.fragment_size/self.fragment_count} B.')
                    self.fragment_count = 0
            elif 5 in flags and 6 in flags:
                self.file_name = (message[11:].decode("utf-8")).split('/')[-1]

            elif 6 in flags:
                if not self.path:
                    self.path = self.control.askfile()
                f = open(self.path + '/' + self.file_name, 'wb')
                f.write(self.file)
                f.close()
                self.control.write(f'Prijatý súbor: {self.path}/{self.file_name}')
                self.file = b''
                self.file_name = ''

            elif 6 not in flags and 3 not in flags:
                self.control.write(message[11:])

        self.to_analyze = False
        return
