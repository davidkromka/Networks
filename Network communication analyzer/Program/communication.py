import gui
import pcap_analyze
import window

http_list = []
https_list = []
telnet_list = []
ssh_list = []
ftpc_list = []
ftpd_list = []
tftp_list = []
icmp_list = []
arp_list = []


def arp_com():
    i = 0
    com = 0
    temp = []
    used = []
    # if reply found, find request
    for item in arp_list:
        if item[7].decode() == '0002':
            for q in range(i):
                if arp_list[q][7].decode() == '0001' and arp_list[q][8].decode() == item[10].decode() \
                        and arp_list[q][9].decode() == item[11].decode():
                    temp.append(arp_list[q])
                    used.append(arp_list[q])
        if len(temp) != 0:
            com += 1
            temp.append(item)
            used.append(item)
            gui.arp_com(com, len(temp), item[8], item[9])
            for frame in temp:
                gui.draw_arp(frame[7], frame[8], frame[9], frame[10], frame[11])
                gui.draw(frame[:7], frame[12])
                gui.text = ''
            temp.clear()
            gui.text = ''
        i += 1
    gui.line()
    for frame in arp_list:
        if frame not in used:
            gui.draw_arp(frame[7], frame[8], frame[9], frame[10], frame[11])
            gui.draw(frame[:7], frame[12])
            gui.text = ''


def com_start(prot_list, index):
    def ack(q):
        # searching for tcp communication 3way handshake
        for s in range(q, len(prot_list)):
            if ({prot_list[s][7], prot_list[s][10]} == {prot_list[q][8], prot_list[q][11]}
                and {prot_list[s][8], prot_list[s][11]} == {prot_list[q][7], prot_list[q][10]}) and \
                    'ACK' in prot_list[s][13]:
                result.append(s)
                return result

        return -1

    def acksyn(i):
        for q in range(i, len(prot_list)):
            if ({prot_list[q][7], prot_list[q][10]} == {prot_list[i][8], prot_list[i][11]}
                and {prot_list[q][8], prot_list[q][11]} == {prot_list[i][7], prot_list[i][10]}) and \
                    'SYN' in prot_list[q][13] and 'ACK' in prot_list[q][13]:
                result.append(q)
                return ack(q)

        return -1

    def syn():
        for i in range(index, len(prot_list)):
            if 'SYN' in prot_list[i][13]:
                result.append(i)
                return acksyn(i)

        return -1

    result = []
    return syn()


# [order, len_api, len_real, eth, dmac, smac, ipv4, sip, dip, tcp, sport, dport, http, flag]
def get_com(start, prot_list):
    com_open = com_start(prot_list, start)
    comm = []
    index = 2
    flag = 0
    complete = False
    if com_open == -1:
        return -1
    for i in range(3):
        comm.append(prot_list[com_open[i]])
    # decide if frame is in the communication
    for q in range(com_open[2] + 1, len(prot_list)):
        if ({prot_list[q][7], prot_list[q][10]} == {comm[index][8], comm[index][11]}
            and {prot_list[q][8], prot_list[q][11]} == {comm[index][7], comm[index][10]}) \
                or ({prot_list[q][7], prot_list[q][10]} == {comm[index][7], comm[index][10]}
                    and {prot_list[q][8], prot_list[q][11]} == {comm[index][8], comm[index][11]}):
            comm.append(prot_list[q])
            index += 1
            # checking terminated communication if they are complete
            if 'RST' in prot_list[q][13]:
                complete = True
                break
            elif flag == 0 and 'FIN' in prot_list[q][13]:
                flag = 1
                continue
            elif flag == 1:
                if 'FIN' in prot_list[q][13] and 'ACK' in prot_list[q][13]:
                    flag = 2
                    continue
                elif 'ACK' in prot_list[q][13]:
                    flag = 3
                    continue
                else:
                    flag = 0
            elif flag == 2:
                if 'ACK' in prot_list[q][13]:
                    complete = True
                    break
                else:
                    flag = 0
            elif flag == 3:
                if 'FIN' in prot_list[q][13]:
                    flag = 2
                    continue
                else:
                    flag = 0
    return [comm, complete, com_open[0] + 1]


def communication(prot_list):
    def draw(com, flag):
        window.textfield.see('end')
        if len(com) > 20:
            com = com[:10] + com[len(com) - 10:]
        if flag == 1:
            window.draw('Kompletná komunikácia:\n\n')
        else:
            window.draw('Nekompletná komunikácia:\n\n')
        for frame in com:
            gui.draw_ip(frame[7], frame[8], frame[9])
            gui.draw_udp_tcp(frame[10], '', frame[11], '', frame[12], frame[13])
            gui.draw(frame[:7], frame[14])

    complete = False
    incomplete = False
    index = 0
    # calling get_com with different index to get complet and incomplet communication
    while (not complete or not incomplete) and index < len(prot_list) - 1:
        result = get_com(index, prot_list)
        if result == -1:
            index += 1
            continue
        if result[1] and complete is False:
            complete = True
            draw(result[0], 1)
        elif not result[1] and incomplete is False:
            incomplete = True
            draw(result[0], 0)
        index = result[2]


def http_com():
    window.draw('HTTP komunikácia\n\n')
    communication(http_list)


def https_com():
    window.draw('HTTPS komunikácia\n\n')
    communication(https_list)


def ssh_com():
    window.draw('SSH komunikácia\n\n')
    communication(ssh_list)


def telnet_com():
    window.draw('TELNET komunikácia\n\n')
    communication(telnet_list)


def ftpc_com():
    window.draw('FTP-control komunikácia\n\n')
    communication(ftpc_list)


def ftpd_com():
    window.draw('FTP-data komunikácia\n\n')
    communication(ftpd_list)


def tftp_com():
    i = 0
    com = {}
    pair = []
    # sorting frames to communication
    for frame in tftp_list:
        if str(frame[10] + frame[11]) in com or str(frame[11] + frame[10]) in com:
            pair[com[str(frame[10] + frame[11])]].append(frame)
        else:
            pair.append([])
            com[str(frame[10] + frame[11])] = i
            com[str(frame[11] + frame[10])] = i
            i += 1
            pair[com[str(frame[10] + frame[11])]].append(frame)
    order = 1
    # sending frames to write
    for frame in pair:
        for item in frame:
            if item[11].decode() == '0045':
                window.draw(f'TFTP komunikácia číslo {order}\n\n')
                window.textfield.see('end')
                order += 1
            gui.draw_udp_tcp(item[10], '', item[11], '', item[12], '')
            gui.draw(item[:7], item[14])


def icmp_com():
    i = 0
    com = {}
    pair = []
    for frame in icmp_list:
        if str(frame[7] + frame[8]) in com or str(frame[8] + frame[7]) in com:
            pair[com[str(frame[7] + frame[8])]].append(frame)
        else:
            pair.append([])
            com[str(frame[7] + frame[8])] = i
            com[str(frame[8] + frame[7])] = i
            i += 1
            pair[com[str(frame[7] + frame[8])]].append(frame)
    order = 1
    for frame in pair:
        gui.icmp_com(order, frame[0][7], frame[0][8])
        order += 1
        for item in frame:
            gui.draw_ip(item[7], item[8], item[9])
            gui.draw_icmp(item[10])
            gui.draw(item[:7], item[11])
            gui.text = ''


def arpc(result, frame):
    op = frame[40:44]
    smac = frame[44:56]
    sip = frame[56:64]
    dmac = frame[64:76]
    dip = frame[76:84]
    result.extend([op, smac, sip, dmac, dip])
    result.append(frame)
    arp_list.append(result)
    gui.draw_arp(op, smac, sip, dmac, dip)
    gui.draw(result[:7], frame)


def icmp(result, frame):
    task = pcap_analyze.find(frame, 68, 70, '#icmp')
    result.append(task)
    gui.draw_icmp(task)
    gui.draw(result[:7], frame)
    result.append(frame)
    icmp_list.append(result)


def http(result, frame):
    result.append(frame)
    http_list.append(result)


def https(result, frame):
    result.append(frame)
    https_list.append(result)


def ssh(result, frame):
    result.append(frame)
    ssh_list.append(result)


def telnet(result, frame):
    result.append(frame)
    telnet_list.append(result)


def ftp_data(result, frame):
    result.append(frame)
    ftpd_list.append(result)


def ftp_control(result, frame):
    result.append(frame)
    ftpc_list.append(result)


def tftp(result, frame):
    result.append(frame[84:88])
    result.append(frame)
    tftp_list.append(result)


def zero():
    http_list.clear()
    https_list.clear()
    telnet_list.clear()
    ssh_list.clear()
    ftpc_list.clear()
    ftpd_list.clear()
    tftp_list.clear()
    icmp_list.clear()
    arp_list.clear()


def write_com():
    protocol = {
        'HTTP': http_com,
        'HTTPS': https_com,
        'TELNET': telnet_com,
        'SSH': ssh_com,
        'FTP RIADIACE': ftpc_com,
        'FTP DÁTOVÉ': ftpd_com,
        'TFTP': tftp_com,
        'ICMP': icmp_com,
        'ARP': arp_com
    }
    protocol[window.com_choose.get()]()
