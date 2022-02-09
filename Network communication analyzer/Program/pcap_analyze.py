import gui
import communication

file = open('protocols.txt')  # textovy subor s protokolmi
addr_list = []
count_list = []
port_list = []


def find(frame, n1, n2, sign):
    file.seek(0)
    f_hash = ''
    for line in file:
        if line.find('#') >= 0:
            f_hash = line[:-1]
        if line.find(frame[n1:n2].decode()) >= 0 and f_hash == sign:
            return ((line.split(':'))[1])[:-1]
    return 'Neznámy'


def ip_result():
    return gui.ip_result(addr_list, count_list)


def tcp(result, frame):
    flag_list = {4: 'ACK', 3: 'PSH', 2: 'RST', 1: 'SYN', 0: 'FIN'}
    flag_bin = (bin(int(frame[92:96], 16)))[12:]
    flag_bin = (flag_bin[::-1])[:5]
    flag = []
    for i in range(len(flag_bin)):
        if flag_bin[i] == '1':
            flag.append(flag_list[i])
    sport = find(frame, 68, 72, '#tcp')
    dport = find(frame, 72, 76, '#tcp')
    if sport == 'Neznámy':
        protocol = dport
    else:
        protocol = sport
    result.extend(([frame[68:72], frame[72:76], protocol, flag]))
    if frame[68:72].decode() == '0050' or frame[72:76].decode() == '0050':
        communication.http(result, frame)
    if frame[68:72].decode() == '01bb' or frame[72:76].decode() == '01bb':
        communication.https(result, frame)
    if frame[68:72].decode() == '0016' or frame[72:76].decode() == '0016':
        communication.ssh(result, frame)
    if frame[68:72].decode() == '0017' or frame[72:76].decode() == '0017':
        communication.telnet(result, frame)
    if frame[68:72].decode() == '0014' or frame[72:76].decode() == '0014':
        communication.ftp_data(result, frame)
    if frame[68:72].decode() == '0015' or frame[72:76].decode() == '0015':
        communication.ftp_control(result, frame)
    gui.draw_udp_tcp(frame[68:72], sport, frame[72:76], dport, protocol, flag)
    gui.draw(result[:7], frame)


def udp(result, frame):
    sport = find(frame, 68, 72, '#udp')
    dport = find(frame, 72, 76, '#udp')
    if sport == 'Neznámy':
        protocol = dport
    else:
        protocol = sport
    result.extend(([frame[68:72], frame[72:76], protocol]))

    if frame[72:76].decode() in port_list:
        port_list.append(frame[68:72].decode())
        protocol, result[12] = 'TFTP', 'TFTP'
        communication.tftp(result, frame)
    if frame[68:72].decode() == '0045' or frame[72:76].decode() == '0045':
        port_list.append(frame[68:72].decode())
        protocol, result[12] = 'TFTP', 'TFTP'
        communication.tftp(result, frame)
    gui.draw_udp_tcp(frame[68:72], sport, frame[72:76], dport, protocol, '')
    gui.draw(result[:7], frame)


def ipv4(result, frame):
    global addr_list, count_list  # for list of all source ip and count
    ip_src = frame[52:60]
    ip_dst = frame[60:68]
    if ip_src in addr_list:
        count_list[addr_list.index(ip_src)] += 1
    elif ip_src not in addr_list:
        addr_list.append(ip_src)
        count_list.append(1)
    protocol = find(frame, 46, 48, '#ip')
    result.extend([ip_src, ip_dst, protocol])
    gui.draw_ip(ip_src, ip_dst, protocol)
    # inner protocols for analyse
    if frame[46:48].decode() == '11':
        udp(result, frame)
    elif frame[46:48].decode() == '06':
        tcp(result, frame)
    elif frame[46:48].decode() == '01':
        communication.icmp(result, frame)
    else:
        gui.draw(result[:7], frame)


def get_type(result, frame):
    if int(frame[24:28], 16) > 1500:  # if yes, Ethernet II
        # [order, api_len, real_len, EthernetII, dst_MAC, src_MAC, ethertype]
        result.extend(['EthernetII', frame[0:12], frame[12:24], find(frame, 24, 28, '#ethertype')])
        if frame[24:28].decode() == '0800':
            ipv4(result, frame)
        elif frame[24:28].decode() == '0806':
            communication.arpc(result, frame)
        else:
            gui.draw(result, frame)
    else:  # LLC
        llc_t = find(frame, 28, 30, '#sap')
        if frame[28:30].decode() == 'aa':
            # [order, api_len, real_len, LLC + SNAP, dst_MAC, src_MAC, ethertype]
            result.extend([llc_t, frame[0:12], frame[0:24], find(frame, 40, 44, '#ethertype')])
        elif frame[28:30].decode() == 'ff':
            # [order, api_len, real_len, LLC RAW, dst_MAC, src_MAC, IPX]
            result.extend([llc_t, frame[0:12], frame[0:24], 'IPX'])
        else:
            # [order, api_len, real_len, LLC, dst_MAC, src_MAC, sap]
            result.extend(['IEEE 802.3 LLC', frame[0:12], frame[0:24], llc_t])
        gui.draw(result, frame)


def frame_len(result, frame):
    api_len = int(len(frame) / 2)
    if api_len < 60:
        real_len = 64
    else:
        real_len = api_len + 4
    result.extend([api_len, real_len])  # [order, ap_len, real_len]
    get_type(result, frame)


def analyze(order, frame):
    result = [order]
    frame_len(result, frame)  # [order]
