import window

text = ''


def get_mac(mac):
    return (b':'.join(mac[i:i + 2] for i in range(0, len(mac), 2))).decode()


def draw(data, frame):
    global text
    # [order, api_len, real_len, EthernetII, dst_MAC, src_MAC, ethertype]
    order, api_len, real_len, type1, dmac, smac, type2 = data
    # formatovanie textu na vypis
    twins = b' '.join(frame[i:i + 2] for i in range(0, len(frame), 2))
    splited = b' '.join(twins[i:i + 24] for i in range(0, len(twins), 24))
    lines = b'\n'.join(splited[i:i + 50] for i in range(0, len(splited), 50))
    dmac = b':'.join(dmac[i:i + 2] for i in range(0, len(dmac), 2))
    smac = b':'.join(smac[i:i + 2] for i in range(0, len(smac), 2))

    text = (f'Rámec {order}\n'
            f'Dĺžka rámca poskytnutá pcap API: {api_len} B\n'
            f'Dĺžka rámca prenášaného po médiu: {real_len} B\n'
            f'{type1}\n'
            f'Cieľová MAC adresa: {dmac.decode()}\n'
            f'Zdrojová MAC adresa: {smac.decode()}\n'
            f'{type2}\n'
            f'{text}\n' + lines.decode().upper() + '\n' + 47 * '-' + '\n')
    window.draw(text)
    text = ''


def ip_convert(ip):
    ip.decode()
    result = ''
    for i in range(0, 8, 2):
        result += str(int(ip[i:i + 2], 16)) + '.'
    return result[:-1]


def draw_ip(src, dst, protocol):
    global text
    src = ip_convert(src)
    dst = ip_convert(dst)
    text = f'Zdrojová IP adresa: {src}\nCieľová IP adresa: {dst}\n{protocol}\n'


def ip_result(addr_list, count_list):
    i = 0
    for item in addr_list:
        addr_list[i] = ip_convert(item)
        i += 1
    top_count = max(count_list)
    top_ip = count_list.index(top_count)
    result = 'IP adresy vysielajúcich uzlov:\n' + '\n'.join(addr_list) + \
             '\nAdresa uzla s najväčším počtom odoslaných paketov:' + \
             addr_list[top_ip] + ' ' + str(top_count) + ' paketov.\n\n'
    return result


def draw_arp(op, smac, sip, dmac, dip):
    global text
    if op.decode() == '0001':
        op = 'request'
    else:
        op = 'reply'
    sip = ip_convert(sip)
    dip = ip_convert(dip)
    smac = get_mac(smac)
    dmac = get_mac(dmac)
    text = f'{op}\n' \
           f'Zdrojová MAC adresa: {smac}\n' \
           f'Zdrojová IP adresa {sip}\n' \
           f'Cieľová MAC adresa {dmac}\n' \
           f'Cieľová IP adresa {dip}\n'


def draw_udp_tcp(spn, sport, sdp, dport, protocol, flag):
    global text
    text = text + f'Zdrojový port: {int(spn, 16)} {sport}\n' f'Cieľový port: {int(sdp, 16)} {dport}\n{protocol}\n'
    if flag != '':
        text += f'{flag}\n'


def arp_com(order, lenght, mac, ip):
    mac = get_mac(mac)
    ip = ip_convert(ip)
    window.draw(f'ARP komunikácia číslo {order}\n'
                f'Počet rámcov v komunikácii: {lenght}\n'
                f'Nájdena MAC: {mac} k IP: {ip}\n\n')
    window.textfield.see('end')


def draw_icmp(type_icmp):
    global text
    text = text + type_icmp+'\n'


def icmp_com(order, ip1, ip2):
    window.draw(f'ICMP komunikácia číslo {order}\n'
                f'medzi adresami {ip_convert(ip1)} a {ip_convert(ip2)}\n\n')
    window.textfield.see('end')


def line():
    window.draw('Bez páru:\n\n')
