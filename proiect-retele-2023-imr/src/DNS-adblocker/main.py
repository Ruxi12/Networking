import socket
from scapy.layers.dns import DNS, DNSRR
import dns.resolver as dns_resolver

# Change this line to use the correct blocklist file
with open("blocklist.txt", "r") as file:
    blocked_sites = [site[8:] for site in file.read().strip().splitlines()]
    f = open("adservers.txt", 'r')
    for _ in range(8):
        next(f)  # Ignore the next line
    for line in f:
        line = line.split()
        blocked_sites.append(line[1])
    f.close()
    f = open("facebook.txt", 'r')
    for _ in range(8):
        next(f)  # Ignore the next line
    for line in f:
        line = line.split()
        blocked_sites.append(line[1])
    f.close()

blocked_sites = blocked_sites[10:]

simple_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, proto=socket.IPPROTO_UDP)
simple_udp.bind(('0.0.0.0', 53))


# metoda care interogheaza serverul de la google pentru a afla adresa corecta ip a domeniului
def ask_google(domain_name, rr_type):
    google_dns = '8.8.8.8'

    # cream o instanta resolver care are setat drept nameserver google dns server
    resolver = dns_resolver.Resolver()
    resolver.nameservers = [google_dns]

    domain_name = domain_name.decode("utf-8")

    # interogam serverul google
    answer = resolver.resolve(domain_name, rdtype=rr_type)
    # realizeaza o lista cu ip-urile rezultate si returneaza primul ip
    ip_addresses = [str(ip) for ip in answer]

    return ip_addresses[0]


# metoda care verifica daca recordul solicitat este de tipul A sau AAAA, adica corespunzator unui ipv4 sau ipv6
def get_type(dns):
    # daca sectiunea de rapsuns din request nu este nula, cauta atributul rr -> resource record
    if dns.an is not None:
        for rr in dns.an:
            if hasattr(rr, 'type'):
                return rr.type

    # daca sectiunea de query nu este vida cauta atributul qd -> question record
    if dns.qd is not None:
        for qd in dns.qd:
            if hasattr(qd, 'qtype'):
                if qd.qtype == 1:  # daca este egal cu 1 -> A: ipv4
                    return 'A'
                elif qd.qtype == 28:  # daca este egal cu 28 -> AAAA: ipv6
                    return 'AAAA'

f = open("domainss.txt", 'w', 0o666)
while True:
    # extrag pachetul de request si adresa sursa a acestuia
    request, adresa_sursa = simple_udp.recvfrom(65535)

    # contruiesc un obiect de tip scapy, pentru a manipula mai usor requesturile dns
    packet = DNS(request)
    dns = packet.getlayer(DNS)

    # get the tipe of record A or AAAA
    rr_type = get_type(dns)
    # set the ip coresponding to the answer given to ad sites accordingly 
    if rr_type == 'AAAA':
        block_ip = '::'
    else:
        block_ip = '0.0.0.0'

    # verific daca requestul acesta dns este de tipul interogare nume domeniu - ipv4
    if dns is not None and dns.opcode == 0:

        # extrage din sectiunea de intergoare din requestu dns, numele domeniului cautat
        queried_domain = dns.qd.qname.decode("utf-8")

        print("Queried domain: ", queried_domain)
        if any(site in queried_domain for site in blocked_sites):

            print(dns.qd.qname.decode("utf-8"))
            f.write(dns.qd.qname.decode("utf-8"))
            f.write("\n")
            # este creat un obiect de tip dns record (DNSRR)
            dns_answer = DNSRR(
                rrname=dns.qd.qname,  # numele domeniului interogat
                ttl=10 if rr_type == 'AAAA' else 0,  # time to live este setat la 0 -> queryul nu trebuie salvat
                type=rr_type,  # tipul recordului: ipv4
                rclass="IN",  # clasa recordului DNS: internet class
                rdata=block_ip  # raspunsul interogarii, siteul este un ad -> rezultat = 0.0.0.0
            )

        # altfel, siteul curent nu este un ad, va fi intors un record cu adresa lui ip corecta
        else:
            # try-catch block to bypass No Response errors
            try:
                dns_answer = DNSRR(
                    rrname=dns.qd.qname,
                    ttl=330,  # time to live este setat la 330 -> raspunsul este cacheuit aprox 5 minute
                    type=rr_type,
                    rclass="IN",

                    # adresa corecta a siteului de interogat
                    rdata=ask_google(dns.qd.qname, rr_type)
                )

            except dns_resolver.NoAnswer:
                dns_answer = DNSRR(
                    rrname=dns.qd.qname,
                    ttl=0,
                    type=rr_type,
                    rclass="IN",
                    rdata=block_ip
                )

        # este contruit raspunsul dns final
        dns_response = DNS(
            id=packet[DNS].id,
            qr=1,  # id-ul requestului original, din headerul interogarii
            aa=0,  # nu e authorative answer ?
            rcode=0,  # statusul raspunsului: 0 -> fara eroare
            qd=packet.qd,  # interogarea propriu-zisa din requetsul original
            an=dns_answer  # raspunsul construit anterior, fie o adresa ip a domeniului, fie 0.0.0.0 daca este reclama
        )

        print('response:')
        print(dns_response.show())
        simple_udp.sendto(bytes(dns_response), adresa_sursa)

simple_udp.close()

f.close()
os.chmod("domains.txt", 0o666)
