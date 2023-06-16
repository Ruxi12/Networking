# TCP Server
import socket
import logging
import time

# configurarea unui format pentru mesajele de loggging
logging.basicConfig(format = u'[:)LINE:%(lineno)d]# %(levelname)-8s [%(asctime)s]  %(message)s', level = logging.NOTSET)

# stabilirea unui socket de comunicare TCP
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)

# pe portul 10000, la adresa serverului 198.7.0.2
port = 10000
adresa = '198.7.0.2'
server_address = (adresa, port)
sock.bind(server_address)
logging.info("Serverul a pornit pe %s si portnul portul %d", adresa, port)
sock.listen(5)

try:
    while True:
        try:
            logging.info('Asteptam conexiui...')
            conexiune, address = sock.accept()
            logging.info("Handshake cu %s", address)
            time.sleep(2)

            # asteptam mesaje pana ne plictisim
            while True:
                data = conexiune.recv(1024)
                logging.info('Content primit: "%s"', data)
                conexiune.send(b"Server a primit mesajul: " + data)
        finally:
            conexiune.close()
finally:
    sock.close()
