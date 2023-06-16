# TCP client
import socket
import logging
import time
import sys
import random

# configurarea unui format pentru mesajele de loggging
logging.basicConfig(format = u'[LINE:%(lineno)d]# %(levelname)-8s [%(asctime)s]  %(message)s', level = logging.NOTSET)

# stabilirea unui socket de comunicare TCP
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)

port = 10000
adresa = '198.7.0.2'
server_address = (adresa, port)
# mesaj = sys.argv[1]

jokes = [
    "Why don't scientists trust atoms? Because they make up everything!",
    "Did you hear about the mathematician who's afraid of negative numbers? He will stop at nothing to avoid them!",
    "Why don't skeletons fight each other? They don't have the guts!",
    "Why don't eggs tell jokes? Because they might crack up!",
    "I'm reading a book about anti-gravity. It's impossible to put down!",
    "Why did the scarecrow win an award? Because he was outstanding in his field!",
    "How does a penguin build its house? Igloos it together!",
    "What did one wall say to the other wall? I'll meet you at the corner!",
    "Why don't bicycles fall over? Because they're two-tired!",
    "Why did the tomato turn red? Because it saw the salad dressing!"
]

# alege ca sa ii trimitem serverului
def messageGenerator():
    return jokes[random.randint(0,9)]

try:
    logging.info('Handshake cu %s', str(server_address))
    sock.connect(server_address)
    time.sleep(3)

    # glumeste clientul pana se plictiseste si el
    while True:
        mesaj = messageGenerator()
        sock.send(mesaj.encode('utf-8'))

        data = sock.recv(1024)
        logging.info('Content primit: "%s"', data)
        time.sleep(1)

finally:
    logging.info('closing socket')
    sock.close()