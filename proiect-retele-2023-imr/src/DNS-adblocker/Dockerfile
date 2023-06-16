FROM python:3.8

WORKDIR /app
COPY . /app

COPY domains.txt ./
COPY blocklist.txt ./
COPY adservers.txt ./
COPY facebook.txt ./


RUN pip install scapy
RUN pip install dnspython
RUN pip install matplotlib
RUN pip install flask

USER root

CMD ["python", "./main.py"]

