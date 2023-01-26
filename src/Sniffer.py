import logging
from scapy.all import sniff, Packet
from scapy.layers.dns import DNS

class Sniffer():
    def __init__(self, interface: str):
        self._interface = interface
        self._packet_listeners = {}

    def start(self):
        sniff(quiet=True, store=False, iface=self._interface, prn=self._on_packet)

    def add_packet_handler(self, layer: Packet, callback_fn):
        if layer not in self._packet_listeners:
            self._packet_listeners[layer] = []    
        self._packet_listeners[layer].append(callback_fn)
        logging.info(f"Added handler for {layer}")

    def _on_packet(self, packet: Packet):
        for layer, fns in self._packet_listeners.items():
            if layer in packet:
                for fn in fns:
                    fn(packet)