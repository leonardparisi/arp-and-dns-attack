# INSPECT_TARGET = docker container inspect netsec_arp_victim
# PARSE_NETWORK_CONFIG = jq .[0].NetworkSettings.Networks.arp.Gateway
# GATEWAY_IP := $(shell $(INSPECT_TARGET) | $(PARSE_NETWORK_CONFIG))

GATEWAY_MAC = $(shell docker exec netsec_arp_victim ip neigh | tail -1 | cut -d' ' -f5)

create-network:
	docker network create arp
	docker network ls

create-victim:
	xzcat netsec_arp_victim.img.xz | docker load

create-attacker:
	docker build ./attacker -t netsec_arp_attacker
	
run-victim:
	docker run -it --privileged --rm --network arp --name netsec_arp_victim localhost/netsec_arp_victim

run-attacker:
	@docker container inspect netsec_arp_victim | python3 -c "import sys, json, os; network_settings = json.load(sys.stdin)[0]['NetworkSettings']['Networks']['arp'];victim_mac_address = network_settings['MacAddress']; victim_ip_address = network_settings['IPAddress']; gateway_ip_address = network_settings['Gateway']; os.system(f'docker run --rm --network=arp --cap-add=net_raw  --name netsec_arp_attacker netsec_arp_attacker --hwdst {victim_mac_address} --pdst {victim_ip_address} --gwip {gateway_ip_address}')"

run-server:
	docker run -it --privileged --rm --network=arp --name netsec_arp_server  netsec_arp_server

stop:
	docker stop -t 0 netsec_arp_attacker netsec_arp_victim

foo:
	echo $(GATEWAY_MAC)

get_gateway:
	docker exec netsec_arp_victim ip r
