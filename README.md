1. Create the network

```sh
create-network
```

2. Download `netsec_arp_victim.img.xz` from Canvas and place in root of repo

3. Create attacker and victim container images

```sh
create-victim
create-attacker
```

4. Start victim container

```sh
run-victim
```

5. Start attacker container -- it should automatically find ip and mac of victim container

```sh
run-attacker
```
