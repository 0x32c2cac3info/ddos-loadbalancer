# Development of DoS attack resistance method for L4 load balancing
This is implementation of SYN-flood defense method for a stateful L4 load-balancer.

Setup is deployed by following steps:
- Deploy 2 virtual machines and connect them with each other by 2 internal networks via `enp0s8` and `enp0s9` interfaces.
- Build modified linux kernel sources (you should ask me to send them to you) and boot modified kernel on the second virtual machine. 
- Execute `init.sh` with `sudo` on the second virtual machine.
```bash
sh init.sh
```
- Install mininet, scapy, hping3, curl and siphash from `siphash.zip` on the first virtual machine. And launch `testnet.py` with `sudo`.
```bash
# mininet and scapy
git clone git://github.com/mininet/mininet
mininet/util/install.sh -n
pip3 install mininet scapy

# hping3 and curl
apt install hping3 curl 

# siphash
unzip siphash.zip
python3 siphash/setup.py
```
- Disable rp_filter of enp0s9 on **h1** and launch `lb.py` from `src` on **h2** in the mininet. 
```bash
h1 sysctl -w net.ipv4.conf.enp0s9.rp_filter=0
h2 python lb.py
```
- You can launch hping and curl on h1.
```bash
h1 curl 10.0.0.2
h1 hping3 --flood --rand-source -S -p 80 10.0.0.2
```
