sysctl -w net.ipv4.ip_forward=1

sysctl -w net.ipv4.tcp_syncookies=1

sysctl -w net.ipv4.conf.enp0s8.rp_filter=0

ip addr add 192.168.0.1/30 dev enp0s8

ip addr add 172.16.0.3/30 dev enp0s9

ip tunnel add mytun mode ipip remote 192.168.0.2 local 192.168.0.1 dev enp0s8

ip link set dev mytun up

ip route add default via 172.16.0.1 dev enp0s9

ip addr add 10.0.0.2/32 dev lo

python3 -m http.server 80 --bind 10.0.0.2
