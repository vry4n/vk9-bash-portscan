# vk9-bash-portscan

This is a simple port scan developed as an alternative to other scanners.

1. set the permissions
chmod 777 vk9-bash-portscan.sh

2. Run the script we would require the following data
PORTS = any \\ 80 \\ 80,443
IP = 192.168.0.1 (single) \\ 192.168.0.1/24 (subnet
PROTO = any \\ tcp \\ udp

example
./vk9-bash-portscan.sh any 192.168.0.12 any
./vk9-bash-portscan.sh 80 172.16.0.0/16 tcp
./vk9-bash-portscan.sh 53,445 8.8.8.8 udp
