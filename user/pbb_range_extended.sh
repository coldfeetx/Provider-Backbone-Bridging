#!/usr/bin/bash

#!/usr/bin/bash

modprobe -r br_netfilter
modprobe -r bridge
modprobe bridge

./ip/ip link add veth0 type veth peer name veth1
./ip/ip link add veth2 type veth peer name veth3
./ip/ip link add veth4 type veth peer name veth5
./ip/ip link add veth6 type veth peer name veth7
./ip/ip link add pbbb_0 type pbbb
./ip/ip link add pbbi_0 type pbbi
./ip/ip link set pbbi_0 type pbbi core-bridge pbbb_0
./ip/ip link set pbbi_0 up
./ip/ip link set pbbb_0 up
./ip/ip link set pbbb_0 type pbbb link veth2 b-vid-mode dot1ad i-sid 20000-20003 b-vid 1000-1003
./ip/ip link set pbbb_0 type pbbb link veth2 key-info-map-verify i-sid 20000-20003 b-vid 1000-1003
./ip/ip link set pbbi_0 type pbbi c-vid 200-203 c-vid-mode-keep s-vid 20-23 s-vid-mode-keep i-sid 20000-20003 i-sid-type-excl
./ip/ip link set pbbi_0 type pbbi c-vid 200-203 c-vid-mode-keep s-vid 20-23 s-vid-mode-keep i-sid 20000-20003 i-sid-type-excl key-info-map-verify
./ip/ip link add pbbb_1 type pbbb
./ip/ip link add pbbi_1 type pbbi
./ip/ip link set pbbi_1 type pbbi core-bridge pbbb_1
./ip/ip link set pbbi_1 up
./ip/ip link set pbbb_1 up
./ip/ip link set pbbb_1 type pbbb link veth5 b-vid-mode dot1ad i-sid 20000-20003 b-vid 1000-1003
./ip/ip link set pbbb_1 type pbbb link veth5 key-info-map-verify i-sid 20000-20003 b-vid 1000-1003
./ip/ip link set pbbi_1 type pbbi c-vid 200-203 c-vid-mode-keep s-vid 20-23 s-vid-mode-keep i-sid 20000-20003 i-sid-type-excl
./ip/ip link set pbbi_1 type pbbi c-vid 200-203 c-vid-mode-keep s-vid 20-23 s-vid-mode-keep i-sid 20000-20003 i-sid-type-excl key-info-map-verify

./ip/ip link add name br0 type bridge
./ip/ip link set br0 up
./ip/ip link set veth1 master br0
./ip/ip link set pbbi_0 master br0
./ip/ip link set veth1 up
./ip/ip link set veth2 up
./ip/ip link set name br0 type bridge vlan_filtering 1 vlan_default_pvid 23 vlan_protocol 802.1ad
bridge vlan add vid 23 dev br0 self
bridge vlan add dev veth1 vid 23
bridge vlan add dev pbbi_0 vid 23

./ip/ip link add name br1 type bridge
./ip/ip link set br1 up
./ip/ip link set veth3 master br1
./ip/ip link set veth4 master br1
./ip/ip link set veth3 up
./ip/ip link set veth4 up
./ip/ip link set name br1 type bridge vlan_filtering 1 vlan_default_pvid 1003 vlan_protocol 802.1ad
bridge vlan add vid 1003 dev br1 self
bridge vlan add dev veth3 vid 1003
bridge vlan add dev veth4 vid 1003

./ip/ip link add name br2 type bridge
./ip/ip link set br2 up
./ip/ip link set veth6 master br2
./ip/ip link set pbbi_1 master br2
./ip/ip link set veth5 up
./ip/ip link set veth6 up
./ip/ip link set name br2 type bridge vlan_filtering 1 vlan_default_pvid 23 vlan_protocol 802.1ad
bridge vlan add vid 23 dev br2 self
bridge vlan add dev veth6 vid 23
bridge vlan add dev pbbi_1 vid 23

./ip/ip netns add netedge1
./ip/ip netns add netedge2

./ip/ip link set veth0 netns netedge1
./ip/ip link set veth7 netns netedge2
./ip/ip netns exec netedge1 ifconfig veth0 up
./ip/ip netns exec netedge2 ifconfig veth7 up
./ip/ip netns exec netedge1 ifconfig lo up
./ip/ip netns exec netedge2 ifconfig lo up

modprobe 8021q
./ip/ip netns exec netedge1 ./ip/ip link add link veth0 name veth0.23 type vlan proto 802.1ad id 23
./ip/ip netns exec netedge1 ./ip/ip link add link veth0.23 name veth0.23.203 type vlan proto 802.1q id 203
./ip/ip netns exec netedge1 ifconfig veth0.23 up
./ip/ip netns exec netedge1 ifconfig veth0.23.203 10.1.1.1 up

./ip/ip netns exec netedge2 ./ip/ip link add link veth7 name veth7.23 type vlan proto 802.1ad id 23
./ip/ip netns exec netedge2 ./ip/ip link add link veth7.23 name veth7.23.203 type vlan proto 802.1q id 203
./ip/ip netns exec netedge2 ifconfig veth7.23 up
./ip/ip netns exec netedge2 ifconfig veth7.23.203 10.1.1.2 up

#./ip/ip netns exec netedge1 arp -s 10.1.1.2 7e:bf:b8:42:bd:68
#./ip/ip netns exec netedge1 arp -s 10.1.1.2 e6:40:33:7a:2a:e8
#./ip/ip netns exec netedge2 arp -s 10.1.1.1 d2:c6:82:28:9f:ef
echo "./ip/ip netns exec netedge1 ping 10.1.1.2 -I veth0.23.203"

