#!/usr/bin/bash

./ip/ip link del pbbb_0
./ip/ip link del br0
./ip/ip link del veth1
./ip/ip link del veth2

./ip/ip link del pbbb_1
./ip/ip link del br1
./ip/ip link del br2
./ip/ip link del veth3
./ip/ip link del veth4
./ip/ip link del veth5
./ip/ip link del veth6


ip netns del netedge1
ip netns del netedge2
