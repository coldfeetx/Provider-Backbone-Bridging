# SPDX-License-Identifier: GPL-2.0-only

# Makefile for Provider Backbone Bridging Network (PBBN) node

# Copyright (C) 2025 coldfeet

# Author: coldfeet <soumikbanerjee68@yahoo.com>
# Virtual Driver for Barebones Provider Backbone Bridging
# (inspired from Linux Bridge, MacVlan, Veth and everything else open source!)


obj-m+= pbbn.o

pbb-objs+= pbbn_netfilter_core.o pbbn_flood.o

#CFLAGS+= -Wno-implicit-fallthrough

all:
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
