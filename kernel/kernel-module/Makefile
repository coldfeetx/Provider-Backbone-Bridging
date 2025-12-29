# SPDX-License-Identifier: GPL-2.0-only

# Makefile for Provider Backbone Bridging 

# Copyright (C) 2025 coldfeet

# Author: coldfeet <soumikbanerjee68@yahoo.com>
# Virtual Driver for Barebones Provider Backbone Bridging
# (inspired from Linux Bridge, MacVlan, Veth and everything else open source!)


obj-m+= pbb.o

pbb-objs+= pbb_init.o pbb_core.o pbb_edge.o

#CFLAGS+= -Wno-implicit-fallthrough

all:
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
