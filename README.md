Provider Backbone Bridging (PBB)

This project is an honest attempt to implement Provider Backbone Bridging (802.1ah) from barebones as per the open documentation available on the same.
As of the present, this project is just a starting point for the author himself to delve into the very basic principles of 802.1ah, before taking it further (like implementing Control Plane Support to PBB, for example, thus turning the solution this into something like Shortest Path Bridging aka SPB).

The kernel directory contains the Virtual Driver source code and includes to be compiled, after which the PBB driver can be modprobed into the linux kernel.
The user directory contains a patch to be applied on top of the existing (as pf 29-12-2025) iproute package to build the user space facilities to be able to use the Virtual Driver.

Below steps need to be followed for now, automation for the same is being planned in near future -
1. Go to kernel/kernel-module directory.
2. Copy include.uapi.linux/if_pbb.h to your system linux header/source-code folder as is the case @include/uapi/linux.
3. Copy include.linux/if_pbb.h to your system linux header/source-code folder as is the case @include/linux.
4. Do make clean + make + modprobe pbb.ko.
5. Go to user directory.
6. Download iproute source code for your distribution and apply iproute patch on top, and copy all scripts to the same folder. Do make clean + make.
7. Then execute/modify+execute the specific pbb_xxx.sh script file!

Since this project is just at a nascaent phase, more fixes and details will be available soon once the Project progresses further.
LONG LIVE OPEN SOURCE!
