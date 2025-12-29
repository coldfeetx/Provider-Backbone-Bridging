Provider Backbone Bridging (PBB)

This project is an honest attempt to understand Provider Backbone Bridging (802.1ah) protocol from the very barebones, based on the open documentation available on the same.
As of the present, this project is just a starting point for the author himself to delve into the design and implementation of the very basic principles of this standard in its simplest form, before taking it further (like implementing Control Plane Support to PBB, for example, thus turning it into something like Shortest Path Bridging aka SPB).

The kernel directory contains the Virtual Driver source code and includes to be compiled, after which the PBB driver can be modprobed into the linux kernel.
The user directory contains a patch to be applied on top of the existing (as of 29-12-2025) iproute package to build the user space iproute extension to use the Virtual Driver, and some scripts to fire-up the pbb toolkit.

Below steps need to be followed for now, automation for the same is being planned in near future -
1. Go to kernel/include directory.
2. Copy include.uapi.linux/if_pbb.h to your system linux header/source-code folder (as is the case) @include/uapi/linux.
3. Copy include.linux/if_pbb.h to your system linux header/source-code folder (as is the case) @include/linux.
4. Go to kernel/kernel-module directory.
4. Do make clean + make + modprobe pbb.ko.
5. Go to user directory.
6. Download iproute source code for your distribution and apply iproute patch on top, and copy all scripts to the same folder. Do make clean + make.
7. Then execute/modify+execute the specific pbb_xxx_extended.sh script file as per the use case.
8. At last execute/modify+execute pbb_del.sh to clean up all the user/kernel resources created in step7, and finally rmmod pbb.ko to finally wrap up with PBB experimentation!

Since this project is just at a nascaent phase, more fixes and details will be available soon once the Project progresses further and the author develops more understanding of the standard.
For any queries/complaints on this project, please reach out to me at soumikbaneree68@yahoo.com.
LONG LIVE OPEN SOURCE!
