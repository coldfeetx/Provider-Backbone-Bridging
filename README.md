**Provider Backbone Bridging (PBB) Project High-Level Summary**

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


**PBB Architecture Summary**

Backbone edge bridges (BEBs) can contain either an I-Component or a B-Component. 
The I-Component (pbbi) maps Customer VLAN identifiers (C-VIDs) and/or Service VLAN identifiers (S-VIDs) to service instance identifiers (I-SIDs) and adds a provider backbone bridge (PBB) header without a backbone VLAN tag (B-Tag) in 4 different combinations -

  a. S-Tagged Service (c-vid 0 c-vid-mode-strip s-vid <svid> s-vid-mode-keep i-sid <isid>)

  b. C-Tagged Service (c-vid <cvid> c-vid-mode-keep s-vid 0 c-vid-mode-strip i-sid <isid>)
  
  c. S/C Tagged Service (c-vid <cvid> c-vid-mode-keep s-vid <svid> s-vid-mode-keep i-sid <isid>)
  
  d. Port-based Service (c-vid 0 c-vid-mode-strip s-vid 0 s-vid-mode-strip i-sid <isid>)
  
  e. This translation ruleset is currently symmetric ie. applies the same way on egress as on ingress.
  
  f. If the customer and/or service tags need to be retained across the Provider Backbone Network (PBBN), use c/s-vid-mode-keep else use c/s-vid-mode-strip. Currently if a range of C-vid and/or S-vid tags has to be mapped to a single I-sid, then I-sid i-sid-type-shared has to be specified which can only support c/s-vid-mode-keep option.

The B-Component (pbbb) maps I-SIDs to backbone VIDs (B-VIDs) and adds a PBB header with a B-Tag. Below 2 options are supported in that regard -

  a. b-vid-mode dot1ad i-sid <isid> b-vid <bvid>
  
  b. b-vid-mode dot1q i-sid <isid> b-vid <bvid>


**PBB Implementation Summary**

The pbbi component has been implemented as a virtual driver supporting aforementioned I-component operations (enlisted in previous section) that is to be enslaved by a Linux Kernel Bridge Device (to utilize the available facilities of Traditional Bridging provided by the Linux Kernel Bridge). The other side of the bridge device should be an ethernet device that is connected to an Access Network (CE->PEB->PB on Ingress and PB->PEB->CE on Egress). The bridge device must be in 802.1q mode with vlan_filtering set for C-tagged Service mode, in 802.1ad mode with vlan_filtering set for S and S/C-tagged Service mode. No vlan settings required for Port-based Service.

Eg: ./ip/ip link set pbbi_0 type pbbi core-bridge pbbb_0

The pbbb component has been implemented as a virtual driver supporting aforementioned B-component operations (enlisted in previous section) that requires an ethernet device to be enslaved. The other side of this device should be part of the PBBN Core network (BEB-BCB on Ingress and BCB-BEB on Egress).

Eg: ./ip/ip link set pbbb_1 type pbbb link veth5 b-vid-mode dot1ad i-sid 20000 b-vid 1000

