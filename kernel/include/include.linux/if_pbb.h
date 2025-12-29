// SPDX-License-Identifier: GPL-2.0-only
/*
 *  Copyright (C) 2025 Demon
 *
 * Author: Demon <soumikbanerjee68@yahoo.com>
 * Kernel Includes for Barebones Provider Backbone Bridging Virtual Driver
 * (inspired from Linux Bridge, MacVlan, Veth and everything else open source!)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#ifndef _LINUX_IF_PBB_H
#define _LINUX_IF_PBB_H

#include <linux/skbuff.h>
#include <uapi/linux/if_arp.h>
#include <uapi/linux/if_vlan.h>
#include <linux/netdevice.h>
#include <linux/slab.h>
#include <linux/etherdevice.h>
#include <linux/u64_stats_sync.h>
#include <net/rtnetlink.h>
#include <net/dst.h>
#include <linux/veth.h>
#include <linux/module.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/ptr_ring.h>
#include <linux/bpf_trace.h>
#include <linux/net_tstamp.h>
#include <net/page_pool/helpers.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/rculist.h>
#include <linux/notifier.h>
#include <linux/ethtool.h>
#include <linux/if_arp.h>
#include <linux/if_vlan.h>
#include <linux/if_link.h>

#define PBB_DRV_VERSION	"1.0"
#define PBB_DRV_NAME	"pbb"
#define PBB_B_DRV_NAME	"pbbb"
#define PBB_I_DRV_NAME	"pbbi"

#ifndef IFF_PBB_B
#define IFF_PBB_B BIT_ULL(34)
#endif
#ifndef IFF_PBB_B_PORT
#define IFF_PBB_B_PORT BIT_ULL(35)
#endif
#ifndef IFF_PBB_I
#define IFF_PBB_I BIT_ULL(36)
#endif

// PBB debugging/dump APIs
#define pbb_printk(level, pbb, format, args...)   \
        printk(level "%s: " format, (pbb)->name, ##args)

#define pbb_err(__pbb, format, args...)                   \
        pbb_printk(KERN_ERR, __pbb, format, ##args)
#define pbb_warn(__pbb, format, args...)                  \
        pbb_printk(KERN_WARNING, __pbb, format, ##args)
#define pbb_notice(__pbb, format, args...)                \
        pbb_printk(KERN_NOTICE, __pbb, format, ##args)
#define pbb_info(__pbb, format, args...)                  \
        pbb_printk(KERN_INFO, __pbb, format, ##args)

#define pbb_debug(pbb, format, args...)                   \
        pr_debug("%s: " format,  (pbb)->name, ##args)

// PBB driver data structures and values
#define PBB_B_ALWAYS_ON_OFFLOADS \
        (NETIF_F_SG | NETIF_F_HW_CSUM | NETIF_F_GSO_SOFTWARE | \
         NETIF_F_GSO_ROBUST | NETIF_F_GSO_ENCAP_ALL)

#define PBB_B_ALWAYS_ON_FEATURES (PBB_B_ALWAYS_ON_OFFLOADS | NETIF_F_LLTX)

#define PBB_B_FEATURES \
        (NETIF_F_SG | NETIF_F_HW_CSUM | NETIF_F_HIGHDMA | NETIF_F_FRAGLIST | \
         NETIF_F_GSO | NETIF_F_TSO | NETIF_F_LRO | \
         NETIF_F_TSO_ECN | NETIF_F_TSO6 | NETIF_F_GRO | NETIF_F_RXCSUM)

#define PBB_B_STATE_MASK \
        ((1<<__LINK_STATE_NOCARRIER) | (1<<__LINK_STATE_DORMANT))

#define PBB_I_FEATURES (NETIF_F_SG | NETIF_F_FRAGLIST | NETIF_F_HW_CSUM | \
                        NETIF_F_RXCSUM | NETIF_F_SCTP_CRC | NETIF_F_HIGHDMA | \
                        NETIF_F_GSO_SOFTWARE | NETIF_F_GSO_ENCAP_ALL)

#define PBB_B_DEFAULT_BC_QUEUE_LEN					1000

/* PBB L2VPN Port Mode flags */
#define PBB_B_PORT_FLAGS_MODE_DOT1Q					1
#define PBB_B_PORT_FLAGS_MODE_DOT1AD					2

/* PBB L2VPN AH Manipulation Macros */
#define PBB_L2VPN_AH_RHT_LEN_MAX					67112960

#define PBB_L2VPN_RHNODE_TYPE_KEY_WIDTH_MAX				28

#define PBB_L2VPN_RHNODE_TYPE_C_QINQ_KEY_ENCODE				0x10000000
#define PBB_L2VPN_RHNODE_TYPE_I_SID_KEY_ENCODE				0x20000000

#define PBB_L2VPN_RHNODE_TYPE_C_CTAG_KEY_SHIFT				0
#define PBB_L2VPN_RHNODE_TYPE_C_STAG_KEY_SHIFT				12

#define PBB_L2VPN_RHNODE_TYPE_I_SID_KEY_SHIFT				0
#define PBB_L2VPN_RHNODE_TYPE_I_SID_DIR_KEY_SHIFT			24	

#define PBB_L2VPN_RHNODE_TYPE_C_CTAG_KEY_MASK				0xFFF
#define PBB_L2VPN_RHNODE_TYPE_C_STAG_KEY_MASK				0xFFF000
#define PBB_L2VPN_RHNODE_TYPE_C_CSTAG_KEY_MASK           		0xFFFFFF

#define PBB_L2VPN_RHNODE_TYPE_I_SID_KEY_MASK				0xFFFFFF
#define PBB_L2VPN_RHNODE_TYPE_I_SID_KEY_DIR_MASK			0x3000000
#define PBB_L2VPN_RHNODE_TYPE_I_SID_KEY_DIR_EDGE			0x1
#define PBB_L2VPN_RHNODE_TYPE_I_SID_KEY_DIR_CORE			0x2

#define PBB_L2VPN_RHNODE_TYPE_C_CTAG_INFO_ACTION_SHIFT			24
#define PBB_L2VPN_RHNODE_TYPE_C_CTAG_INFO_ACTION_MASK			0x3000000
#define PBB_L2VPN_RHNODE_TYPE_C_CTAG_INFO_ACTION_KEEP			0x1
#define PBB_L2VPN_RHNODE_TYPE_C_CTAG_INFO_ACTION_STRIP			0x2
#define PBB_L2VPN_RHNODE_TYPE_C_STAG_INFO_ACTION_MASK			0xC000000
#define PBB_L2VPN_RHNODE_TYPE_C_STAG_INFO_ACTION_KEEP			0x1
#define PBB_L2VPN_RHNODE_TYPE_C_STAG_INFO_ACTION_STRIP			0x2
#define PBB_L2VPN_RHNODE_TYPE_C_CSTAG_INFO_ACTION_MASK			0xF000000

#define PBB_L2VPN_RHNODE_TYPE_I_SID_INFO_SHIFT				24
#define PBB_L2VPN_RHNODE_TYPE_I_SID_CTAG_ACTION_INFO_SHIFT		26
#define PBB_L2VPN_RHNODE_TYPE_I_SID_TYPE_INFO_SHIFT			28
#define PBB_L2VPN_RHNODE_TYPE_I_SID_INFO_MASK				0xFFFFFF
#define PBB_L2VPN_RHNODE_TYPE_I_SID_TYPE_C_CSTAG_INFO_ACTION_MASK	0x3F000000
#define PBB_L2VPN_RHNODE_TYPE_I_SID_TYPE_INFO_MASK			0x30000000
#define PBB_L2VPN_RHNODE_TYPE_I_SID_TYPE_INFO_SHARED			0x1
#define PBB_L2VPN_RHNODE_TYPE_I_SID_TYPE_INFO_EXCL			0x2

#define PBB_L2VPN_RHNODE_TYPE_B_VID_INFO_MASK				0xFFF

/* PBB L2VPN AH Manipulation Macros */
#define PBB_L2VPN_FDB_RHT_LEN_MAX					67112960

/* PBB L2VPN AH Manipulation Data Structures */
union pbb_l2vpn_ah_rhnode_info {
	u32	c_qinq_edge_hash_info;
	u32	c_qinq_core_hash_info;
	u32	i_sid_hash_info;
	u32	b_vid_hash_info;
};

struct pbb_l2vpn_ah_rhnode {
	struct rhash_head		rhnode_hash;
	u32				rhnode_key;
	union pbb_l2vpn_ah_rhnode_info	rhnode_info;
	struct net_device		*pbb_b;
};

/* PBB L2VPN FDB Manipulation Data Structures */
struct pbb_l2vpn_edge_ifinfo {
	struct net_device *in_dev;
	u16		  cvlan_tci;
	u16		  svlan_tci;
};

struct pbb_l2vpn_core_ifinfo {
	struct net_device *b_dev;
	unsigned char	  core_nh_mac[ETH_ALEN];
};

struct pbb_l2vpn_core_ulay_ifinfo {
	struct net_device *lowerdev;
};

union pbb_l2vpn_ifinfo {
	struct pbb_l2vpn_edge_ifinfo		edge_ifinfo;		// Both PBB_MAC_TYPE_EDGE
	struct pbb_l2vpn_core_ifinfo		core_ifinfo;		// PBB_MAC_TYPE_CORE
	struct pbb_l2vpn_core_ulay_ifinfo	core_ulay_ifinfo;	// PBB_MAC_TYPE_CORE_ULAY
};
	  
typedef enum pbb_mac_type_e {
	PBB_MAC_TYPE_EDGE,
	PBB_MAC_TYPE_CORE,
	PBB_MAC_TYPE_CORE_ULAY,
} pbb_mac_type;

typedef enum pbb_mac_flags_e {
	PBB_MAC_FLAGS_STATIC,
	PBB_MAC_FLAGS_DYNAMIC,
	PBB_MAC_FLAGS_CPLEARN,
	PBB_MAC_FLAGS_HWLEARN,
} pbb_mac_flags;

struct pbb_l2vpn_fdb_rhnode_key {
	pbb_mac_type	type;
	unsigned char	mac[ETH_ALEN];
	u32	 	pbb_l2vpn_bd;
};

struct pbb_l2vpn_fdb_rhnode {
	struct rhash_head		fdb_rhnode_hash;
	struct pbb_l2vpn_fdb_rhnode_key	fdb_rhnode_key;
	pbb_mac_flags			fdb_rhnode_flags;
	union pbb_l2vpn_ifinfo		fdb_ifinfo;
	struct rcu_head                 fdb_rcu;
};

/* PBB Internal Data Structures */
struct pbb_b_priv {
	struct net_device __rcu		*pbb_i;
	struct net_device __rcu		*lowerdev;
	struct net_device		*self_pbb_b;
	netdevice_tracker		dev_tracker;
	struct pbb_pcpu_stats __percpu	*pcpu_stats;
	struct pbb_b_port		*pbb_b_port;
	netdev_features_t		set_features;
	struct rhashtable               pbb_l2vpn_ah_rht;
	struct rhashtable               pbb_l2vpn_fdb_rht;
};

struct pbb_i_priv {
	struct net_device __rcu		*pbb_b;
	struct pbb_pcpu_stats __percpu	*pcpu_stats;
};

struct pbb_pcpu_stats {
	u64_stats_t             rx_packets;
	u64_stats_t             rx_bytes;
	u64_stats_t             rx_multicast;
	u64_stats_t             tx_packets;
	u64_stats_t             tx_bytes;
	struct u64_stats_sync   syncp;
	u32                     rx_dropped;
	u32                     tx_dropped;
	u32                     rx_errors;
	u32                     rx_nohandler;
};

struct pbb_b_port {
	struct net_device __rcu *lowerdev;
	struct net_device __rcu *pbb_b;
	u32                     flags;
	unsigned char           perm_addr[ETH_ALEN];
};


/* PBB Qtag Manipulation/Dump Data Structures */
typedef struct __attribute__((__packed__)) dot1ah_outer_ethhdr_s {
	unsigned char	bb_dmac[ETH_ALEN];	/* Backbone 8021ah DMAC */
	unsigned char	bb_smac[ETH_ALEN];	/* Backbone 8021ah SMAC */
        u16		bb_vlan_proto;		/* Backbone 8021ah VID Protocol type - usually 8021ah aka 0x88a8 */	
        u16		bb_vlan_tci;		/* Backbone 8021ah VID Data */
	u16		bb_1ah_proto;		/* Backbone 8021ah Protocol Type 0x88e7 */
#ifdef PBB_8021AH_HDR_FLAGS_SUPPORTED // TODO
	__be32		bb_1ah_flags:8;		/* Backbone 8021ah flags - TODO: Can this be used if required? */
	__be32		bb_1ah_isid:24;		/* Backbone 8021ah 24-bit Session-ID */
#else
	__be32		bb_1ah_isid;		/* Backbone 8021ah 24-bit Session-ID */
#endif /* PBB_8021AH_HDR_FLAGS_SUPPORTED */
} dot1ah_outer_ethhdr;

/* PBB Qtag Manipulation/Dump Data Structures */
typedef struct __attribute__((__packed__)) dot1ah_outer_ethhdr_in_s {
	unsigned char	bb_dmac[ETH_ALEN];	/* Backbone 8021ah DMAC */
	unsigned char	bb_smac[ETH_ALEN];	/* Backbone 8021ah SMAC */
	u16		bb_1ah_proto;		/* Backbone 8021ah Protocol Type 0x88e7 */
#ifdef PBB_8021AH_HDR_FLAGS_SUPPORTED // TODO
	__be32		bb_1ah_flags:8;		/* Backbone 8021ah flags - TODO: Can this be used if required? */
	__be32		bb_1ah_isid:24;		/* Backbone 8021ah 24-bit Session-ID */
#else
	__be32		bb_1ah_isid;		/* Backbone 8021ah 24-bit Session-ID */
#endif /* PBB_8021AH_HDR_FLAGS_SUPPORTED */
} dot1ah_outer_ethhdr_in;

typedef struct __attribute__((__packed__)) dot1ad_ethhdr_s {
	unsigned char	c_dmac[ETH_ALEN];	/* destination eth addr */
	unsigned char	c_smac[ETH_ALEN];	/* source ether addr    */
        u16		c_svlan_proto;		
        u16		c_svlan_tci;
        u16		c_cvlan_proto;
        u16		c_cvlan_tci;
	u16		c_proto;		/* Protocol type        */
} dot1ad_ethhdr;

typedef struct dot1q_ethhdr_s {
	unsigned char	c_dmac[ETH_ALEN];	/* destination eth addr */
	unsigned char	c_smac[ETH_ALEN];	/* source ether addr    */
        u16		c_cvlan_proto;
        u16		c_cvlan_tci;
	u16		c_proto;		/* Protocol type        */
} dot1q_ethhdr;

typedef enum pbb_dump_type_e {
	PBB_DUMP_QINQ_HDR,
	PBB_DUMP_HDR,
} pbb_dump_type;

typedef enum skb_dump_direction_e {
	TX,
	RX,
} skb_dump_direction;

/* PBB Qtag Manipulation/Dump APIs */
void 				pbb_qinq_dump_skb(struct sk_buff *skb, skb_dump_direction dir);
void 				pbb_dump_skb(struct sk_buff *skb, skb_dump_direction dir);

u16 				vlan_tag_get_id(u16 vlan_tci);
u16 				vlan_tag_get_cfi(u16 vlan_tci);
u16 				vlan_tag_get_prio(u16 vlan_tci);

/* PBB L2VPN AH Manipulation Data APIs */
int 				pbb_l2vpn_ah_rht_init(struct rhashtable *tbl);
void 				pbb_l2vpn_ah_rht_deinit(struct rhashtable *tbl);
struct pbb_l2vpn_ah_rhnode 	*pbb_l2vpn_ah_rhnode_alloc(void);
int 				pbb_l2vpn_ah_rhnode_insert(struct rhashtable *tbl, struct rhash_head *rhnode_hash);
struct pbb_l2vpn_ah_rhnode 	*pbb_l2vpn_ah_rhnode_lookup(struct rhashtable *tbl, u32 *rhnode_key);
void 				pbb_l2vpn_ah_rhnode_free(struct pbb_l2vpn_ah_rhnode *ah_rhnode);

bool 				pbb_l2vpn_ah_rhnode_is_type_c_qinq_key(u32 rhnode_key);
bool 				pbb_l2vpn_ah_rhnode_is_type_i_sid_key(u32 rhnode_key);

int 				pbb_l2vpn_ah_rhnode_type_c_cstag_key_add(u32 *rhnode_key, u16 cvlan_tci, u16 svlan_tci);
int 				pbb_l2vpn_ah_rhnode_type_i_sid_key_add(u32 *rhnode_key, u32 isid_encap, u32 isid_dir);

int 				pbb_l2vpn_ah_rhnode_c_qinq_edge_info_add(union pbb_l2vpn_ah_rhnode_info *rhnode_info, u32 isid_encap, u8 isid_type, u8 cvlan_tci_action, u8 svlan_tci_action);
int 				pbb_l2vpn_ah_rhnode_c_qinq_core_info_add(union pbb_l2vpn_ah_rhnode_info *rhnode_info, u16 cvlan_tci, u16 svlan_tci, u8 cvlan_tci_action, u8 svlan_tci_action);
int 				pbb_l2vpn_ah_rhnode_type_b_vid_info_add(union pbb_l2vpn_ah_rhnode_info *rhnode_info, u16 bvlan_tci);

/* PBB L2VPN FDB Manipulation Data APIs */
int 			    	pbb_l2vpn_fdb_rht_init(struct rhashtable *tbl);
void 			    	pbb_l2vpn_fdb_rht_deinit(struct rhashtable *tbl);
struct pbb_l2vpn_fdb_rhnode	*pbb_l2vpn_fdb_rhnode_alloc(void);
int 			    	pbb_l2vpn_fdb_rhnode_insert(struct rhashtable *tbl, struct rhash_head *fdb_rhnode_hash);
struct pbb_l2vpn_fdb_rhnode 	*pbb_l2vpn_fdb_rhnode_lookup(struct rhashtable *tbl, struct pbb_l2vpn_fdb_rhnode_key *fdb_rhnode_key);
int 				pbb_l2vpn_fdb_rhnode_remove(struct rhashtable *tbl, struct rhash_head *fdb_rhnode_hash);
void 			    	pbb_l2vpn_fdb_rhnode_free(struct pbb_l2vpn_fdb_rhnode *fdb_rhnode);
void 				pbb_l2vpn_fdb_get_flood_mac_for_sid(unsigned char flood_mac[], u32 sid);

/* PBB Generic L2VPN Manipulation Data APIs */
int 				pbb_l2vpn_init(void);
void 				pbb_l2vpn_deinit(void);

/* PBB RTNL APIs */
int 				pbb_b_rtnl_link_register(void);
void 				pbb_b_rtnl_link_unregister(void);

int 				pbb_i_rtnl_link_register(void);
void 				pbb_i_rtnl_link_unregister(void);

/* PBB Netdevice/notifier APIs */
void 				pbb_get_stats64(struct net_device *pbb, struct rtnl_link_stats64 *stats);

void 				pbb_b_netdev_notifier_register(void);
void 				pbb_b_netdev_notifier_unregister(void);

#endif /* _LINUX_IF_PBB_H */
