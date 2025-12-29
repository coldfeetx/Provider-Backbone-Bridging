// SPDX-License-Identifier: GPL-2.0-only
/*
 *  drivers/net/pbb_init.c
 *
 *  Copyright (C) 2025 coldfeet
 *
 * Author: coldfeet <soumikbanerjee68@yahoo.com>
 * Virtual Driver for Barebones Provider Backbone Bridging
 * (inspired from Linux Bridge, MacVlan, Veth and everything else open source!)
 *
 */

#include <uapi/linux/if_pbb.h>
#include <linux/if_pbb.h>
#pragma GCC diagnostic ignored "-Wimplicit-fallthrough"

/***************************************** Generic PBB Routines ***********************************************/
/***************************************** PBB Packet Dump routines *******************************************/
static void pbb_dump(const struct sk_buff *skb, pbb_dump_type dump_type, skb_dump_direction dir)
{
	const dot1ad_ethhdr *dot1ad_eth_hdr = NULL;

	if (dir == TX) {
		dot1ad_eth_hdr = (const dot1ad_ethhdr *)skb_eth_hdr(skb);
	} else {
		dot1ad_eth_hdr = (const dot1ad_ethhdr *)eth_hdr(skb);
	}

	if (!dot1ad_eth_hdr || !skb->dev) {
		printk(KERN_ERR "%s: SKB_Eth_Hdr:%p OR Device:%p Invalid!",
		       __FUNCTION__, dot1ad_eth_hdr, skb->dev);
		return;
	}

	pbb_info(skb->dev, "%s: Processing for dump_type:%d direction:%d for interface:%s skb_proto:0x%x",
		 __FUNCTION__, dump_type, dir, skb->dev->name, skb->protocol);

	// TODO: Rx work for Outer DOT1AH Header dumps!
	switch (dump_type) {
		case PBB_DUMP_HDR:
			const dot1ah_outer_ethhdr *dot1ah_outer_eth_hdr = (const dot1ah_outer_ethhdr *)dot1ad_eth_hdr;
			printk(KERN_INFO "BB_DMAC:%pM ", dot1ah_outer_eth_hdr->bb_dmac);
			printk(KERN_INFO "BB_SMAC:%pM ", dot1ah_outer_eth_hdr->bb_smac);

			if ((dir == TX) && !eth_type_vlan(dot1ah_outer_eth_hdr->bb_vlan_proto)) {
				printk(KERN_INFO "BB Vlan tag not present! %d:%d:%d tci %d:%d:%d",
				       dot1ah_outer_eth_hdr->bb_vlan_proto, htons(dot1ah_outer_eth_hdr->bb_vlan_proto), ntohs(dot1ah_outer_eth_hdr->bb_vlan_proto),
				       dot1ah_outer_eth_hdr->bb_vlan_tci, htons(dot1ah_outer_eth_hdr->bb_vlan_tci), ntohs(dot1ah_outer_eth_hdr->bb_vlan_tci));
			} else if (dir == TX) {
				printk(KERN_INFO "BB_VlanProto:0x%x ", ntohs(dot1ah_outer_eth_hdr->bb_vlan_proto));
				printk(KERN_INFO "BB_VlanId:%d ", ntohs(dot1ah_outer_eth_hdr->bb_vlan_tci));
			} else if ((dir == RX) && skb_vlan_tag_present(skb) && (htons(skb->vlan_proto) == ETH_P_8021AD)) {
				printk(KERN_INFO "BB_VlanProto:0x%x ", ETH_P_8021AD);
				printk(KERN_INFO "BB_VlanId:%d ", skb_vlan_tag_get_id(skb));
			} else if ((dir == RX) && skb_vlan_tag_present(skb) && (htons(skb->vlan_proto) == ETH_P_8021Q)) {
				printk(KERN_INFO "BB_VlanProto:0x%x ", ETH_P_8021Q);
				printk(KERN_INFO "BB_VlanId:%d ", skb_vlan_tag_get_id(skb));
			}

			if (dir == TX) {
				printk(KERN_INFO "8021ah_Proto:0x%x", htons(dot1ah_outer_eth_hdr->bb_1ah_proto));
				printk(KERN_INFO "8021ah_ISessionId:0x%x", htonl(dot1ah_outer_eth_hdr->bb_1ah_isid));
			} else {
				const dot1ah_outer_ethhdr_in *dot1ah_outer_eth_hdr_in = (dot1ah_outer_ethhdr_in *)dot1ah_outer_eth_hdr;
				printk(KERN_INFO "8021ah_Proto:0x%x", htons(dot1ah_outer_eth_hdr_in->bb_1ah_proto));
				printk(KERN_INFO "8021ah_ISessionId:0x%x", htonl(dot1ah_outer_eth_hdr_in->bb_1ah_isid));
			}

			uint32_t dot1ah_outer_eth_hdr_offset = (dir == TX) ? sizeof(dot1ah_outer_ethhdr) : sizeof(dot1ah_outer_ethhdr_in);
			dot1ad_eth_hdr = (const dot1ad_ethhdr *)((char *)dot1ah_outer_eth_hdr + dot1ah_outer_eth_hdr_offset);
		case PBB_DUMP_QINQ_HDR:
			printk(KERN_INFO "C_DMAC:%pM ", dot1ad_eth_hdr->c_dmac);
			printk(KERN_INFO "C_SMAC:%pM ", dot1ad_eth_hdr->c_smac);

			bool svlan_present = false, cvlan_present = false, qiq_rx = (dump_type == PBB_DUMP_QINQ_HDR) && (dir == RX);
			u16  svlan_proto = 0, svlan_tag = 0, cvlan_proto = 0, cvlan_tag = 0, proto = 0;

			if (((dir == TX) || (dump_type != PBB_DUMP_QINQ_HDR)) && (htons(dot1ad_eth_hdr->c_svlan_proto) == ETH_P_8021AD)) {
				svlan_present	= true;
				svlan_proto	= ETH_P_8021AD;
				svlan_tag	= vlan_tag_get_id(ntohs(dot1ad_eth_hdr->c_svlan_tci));
			/* FIXME: Somehow for QinQ frame in Rx, skb->protocol received as Q (not AD),
			 * need to check if this is expected. Till then, use below workaround.
			 */
			} else if (qiq_rx && skb_vlan_tag_present(skb) && (htons(skb->vlan_proto) == ETH_P_8021AD)) {
				svlan_present	= true;
				svlan_proto	= ETH_P_8021AD;
				svlan_tag	= skb_vlan_tag_get_id(skb);
			}

			if (svlan_present == false) {
				printk(KERN_INFO "Vlan S-tag not present!");
			} else {
				printk(KERN_INFO "S_VlanProto:0x%x ", svlan_proto);
				printk(KERN_INFO "S_VlanId:%d ", svlan_tag);
			}

			if ((svlan_present == true) && (((dir == TX) && (htons(dot1ad_eth_hdr->c_cvlan_proto) == ETH_P_8021Q)) ||
							((qiq_rx == true) && (htons(dot1ad_eth_hdr->c_svlan_proto) == ETH_P_8021Q)))) {
				cvlan_present	= true;
				cvlan_proto	= ETH_P_8021Q;
				cvlan_tag	= (qiq_rx == false) ? vlan_tag_get_id(ntohs(dot1ad_eth_hdr->c_cvlan_tci)) : vlan_tag_get_id(ntohs(dot1ad_eth_hdr->c_svlan_tci));
				proto		= (qiq_rx == false) ? htons(dot1ad_eth_hdr->c_proto) : htons(dot1ad_eth_hdr->c_cvlan_proto);
			} else if ((svlan_present == false) && (htons(dot1ad_eth_hdr->c_svlan_proto) == ETH_P_8021Q)) {
				cvlan_present	= true;
				cvlan_proto	= ETH_P_8021Q;
				cvlan_tag	= vlan_tag_get_id(ntohs(dot1ad_eth_hdr->c_svlan_tci));
				proto		= htons(dot1ad_eth_hdr->c_cvlan_proto);
			} else {
				printk(KERN_INFO "Vlan C-tag not present!");
				proto		= htons(dot1ad_eth_hdr->c_cvlan_proto);
			}

			if ((svlan_present == true) && (cvlan_present == false)) {
				printk(KERN_ERR "Strange packet!");
			}

			if (cvlan_present == true) {
				printk(KERN_INFO "C_VlanProto:0x%x ", cvlan_proto);
				printk(KERN_INFO "C_VlanId:%d ", cvlan_tag);
			}
			printk(KERN_INFO "C_Protocol:0x%x", proto);

			break;
		default:
			printk(KERN_ERR "%s: Invalid PBB Dump request type %d",
			       __FUNCTION__, dump_type);
	}

	return;
}

// 8021AH
void pbb_dump_skb(struct sk_buff *skb, skb_dump_direction dir)
{
	if (!skb) {
		printk(KERN_ERR "%s: SKB Invalid!", __FUNCTION__);
		return;
	}

        pbb_dump(skb, PBB_DUMP_HDR, dir);
}

// 8021AD
void pbb_qinq_dump_skb(struct sk_buff *skb, skb_dump_direction dir)
{
	if (!skb) {
		printk(KERN_ERR "%s: SKB Invalid!", __FUNCTION__);
		return;
	}

	pbb_dump(skb, PBB_DUMP_QINQ_HDR, dir);
}

/***************************************** PBB Qtag APIs *******************************************/
u16 vlan_tag_get_id(u16 vlan_tci)
{
        return (vlan_tci & VLAN_VID_MASK);
}

u16 vlan_tag_get_cfi(u16 vlan_tci)
{
        return (vlan_tci & VLAN_CFI_MASK);
}

u16 vlan_tag_get_prio(u16 vlan_tci)
{
        return ((vlan_tci & VLAN_PRIO_MASK) >> VLAN_PRIO_SHIFT);
}

/***************************************** PBB L2VPN RHnode APIs *************************************/
/***************************************** PBB L2VPN RHnode 802.1ah Key APIs *************************/
bool pbb_l2vpn_ah_rhnode_is_type_c_qinq_key(u32 rhnode_key)
{
	return (rhnode_key & PBB_L2VPN_RHNODE_TYPE_C_QINQ_KEY_ENCODE);
}

bool pbb_l2vpn_ah_rhnode_is_type_i_sid_key(u32 rhnode_key)
{
	return (rhnode_key & PBB_L2VPN_RHNODE_TYPE_I_SID_KEY_ENCODE);
}

int pbb_l2vpn_ah_rhnode_type_c_cstag_key_add(u32 *rhnode_key, u16 cvlan_tci, u16 svlan_tci)
{
	if (rhnode_key) {
		*rhnode_key = (cvlan_tci << PBB_L2VPN_RHNODE_TYPE_C_CTAG_KEY_SHIFT);
		*rhnode_key &= PBB_L2VPN_RHNODE_TYPE_C_CTAG_KEY_MASK;

		*rhnode_key |= (svlan_tci << PBB_L2VPN_RHNODE_TYPE_C_STAG_KEY_SHIFT);

		*rhnode_key &= PBB_L2VPN_RHNODE_TYPE_C_CSTAG_KEY_MASK;

		*rhnode_key |= PBB_L2VPN_RHNODE_TYPE_C_QINQ_KEY_ENCODE;

		return 0;
	} else {
		printk(KERN_ERR "%s: Failed to add ctag:%d and stag:%d key to pbb_l2vpn_ah_rhnode!",
		       __FUNCTION__, cvlan_tci, svlan_tci);

		return -EINVAL;
	}
}

int pbb_l2vpn_ah_rhnode_type_i_sid_key_add(u32 *rhnode_key, u32 isid_encap, u32 isid_dir)
{
	if (rhnode_key) {
		isid_dir <<= PBB_L2VPN_RHNODE_TYPE_I_SID_DIR_KEY_SHIFT;
		isid_dir &= PBB_L2VPN_RHNODE_TYPE_I_SID_KEY_DIR_MASK;

		*rhnode_key = (isid_encap << PBB_L2VPN_RHNODE_TYPE_I_SID_KEY_SHIFT);
		*rhnode_key &= PBB_L2VPN_RHNODE_TYPE_I_SID_KEY_MASK;

		*rhnode_key |= isid_dir;

		*rhnode_key |= PBB_L2VPN_RHNODE_TYPE_I_SID_KEY_ENCODE;

		return 0;
	} else {
		printk(KERN_ERR "%s: Failed to add isid_encap:%d and isid_dir:%d key to pbb_l2vpn_ah_rhnode!",
		       __FUNCTION__, isid_encap, isid_dir);

		return -EINVAL;
	}
}
/***************************************** PBB L2VPN RHnode 802.1ah Info APIs *************************/
int pbb_l2vpn_ah_rhnode_c_qinq_edge_info_add(union pbb_l2vpn_ah_rhnode_info *rhnode_info, u32 isid_encap, u8 isid_type, u8 cvlan_tci_action, u8 svlan_tci_action)
{
	if (rhnode_info) {
		u32 isid_type_csvlan_tci_action = 0;
		isid_type_csvlan_tci_action = (isid_type << PBB_L2VPN_RHNODE_TYPE_I_SID_TYPE_INFO_SHIFT);
		isid_type_csvlan_tci_action &= PBB_L2VPN_RHNODE_TYPE_I_SID_TYPE_INFO_MASK;

		isid_type_csvlan_tci_action |= (svlan_tci_action << PBB_L2VPN_RHNODE_TYPE_I_SID_CTAG_ACTION_INFO_SHIFT);

		isid_type_csvlan_tci_action |= (cvlan_tci_action << PBB_L2VPN_RHNODE_TYPE_I_SID_INFO_SHIFT);

		isid_type_csvlan_tci_action &= PBB_L2VPN_RHNODE_TYPE_I_SID_TYPE_C_CSTAG_INFO_ACTION_MASK;

		rhnode_info->c_qinq_edge_hash_info = isid_encap;

		rhnode_info->c_qinq_edge_hash_info |= isid_type_csvlan_tci_action;

		return 0;
	} else {
		printk(KERN_ERR "%s: Failed to add isid_encap:%d, cvlan_tci_action:%d and svlan_tci_action:%d info to pbb_l2vpn_ah_rhnode!",
		       __FUNCTION__, isid_encap, cvlan_tci_action, svlan_tci_action);

		return -EINVAL;
	}
}

int pbb_l2vpn_ah_rhnode_c_qinq_core_info_add(union pbb_l2vpn_ah_rhnode_info *rhnode_info, u16 cvlan_tci, u16 svlan_tci, u8 cvlan_tci_action, u8 svlan_tci_action)
{
	if (rhnode_info) {
		u32 csvlan_tci_action = 0;
		csvlan_tci_action = (svlan_tci_action << PBB_L2VPN_RHNODE_TYPE_I_SID_CTAG_ACTION_INFO_SHIFT);

		csvlan_tci_action |= (cvlan_tci_action << PBB_L2VPN_RHNODE_TYPE_I_SID_INFO_SHIFT);
		csvlan_tci_action &= PBB_L2VPN_RHNODE_TYPE_C_CSTAG_INFO_ACTION_MASK;

		rhnode_info->c_qinq_core_hash_info = (cvlan_tci << PBB_L2VPN_RHNODE_TYPE_C_CTAG_KEY_SHIFT);
		rhnode_info->c_qinq_core_hash_info &= PBB_L2VPN_RHNODE_TYPE_C_CTAG_KEY_MASK;

		rhnode_info->c_qinq_core_hash_info |= (svlan_tci << PBB_L2VPN_RHNODE_TYPE_C_STAG_KEY_SHIFT);

		rhnode_info->c_qinq_core_hash_info &= PBB_L2VPN_RHNODE_TYPE_C_CSTAG_KEY_MASK;

		rhnode_info->c_qinq_core_hash_info |= csvlan_tci_action;

		return 0;
	} else {
		printk(KERN_ERR "%s: Failed to add ctag:%d, stag:%d, cvlan_tci_action:%d and svlan_tci_action:%d info to pbb_l2vpn_ah_rhnode!",
		       __FUNCTION__, cvlan_tci, svlan_tci, cvlan_tci_action, svlan_tci_action);

		return -EINVAL;
	}
}

int pbb_l2vpn_ah_rhnode_type_b_vid_info_add(union pbb_l2vpn_ah_rhnode_info *rhnode_info, u16 bvlan_tci)
{
	if (rhnode_info) {
		rhnode_info->b_vid_hash_info = bvlan_tci;
		rhnode_info->b_vid_hash_info &= PBB_L2VPN_RHNODE_TYPE_B_VID_INFO_MASK;

		return 0;
	} else {
		printk(KERN_ERR "%s: Failed to add btag:%d info to pbb_l2vpn_ah_rhnode!",
		       __FUNCTION__, bvlan_tci);

		return -EINVAL;
	}
}

/***************************************** PBB Module APIs **************************************/
/* PBB L2VPN AH Data Structure Manipulation APIs */
static struct kmem_cache *pbb_b_l2vpn_ah_rhnode_cache __read_mostly;

static int __init pbb_l2vpn_ah_init(void)
{
	pbb_b_l2vpn_ah_rhnode_cache = kmem_cache_create("pbb_b_l2vpn_ah_rhnode_cache",
							sizeof(struct pbb_l2vpn_ah_rhnode),
					 		0,
					 		SLAB_HWCACHE_ALIGN, NULL);

	if (!pbb_b_l2vpn_ah_rhnode_cache) {
		printk(KERN_ERR "%s: Failed to allocate cache memory for pbb_b_l2vpn_ah_rhnode!",
		       __FUNCTION__);

		return -ENOMEM;
	}


	printk(KERN_INFO "%s: Allocated cache memory for pbb_b_l2vpn_ah_rhnode",
	       __FUNCTION__);

	return 0;
}

static void pbb_l2vpn_ah_deinit(void)
{
	kmem_cache_destroy(pbb_b_l2vpn_ah_rhnode_cache);
}

struct pbb_l2vpn_ah_rhnode *pbb_l2vpn_ah_rhnode_alloc(void)
{
	return (struct pbb_l2vpn_ah_rhnode *)kmem_cache_alloc(pbb_b_l2vpn_ah_rhnode_cache, GFP_ATOMIC);
}

void pbb_l2vpn_ah_rhnode_free(struct pbb_l2vpn_ah_rhnode *ah_rhnode)
{
	kmem_cache_free(pbb_b_l2vpn_ah_rhnode_cache, ah_rhnode);
}

static inline int pbb_l2vpn_ah_cmp(struct rhashtable_compare_arg *arg,
                              const void *ptr)
{
        const struct pbb_l2vpn_ah_rhnode *ah_rhnode = ptr;
        u32 rhnode_key = *(u32 *)arg->key;

        return (ah_rhnode->rhnode_key != rhnode_key);
}

static const struct rhashtable_params pbb_l2vpn_ah_rht_params = {
        .head_offset = offsetof(struct pbb_l2vpn_ah_rhnode, rhnode_hash),
        .key_offset = offsetof(struct pbb_l2vpn_ah_rhnode, rhnode_key),
        .key_len = sizeof(u32),
        .nelem_hint = 3,
        .max_size = PBB_L2VPN_AH_RHT_LEN_MAX,
        .obj_cmpfn = pbb_l2vpn_ah_cmp,
        .automatic_shrinking = true,
};

int pbb_l2vpn_ah_rht_init(struct rhashtable *tbl)
{
	return rhashtable_init(tbl, &pbb_l2vpn_ah_rht_params);
}

int pbb_l2vpn_ah_rhnode_insert(struct rhashtable *tbl, struct rhash_head *rhnode_hash)
{
	if (!rhnode_hash) {
		return -EINVAL;
	}

        return rhashtable_lookup_insert_fast(tbl, rhnode_hash, pbb_l2vpn_ah_rht_params);
}

struct pbb_l2vpn_ah_rhnode *pbb_l2vpn_ah_rhnode_lookup(struct rhashtable *tbl, u32 *rhnode_key)
{
	if (!rhnode_key) {
		return NULL;
	}

        return (struct pbb_l2vpn_ah_rhnode *)rhashtable_lookup_fast(tbl, rhnode_key, pbb_l2vpn_ah_rht_params);
}

void pbb_l2vpn_ah_rht_deinit(struct rhashtable *tbl)
{
	rhashtable_destroy(tbl);

	printk(KERN_INFO "PBB L2VPN AH RHT De-Init Done");
}

/* PBB L2VPN FDB Data Structure Manipulation APIs */
static struct kmem_cache *pbb_l2vpn_fdb_rhnode_cache __read_mostly;

static int __init pbb_l2vpn_fdb_init(void)
{
	pbb_l2vpn_fdb_rhnode_cache = kmem_cache_create("pbb_l2vpn_fdb_rhnode_cache",
							sizeof(struct pbb_l2vpn_fdb_rhnode),
					 		0,
					 		SLAB_HWCACHE_ALIGN, NULL);

	if (!pbb_l2vpn_fdb_rhnode_cache) {
		printk(KERN_ERR "%s: Failed to allocate cache memory for pbb_l2vpn_fdb_rhnode_cache!",
		       __FUNCTION__);

		return -ENOMEM;
	}

	printk(KERN_INFO "PBB L2VPN FDB Init Done");

	return 0;
}

static void pbb_l2vpn_fdb_deinit(void)
{
	kmem_cache_destroy(pbb_l2vpn_fdb_rhnode_cache);
}

struct pbb_l2vpn_fdb_rhnode *pbb_l2vpn_fdb_rhnode_alloc(void)
{
	return (struct pbb_l2vpn_fdb_rhnode *)kmem_cache_alloc(pbb_l2vpn_fdb_rhnode_cache, GFP_ATOMIC);
}

void pbb_l2vpn_fdb_rhnode_free(struct pbb_l2vpn_fdb_rhnode *fdb_rhnode)
{
	kmem_cache_free(pbb_l2vpn_fdb_rhnode_cache, fdb_rhnode);
}

static inline int pbb_l2vpn_fdb_cmp(struct rhashtable_compare_arg *arg,
                                    const void *ptr)
{
        const struct pbb_l2vpn_fdb_rhnode *fdb_rhnode = ptr;
        struct pbb_l2vpn_fdb_rhnode_key fdb_rhnode_key = {0};
	memcpy(&fdb_rhnode_key, (struct pbb_l2vpn_fdb_rhnode_key *)arg->key, sizeof(struct pbb_l2vpn_fdb_rhnode_key));

        return memcmp(&fdb_rhnode->fdb_rhnode_key, &fdb_rhnode_key, sizeof(struct pbb_l2vpn_fdb_rhnode_key));
}

static const struct rhashtable_params pbb_l2vpn_fdb_rht_params = {
        .head_offset = offsetof(struct pbb_l2vpn_fdb_rhnode, fdb_rhnode_hash),
        .key_offset = offsetof(struct pbb_l2vpn_fdb_rhnode, fdb_rhnode_key),
        .key_len = sizeof(struct pbb_l2vpn_fdb_rhnode_key),
        //.max_size = PBB_L2VPN_FDB_RHT_LEN_MAX,
        //.obj_cmpfn = pbb_l2vpn_fdb_cmp,
        .automatic_shrinking = true,
};

int pbb_l2vpn_fdb_rht_init(struct rhashtable *tbl)
{
	return rhashtable_init(tbl, &pbb_l2vpn_fdb_rht_params);
}

int pbb_l2vpn_fdb_rhnode_insert(struct rhashtable *tbl, struct rhash_head *fdb_rhnode_hash)
{
	if (!fdb_rhnode_hash) {
		return -EINVAL;
	}

        return rhashtable_lookup_insert_fast(tbl, fdb_rhnode_hash, pbb_l2vpn_fdb_rht_params);
}

struct pbb_l2vpn_fdb_rhnode *pbb_l2vpn_fdb_rhnode_lookup(struct rhashtable *tbl, struct pbb_l2vpn_fdb_rhnode_key *fdb_rhnode_key)
{
	if (!fdb_rhnode_key) {
		return NULL;
	}

        return (struct pbb_l2vpn_fdb_rhnode *)rhashtable_lookup_fast(tbl, fdb_rhnode_key, pbb_l2vpn_fdb_rht_params);
}

int pbb_l2vpn_fdb_rhnode_remove(struct rhashtable *tbl, struct rhash_head *fdb_rhnode_hash)
{
	if (!fdb_rhnode_hash) {
		return -EINVAL;
	}

        return rhashtable_remove_fast(tbl, fdb_rhnode_hash, pbb_l2vpn_fdb_rht_params);
}

void pbb_l2vpn_fdb_rht_deinit(struct rhashtable *tbl)
{
	rhashtable_destroy(tbl);
}

void pbb_l2vpn_fdb_get_flood_mac_for_sid(unsigned char flood_mac[], u32 sid)
{
	memset((void *)flood_mac, 0xFF, ETH_ALEN);
}

/* PBB Generic L2VPN Data Structure Manipulation APIs */
int pbb_l2vpn_init(void)
{
	int ret = 0;

	printk(KERN_INFO "%s called", __FUNCTION__);

	ret = pbb_l2vpn_ah_init();
	if (ret < 0) {
		printk(KERN_INFO "%s: pbb_l2vpn_ah_init() failed with error:0x%x",
		       __FUNCTION__, ret);

		return ret;
	}

	ret = pbb_l2vpn_fdb_init();
	if (ret < 0) {
		printk(KERN_INFO "%s: pbb_l2vpn_fdb_init() failed with error:0x%x",
		       __FUNCTION__, ret);

		return ret;
	}

	printk(KERN_INFO "PBB L2VPN Init Done");

	return ret;
}

void pbb_l2vpn_deinit(void)
{
	pbb_l2vpn_ah_deinit();
	pbb_l2vpn_fdb_deinit();

	printk(KERN_INFO "PBB L2VPN Deinit Done");
}
/***************************************** PBB Module APIs **************************************/
/*
 * init/fini
 */

static __init int pbb_init_module(void)
{
	int err = 0;

	printk(KERN_INFO "%s: PBB Virtual Driver Module Init", __FUNCTION__);

	err = pbb_b_rtnl_link_register();
	if (err < 0) {
		printk(KERN_ERR "%s: Failed to register PBB_B RTNL Link!", __FUNCTION__);
		return err;
	}

	err = pbb_i_rtnl_link_register();
	if (err < 0) {
		printk(KERN_ERR "%s: Failed to register PBB_B RTNL Link!", __FUNCTION__);
		goto unregister_pbb_b_rtnl_link;
	}

	pbb_b_netdev_notifier_register();

	err = pbb_l2vpn_init();
	if (err < 0) {
		printk(KERN_ERR "%s: Failed to initialize PBB L2VPN objects!", __FUNCTION__);
		goto unregister_pbb_netdev_notifier_pbb_i_rtnl_link;
	}

	return 0;

unregister_pbb_netdev_notifier_pbb_i_rtnl_link:
	pbb_b_netdev_notifier_unregister();
	pbb_i_rtnl_link_unregister();

unregister_pbb_b_rtnl_link:
	pbb_b_rtnl_link_unregister();

	printk(KERN_ERR "%s: PBB Virtual Driver Module Init Failed!", __FUNCTION__);

	return err;
}

static __exit void pbb_cleanup_module(void)
{
	printk(KERN_INFO "%s: PBB Virtual Driver Module Cleanup", __FUNCTION__);

	pbb_i_rtnl_link_unregister();
	pbb_b_rtnl_link_unregister();

	pbb_b_netdev_notifier_unregister();

	pbb_l2vpn_deinit();
}

module_init(pbb_init_module);
module_exit(pbb_cleanup_module);

MODULE_DESCRIPTION("Barebones Provider Backbone Bridging Virtual Driver");
MODULE_LICENSE("GPL v2");
MODULE_ALIAS_RTNL_LINK(PBB_DRV_NAME);
