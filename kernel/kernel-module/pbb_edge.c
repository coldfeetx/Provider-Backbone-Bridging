// SPDX-License-Identifier: GPL-2.0-only
/*
 *  drivers/net/pbb_edge.c
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

/***************************************** Generic PBB-I Routines ***********************************************/

/***************************************** Netdevice Routines *************************************************/
/***************************************** I-Driver Netdevice Routines ****************************************/

static int pbb_i_init(struct net_device *pbb_i)
{
	struct pbb_i_priv *i_priv = netdev_priv(pbb_i);

	pbb_info(pbb_i, "%s: Processing PBB_I Device Init State:%lu feat:%llu", __FUNCTION__, pbb_i->state, pbb_i->features);

	pbb_i->priv_flags |= IFF_PBB_I;

	if (!i_priv->pcpu_stats) {
		i_priv->pcpu_stats = netdev_alloc_pcpu_stats(struct pbb_pcpu_stats);
	}
	if (!i_priv->pcpu_stats) {
		pbb_err(pbb_i, "%s: Failed to allocate PBB_I pcpu stats!",
			__FUNCTION__);
	
		return -ENOMEM;
	}
 
	return 0;
}

//FIXME: To be filled later once PBB_B and PBB_I code is in
static void pbb_i_uninit(struct net_device *pbb_i)
{
	struct pbb_i_priv *i_priv = NULL;

	if (!pbb_i) {
		printk(KERN_ERR "%s: PBB_I invalid!", __FUNCTION__);

		return;
	}

	i_priv = netdev_priv(pbb_i);
	if (!i_priv) {
		printk(KERN_ERR "%s: PBB_I Private Metadata invalid!", __FUNCTION__);

		return;
	}

	pbb_info(pbb_i, "%s: Processing PBB_I Device Uninit", __FUNCTION__);


	if (i_priv->pcpu_stats) {
        	free_percpu(i_priv->pcpu_stats);
		i_priv->pcpu_stats = NULL;
	}

	pbb_i->priv_flags &= ~IFF_PBB_I;
}

static int pbb_i_open(struct net_device *pbb_i)
{
	struct pbb_i_priv *i_priv = netdev_priv(pbb_i);
	struct net_device *pbb_b = rtnl_dereference(i_priv->pbb_b);

	pbb_info(pbb_i, "%s: Are Only Info PBB_I Device Open", __FUNCTION__);

	if (!pbb_b) {
		pbb_info(pbb_i, "%s: PBB_B is not yet connected", __FUNCTION__);

		return -ENOTCONN;
	}

	if (pbb_b->flags & IFF_UP) {
		pbb_info(pbb_i, "%s: Setting PBB_I and PBB_B:%s Carrier On",
			 __FUNCTION__, pbb_b ? pbb_b->name : "NULL");
		netif_carrier_on(pbb_b);
		netif_carrier_on(pbb_i);
	}

	return 0;
}

static int pbb_i_stop(struct net_device *pbb_i)
{
	struct pbb_i_priv *i_priv = netdev_priv(pbb_i);
	struct net_device *pbb_b = rtnl_dereference(i_priv->pbb_b);

	pbb_info(pbb_i, "%s: PBB_I Device Stop", __FUNCTION__);

	if (!pbb_b) {
		pbb_err(pbb_i, "%s: PBB_B is not connected", __FUNCTION__);
	}

	if (pbb_b) {
		pbb_info(pbb_i, "%s: Setting carrier Off for PBB_B:%s",
			 __FUNCTION__, pbb_b->name);
		netif_carrier_off(pbb_b);
	}

	pbb_info(pbb_i, "%s: Setting carrier Off for PBB_I", __FUNCTION__);
	netif_carrier_off(pbb_i);
	
	return 0;

}

// TODO: For now return PBB_I own ifindex
// FIXME: To return PBB_I Peer PBB_B ifindex, instead?
static int pbb_i_get_iflink(const struct net_device *pbb_i)
{
	return pbb_i->ifindex;
}

// Return Underlying PBB_B Device for PBB_I Instance
static struct net_device *pbb_i_get_peer_dev(struct net_device *pbb_i)
{
	struct pbb_i_priv *i_priv = netdev_priv(pbb_i);
	struct net_device *pbb_b = rtnl_dereference(i_priv->pbb_b);

	return pbb_b;
}

/* FIXME/TODO: Perform the following functions -
 * Verify 8021q/8021ad headers (ctag/stag) as per bridge vlan protocol (as applicable to pbb edge side)
 * Then based on ctag/stag in tags perform lookup to fetch session_id
 * Then as per actions configured for ctag/stag, retain/strip ctag/stag respectively
 * Do a Customer mac lookup (with bridged ctag/stag bd) to identify the other site pbb edge node remote host is associated with
 * Encapsulate inner packet with 8021q/ad + 8021ah headers and invoke pbb core tx function
 * (with will map session id to backbone b-vid as per 8021q/ad configured on pbb core side)
 */
static netdev_tx_t pbb_i_xmit(struct sk_buff *skb, struct net_device *pbb_i)
{
	struct pbb_i_priv *i_priv = netdev_priv(pbb_i);
	struct pbb_b_priv *b_priv = NULL;
	struct net_device *pbb_b = rtnl_dereference(i_priv->pbb_b);
	unsigned int len = skb ? skb->len : 0;
	int ret = NETDEV_TX_OK;
	bool svlan_present = false, cvlan_present = false;
        u16  svlan_proto = 0, svlan_tag = 0,
             cvlan_proto = 0, cvlan_tag = 0, proto = 0;

	if (!pbb_i || !pbb_b) {
		return NET_XMIT_DROP;
	}

	if (!skb) {
		return NET_XMIT_DROP;
	}

	b_priv = netdev_priv(pbb_b);

#ifdef PBB_DEBUG
	pbb_qinq_dump_skb(skb, TX);
#endif // PBB_DEBUG

	/* TODO PBB Edge TX Processing.
	 *
	 * 1. Detect and extract the c and s tags from the frame and do an l2vpn lookup to get action and sid
	 * 2. Detect and extract the source mac and add it in the fdb with [local,sid,smac]
	 * 3. Detect and extract the destination mac and do a lookup based on [core,sid,dmac] below -
	 *  	a. If core mac lookup is a hit -
	 *		i. do another l2vpn lookup with (sid,core) to get bvid then match bvid with bvlan_tci of core mac result
	 *		ii. Then do a lookup with [core_underlay,bvid,encap_mac] to get result. If this returns a hit this is a case of known encap, else same as B/UU case.
	 *	b. Do inner encap action based on c,s action retrieved in step 1.
	 *	c. If inner is B/UU case (either via step 3 returning miss or step 3.a.ii returning miss) -
	 *		Then do outer encap with all FFs (for now).
	 *	d. Else -
	 *		Do outer encap with core mac.
	 *	e. Send the packet out to Core.
	 */
	dot1ad_ethhdr *dot1ad_eth_hdr = (dot1ad_ethhdr *)skb_eth_hdr(skb);
	if ((htons(dot1ad_eth_hdr->c_svlan_proto) == ETH_P_8021AD)) {
	    svlan_present = true;
	    svlan_proto   = ETH_P_8021AD;
	    svlan_tag	  = vlan_tag_get_id(ntohs(dot1ad_eth_hdr->c_svlan_tci));
	}
	if (htons(dot1ad_eth_hdr->c_cvlan_proto) == ETH_P_8021Q) {
                cvlan_present   = true;
                cvlan_proto     = ETH_P_8021Q;
                cvlan_tag       = vlan_tag_get_id(ntohs(dot1ad_eth_hdr->c_cvlan_tci));
                proto           = htons(dot1ad_eth_hdr->c_proto);
        } else if ((svlan_present == false) &&
                 (htons(dot1ad_eth_hdr->c_svlan_proto) == ETH_P_8021Q)) {
                cvlan_present   = true;
                cvlan_proto     = ETH_P_8021Q;
                cvlan_tag       = vlan_tag_get_id(ntohs(dot1ad_eth_hdr->c_svlan_tci));
                proto           = htons(dot1ad_eth_hdr->c_cvlan_proto);
	}

        // Detect and extract the c and s tags from the frame and do an l2vpn lookup to get action and sid
	u32 rhnode_key = 0;
	ret = pbb_l2vpn_ah_rhnode_type_c_cstag_key_add(&rhnode_key, cvlan_tag, svlan_tag);
	if (ret != 0) {
		return NET_XMIT_DROP;
	}
	struct pbb_l2vpn_ah_rhnode *ah_rhnode_core = pbb_l2vpn_ah_rhnode_lookup(&b_priv->pbb_l2vpn_ah_rht, &rhnode_key);
	if (ah_rhnode_core == NULL) {
		return NET_XMIT_DROP;
	}
	union pbb_l2vpn_ah_rhnode_info rhnode_info = {0};
	memcpy(&rhnode_info.c_qinq_edge_hash_info, &ah_rhnode_core->rhnode_info.c_qinq_edge_hash_info, sizeof(u32));
	u32 isid = PBB_L2VPN_RHNODE_TYPE_I_SID_INFO_MASK & rhnode_info.c_qinq_edge_hash_info;

	// Detect and extract the c and s tags from the frame and do an l2vpn lookup to get action and sid
	struct pbb_l2vpn_fdb_rhnode *fdb_rhnode_source = pbb_l2vpn_fdb_rhnode_alloc();
	if (fdb_rhnode_source == NULL) {
		return NET_XMIT_DROP;
	}

	memset(fdb_rhnode_source, 0, sizeof(struct pbb_l2vpn_fdb_rhnode));
	fdb_rhnode_source->fdb_rhnode_key.type = PBB_MAC_TYPE_EDGE;
	memcpy(fdb_rhnode_source->fdb_rhnode_key.mac, dot1ad_eth_hdr->c_smac, ETH_ALEN);
	fdb_rhnode_source->fdb_rhnode_key.pbb_l2vpn_bd = isid;
	struct pbb_l2vpn_fdb_rhnode *fdb_rhnode_smac = pbb_l2vpn_fdb_rhnode_lookup(&b_priv->pbb_l2vpn_fdb_rht, &fdb_rhnode_source->fdb_rhnode_key);
	if (fdb_rhnode_smac &&
	    (!strcmp(fdb_rhnode_smac->fdb_ifinfo.edge_ifinfo.in_dev->name, skb->dev->name)) &&
	    (fdb_rhnode_smac->fdb_ifinfo.edge_ifinfo.cvlan_tci == cvlan_tag) &&
	    (fdb_rhnode_smac->fdb_ifinfo.edge_ifinfo.svlan_tci == svlan_tag) &&
	    (fdb_rhnode_smac->fdb_rhnode_flags == PBB_MAC_FLAGS_DYNAMIC)) {
	} else {
		fdb_rhnode_source->fdb_ifinfo.edge_ifinfo.in_dev = skb->dev;
		fdb_rhnode_source->fdb_ifinfo.edge_ifinfo.cvlan_tci = cvlan_tag;
		fdb_rhnode_source->fdb_ifinfo.edge_ifinfo.svlan_tci = svlan_tag;
        	fdb_rhnode_source->fdb_rhnode_flags = PBB_MAC_FLAGS_DYNAMIC;
		pbb_l2vpn_fdb_rhnode_insert(&b_priv->pbb_l2vpn_fdb_rht, &fdb_rhnode_source->fdb_rhnode_hash);
	}

	unsigned char bb_dmac[ETH_ALEN] = {0}, bb_smac[ETH_ALEN] = {0};
	struct pbb_l2vpn_fdb_rhnode *fdb_rhnode_dmac = NULL;

	memcpy(bb_smac, pbb_b->dev_addr, ETH_ALEN);
	if (!is_multicast_ether_addr(dot1ad_eth_hdr->c_dmac) && !is_broadcast_ether_addr(dot1ad_eth_hdr->c_dmac)) {
		// Detect and extract the destination mac and do a lookup based on [core,sid,dmac] below
        	struct pbb_l2vpn_fdb_rhnode_key fdb_rhnode_key = {0};
		fdb_rhnode_key.type = PBB_MAC_TYPE_CORE;
		memcpy(fdb_rhnode_key.mac, dot1ad_eth_hdr->c_dmac, ETH_ALEN);
		fdb_rhnode_key.pbb_l2vpn_bd = isid;
        	fdb_rhnode_dmac = pbb_l2vpn_fdb_rhnode_lookup(&b_priv->pbb_l2vpn_fdb_rht, &fdb_rhnode_key);
	}
	if (fdb_rhnode_dmac) {
		if (!strcmp(fdb_rhnode_dmac->fdb_ifinfo.core_ifinfo.b_dev->name, pbb_b->name)) {
			return NET_XMIT_DROP;
		}

		memcpy(bb_dmac, fdb_rhnode_dmac->fdb_ifinfo.core_ifinfo.core_nh_mac, ETH_ALEN); 
	} else {
		pbb_l2vpn_fdb_get_flood_mac_for_sid(bb_dmac, isid);
	}

	// Encap outer with 802.1ah
	// Set everything except the backbone fields which will be filled by PBB_B driver
	//skb_push(skb, sizeof(dot1ah_outer_ethhdr));
	char *old_pkt_hdr = kmalloc(skb->len, GFP_KERNEL);
	if (old_pkt_hdr == NULL) {
		return NET_XMIT_DROP;
	}

	// FIXME: Use skb_copy_bits() family of APIs?
	memcpy(old_pkt_hdr, skb->data, skb->len);
	int old_skb_len = skb->len;

	dot1ad_eth_hdr = (dot1ad_ethhdr *)old_pkt_hdr;

	skb_cow(skb, sizeof(dot1ah_outer_ethhdr));
	dot1ah_outer_ethhdr *dot1ah_outer_eth_hdr = (dot1ah_outer_ethhdr *)skb_eth_hdr(skb);
	memset(dot1ah_outer_eth_hdr, 0, sizeof(dot1ah_outer_ethhdr));
	memcpy(dot1ah_outer_eth_hdr->bb_dmac, bb_dmac, ETH_ALEN);
	memcpy(dot1ah_outer_eth_hdr->bb_smac, bb_smac, ETH_ALEN);
	dot1ah_outer_eth_hdr->bb_vlan_proto = b_priv->pbb_b_port->flags & PBB_B_PORT_FLAGS_MODE_DOT1AD ? ntohs(ETH_P_8021AD) : ntohs(ETH_P_8021Q);
	dot1ah_outer_eth_hdr->bb_vlan_tci = 0;
	dot1ah_outer_eth_hdr->bb_1ah_proto = ntohs(ETH_P_8021AH);
	dot1ah_outer_eth_hdr->bb_1ah_isid = htonl(isid);

	dot1ad_ethhdr *new_dot1ad_eth_hdr = (dot1ad_ethhdr *)(dot1ah_outer_eth_hdr+1);//FIXME
	// Copy old skb end-data to new skb area. FIXME: To copy tail-end also?
	memmove(new_dot1ad_eth_hdr, old_pkt_hdr, old_skb_len);

	skb->len += sizeof(dot1ah_outer_ethhdr);
	// FIXME: Fix checksum?

	// Operate on inner 802.1ad/802.1q/802.1 based on C/S action specified
	bool svlan_strip = false;
	if (((rhnode_info.c_qinq_edge_hash_info & PBB_L2VPN_RHNODE_TYPE_C_STAG_INFO_ACTION_MASK) >> PBB_L2VPN_RHNODE_TYPE_I_SID_CTAG_ACTION_INFO_SHIFT) == PBB_L2VPN_RHNODE_TYPE_C_STAG_INFO_ACTION_STRIP) {
		if (svlan_present && (svlan_proto == ETH_P_8021AD)) {
#if 1
			// FIXME: Field spanning write!
			memmove((char *)(&new_dot1ad_eth_hdr->c_svlan_proto), (char *)(&dot1ad_eth_hdr->c_cvlan_proto), old_skb_len - ((char *)(&dot1ad_eth_hdr->c_cvlan_proto) - (char *)dot1ad_eth_hdr));
			skb_trim(skb, skb->len - sizeof(u32));
			svlan_strip = true;
			//skb->end -= sizeof(u32); //FIXME: Required to adjust skb->end also?
#else
			u16 svlan_tci = 0;
			vlan_remove_tag(skb, &svlan_tci);
#endif // CRAP
		}
	 }
	if (((rhnode_info.c_qinq_edge_hash_info & PBB_L2VPN_RHNODE_TYPE_C_CTAG_INFO_ACTION_MASK) >> PBB_L2VPN_RHNODE_TYPE_C_CTAG_INFO_ACTION_SHIFT) == PBB_L2VPN_RHNODE_TYPE_C_CTAG_INFO_ACTION_STRIP) {
		if (cvlan_present && (cvlan_proto == ETH_P_8021Q)) {
#if 1
			if (svlan_strip == true) {	
				memmove((char *)(&new_dot1ad_eth_hdr->c_svlan_proto), (char *)(&dot1ad_eth_hdr->c_proto), old_skb_len - ((char *)(&dot1ad_eth_hdr->c_proto) - (char *)dot1ad_eth_hdr));
			} else {
				memmove((char *)(&new_dot1ad_eth_hdr->c_cvlan_proto), (char *)(&dot1ad_eth_hdr->c_proto), old_skb_len - ((char *)(&dot1ad_eth_hdr->c_proto) - (char *)dot1ad_eth_hdr));
			}
			skb_trim(skb, skb->len - sizeof(u32));
			//skb->end -= sizeof(u32); //FIXME: Required to adjust skb->end also?
			// FIXME: Fix checksum?
#else
			u16 cvlan_tci = 0;
			vlan_remove_tag(skb, &cvlan_tci);
#endif // CRAP
		}
	}

	if (old_pkt_hdr) {
		kfree(old_pkt_hdr);

		old_pkt_hdr = NULL;
		dot1ad_eth_hdr = NULL;
	}

#ifdef PBB_DEBUG
	pbb_dump_skb(skb, TX);
#endif // PBB_DEBUG

	// Handoff to Bridge PBB-B device driver instance
	skb->dev = pbb_b;

	ret = dev_queue_xmit(skb);

	/* Do Tx stats accounting for PBB_I Device */
	struct pbb_pcpu_stats *pcpu_stats = this_cpu_ptr(i_priv->pcpu_stats);
	if (!pcpu_stats) {
		return ret;
	}

	if (likely(ret == NET_XMIT_SUCCESS || ret == NET_XMIT_CN) || (ret == NETDEV_TX_OK)) {
        	u64_stats_update_begin(&pcpu_stats->syncp);
        	u64_stats_inc(&pcpu_stats->tx_packets);
        	u64_stats_add(&pcpu_stats->tx_bytes, len);
                if (is_multicast_ether_addr(eth_hdr(skb)->h_dest))
                        u64_stats_inc(&pcpu_stats->rx_multicast);
        	u64_stats_update_end(&pcpu_stats->syncp);
        } else {
                this_cpu_inc(pcpu_stats->tx_dropped);
        }

        return ret;
}

static const struct net_device_ops pbb_i_netdev_ops = {
        .ndo_init		= pbb_i_init,
	.ndo_uninit		= pbb_i_uninit,
        .ndo_open		= pbb_i_open,
        .ndo_stop		= pbb_i_stop,
	.ndo_start_xmit		= pbb_i_xmit,
        .ndo_get_iflink		= pbb_i_get_iflink,
	.ndo_get_peer_dev	= pbb_i_get_peer_dev,
	.ndo_set_mac_address	= eth_mac_addr,
        .ndo_features_check	= passthru_features_check,
	.ndo_validate_addr	= eth_validate_addr,
	.ndo_get_stats64        = pbb_get_stats64,
};

/***************************************** B-Driver Core Routines ************************************/
/* called under rcu_read_lock() from netif_receive_skb */
static rx_handler_result_t pbb_i_handle_frame_from_core(struct sk_buff **pskb)
{
	struct net_device *pbb_i = NULL, *pbb_b = NULL;
	struct pbb_i_priv *i_priv = NULL;
	struct pbb_b_priv *b_priv = NULL;
	struct sk_buff *skb = NULL;
	unsigned int len = 0;
	bool svlan_present = false, cvlan_present = false;
	u32 svlan_tci_action = PBB_I_VID_INFO_ACTION_MAX, cvlan_tci_action = PBB_I_VID_INFO_ACTION_MAX;
	int svlan_tci = -1, svlan_tag = -1, cvlan_tci = -1, cvlan_tag = -1;
	int ret = NET_RX_SUCCESS;
	rx_handler_result_t handle_res = RX_HANDLER_CONSUMED;
	int err = 0;

	if (!pskb || !*pskb) {
                goto handle_failure;
	}

	skb = *pskb;

        /* Packets from dev_loopback_xmit() do not have L2 header, bail out */
        if (unlikely(skb->pkt_type == PACKET_LOOPBACK)) {
                return RX_HANDLER_PASS;
	}

	if (!skb->dev) {
                goto handle_failure;
	}

        pbb_i = rcu_dereference(skb->dev->rx_handler_data);
        if (!pbb_i) {
                goto handle_failure;
        }

	i_priv = netdev_priv(pbb_i);
	if (!i_priv) {
                goto handle_failure;
        }

	pbb_b = rtnl_dereference(i_priv->pbb_b);
	if (!pbb_b) {
                goto handle_failure;
        }

        b_priv = netdev_priv(pbb_b);
	if (!b_priv) {
                goto handle_failure;
        }

        // FIXME: skb->dev = pbb_i should allow br_handle_frame to get called, right?
        skb->dev = pbb_i;

	if (!(pbb_i->flags & IFF_UP)) {
                goto handle_failure;
        }

	dot1ah_outer_ethhdr_in *dot1ah_outer_eth_hdr_in = (dot1ah_outer_ethhdr_in *)eth_hdr(skb);

	if (dot1ah_outer_eth_hdr_in == NULL) {
	        goto handle_failure;
	}
	
#ifdef PBB_DEBUG
	pbb_dump_skb(skb, RX);
#endif // PBB_DEBUG
	
	/* TODO: PBB-I Core Receive Path Processing Routine as per 8021ah.
	*/
	if (htons(dot1ah_outer_eth_hdr_in->bb_1ah_proto) != ETH_P_8021AH) {
		goto handle_failure;
	}
	
	u32 isid = htonl(dot1ah_outer_eth_hdr_in->bb_1ah_isid);

	// Validate and Lookup Core Source mac and add to FDB if not present
	dot1ad_ethhdr *dot1ad_eth_hdr = (dot1ad_ethhdr *)((char *)dot1ah_outer_eth_hdr_in + sizeof(dot1ah_outer_ethhdr_in));
	
	if (is_multicast_ether_addr(dot1ad_eth_hdr->c_smac) || is_broadcast_ether_addr(dot1ad_eth_hdr->c_smac)) {
		goto handle_failure;
	}

	if (htons(dot1ad_eth_hdr->c_svlan_proto) == ETH_P_8021AD) {
		svlan_present  = true;
		svlan_tag      = vlan_tag_get_id(ntohs(dot1ad_eth_hdr->c_svlan_tci));
	} else if (htons(dot1ad_eth_hdr->c_svlan_proto) == ETH_P_8021Q) {
		cvlan_present  = true;
		cvlan_tag      = vlan_tag_get_id(ntohs(dot1ad_eth_hdr->c_svlan_tci));
	}
	
	if ((svlan_present == true) && htons(dot1ad_eth_hdr->c_cvlan_proto) == ETH_P_8021Q) {
		cvlan_present  = true;
		cvlan_tag      = vlan_tag_get_id(ntohs(dot1ad_eth_hdr->c_cvlan_tci));
	}
	
	u32 rhnode_key = 0;
	ret = pbb_l2vpn_ah_rhnode_type_i_sid_key_add(&rhnode_key, isid, PBB_L2VPN_RHNODE_TYPE_I_SID_KEY_DIR_EDGE);
	if (ret) {
	        goto handle_failure;
	}
	struct pbb_l2vpn_ah_rhnode *ah_rhnode_core = pbb_l2vpn_ah_rhnode_lookup(&b_priv->pbb_l2vpn_ah_rht, &rhnode_key);
	if (ah_rhnode_core != NULL) {
		// Extract the c/svlan tci actions and values
		u32 csvlan_tci_action	= ah_rhnode_core->rhnode_info.c_qinq_core_hash_info & PBB_L2VPN_RHNODE_TYPE_C_CSTAG_INFO_ACTION_MASK;
		svlan_tci_action 	= (csvlan_tci_action & PBB_L2VPN_RHNODE_TYPE_C_STAG_INFO_ACTION_MASK) >> PBB_L2VPN_RHNODE_TYPE_I_SID_CTAG_ACTION_INFO_SHIFT;
		cvlan_tci_action 	= (csvlan_tci_action & PBB_L2VPN_RHNODE_TYPE_C_CTAG_INFO_ACTION_MASK) >> PBB_L2VPN_RHNODE_TYPE_C_CTAG_INFO_ACTION_SHIFT;
		svlan_tci	 	= (ah_rhnode_core->rhnode_info.c_qinq_core_hash_info & PBB_L2VPN_RHNODE_TYPE_C_STAG_KEY_MASK) >> PBB_L2VPN_RHNODE_TYPE_C_STAG_KEY_SHIFT;
		cvlan_tci	 	= (ah_rhnode_core->rhnode_info.c_qinq_core_hash_info & PBB_L2VPN_RHNODE_TYPE_C_CTAG_KEY_MASK) >> PBB_L2VPN_RHNODE_TYPE_C_CTAG_KEY_SHIFT;
	
		if ((svlan_tci_action == PBB_L2VPN_RHNODE_TYPE_C_STAG_INFO_ACTION_KEEP) && ((svlan_present == false) || (svlan_tag != svlan_tci))) {
			goto handle_failure;
		} else if ((svlan_tci_action == PBB_L2VPN_RHNODE_TYPE_C_STAG_INFO_ACTION_STRIP) && (svlan_present == false)) {
			if (((svlan_tci == 0) && (svlan_tag != -1))) {
				goto handle_failure;
			}
		}
	
		if ((cvlan_tci_action == PBB_L2VPN_RHNODE_TYPE_C_CTAG_INFO_ACTION_KEEP) && ((cvlan_present == false) || (cvlan_tag != cvlan_tci))) {
			goto handle_failure;
		} else if ((cvlan_tci_action == PBB_L2VPN_RHNODE_TYPE_C_CTAG_INFO_ACTION_STRIP) && (cvlan_present == false)) {
			if (((cvlan_tci == 0) && (cvlan_tag != -1))) {
				goto handle_failure;
			}
		}
	} else {
		rhnode_key = 0;
	        err = pbb_l2vpn_ah_rhnode_type_c_cstag_key_add(&rhnode_key, cvlan_tag, svlan_tag);
	        if (err) {
	                goto handle_failure;
	        }
	
	        ah_rhnode_core = pbb_l2vpn_ah_rhnode_lookup(&b_priv->pbb_l2vpn_ah_rht, &rhnode_key);
		if (ah_rhnode_core == NULL) {
	                goto handle_failure;
		}
	
		u32 sid_type_csvlan_tci_action	= ah_rhnode_core->rhnode_info.c_qinq_edge_hash_info;
		u8 sid_type			= (sid_type_csvlan_tci_action & PBB_L2VPN_RHNODE_TYPE_I_SID_TYPE_INFO_MASK) >> PBB_L2VPN_RHNODE_TYPE_I_SID_TYPE_INFO_SHIFT;
		u32 sid				= (sid_type_csvlan_tci_action & PBB_L2VPN_RHNODE_TYPE_I_SID_INFO_MASK) >> PBB_L2VPN_RHNODE_TYPE_I_SID_KEY_SHIFT;
		u32 svlan_tci_action		= (sid_type_csvlan_tci_action & PBB_L2VPN_RHNODE_TYPE_C_STAG_INFO_ACTION_MASK) >> PBB_L2VPN_RHNODE_TYPE_I_SID_CTAG_ACTION_INFO_SHIFT;
		u32 cvlan_tci_action		= (sid_type_csvlan_tci_action & PBB_L2VPN_RHNODE_TYPE_C_CTAG_INFO_ACTION_MASK) >> PBB_L2VPN_RHNODE_TYPE_C_CTAG_INFO_ACTION_SHIFT;
	
		if (sid != isid) {
	                goto handle_failure;
		}
	
		if (sid_type != PBB_L2VPN_RHNODE_TYPE_I_SID_TYPE_INFO_SHARED) {
	                goto handle_failure;
		}
	
		if (((svlan_tci_action == PBB_L2VPN_RHNODE_TYPE_C_STAG_INFO_ACTION_KEEP) && (svlan_present == false)) ||
		    ((cvlan_tci_action == PBB_L2VPN_RHNODE_TYPE_C_STAG_INFO_ACTION_KEEP) && (cvlan_present == false))) {
		    goto handle_failure;
		}

/*
		if ((svlan_tci_action == PBB_L2VPN_RHNODE_TYPE_C_STAG_INFO_ACTION_STRIP) && (svlan_present == false)) {
			goto handle_failure;
		}
	
		if ((cvlan_tci_action == PBB_L2VPN_RHNODE_TYPE_C_CTAG_INFO_ACTION_STRIP) && (cvlan_present == false)) {
			goto handle_failure;
		}
*/
	}
	
	struct pbb_l2vpn_fdb_rhnode fdb_rhnode_lkup;
	memset(&fdb_rhnode_lkup, 0, sizeof(struct pbb_l2vpn_fdb_rhnode));
	fdb_rhnode_lkup.fdb_rhnode_key.type = PBB_MAC_TYPE_CORE;
	memcpy(fdb_rhnode_lkup.fdb_rhnode_key.mac, dot1ad_eth_hdr->c_smac, ETH_ALEN);
	fdb_rhnode_lkup.fdb_rhnode_key.pbb_l2vpn_bd = isid;
	struct pbb_l2vpn_fdb_rhnode *fdb_rhnode_src = pbb_l2vpn_fdb_rhnode_lookup(&b_priv->pbb_l2vpn_fdb_rht, &fdb_rhnode_lkup.fdb_rhnode_key);
	if ((fdb_rhnode_src == NULL) ||
	    (memcmp(fdb_rhnode_src->fdb_ifinfo.core_ifinfo.core_nh_mac, dot1ah_outer_eth_hdr_in->bb_smac, ETH_ALEN)) ||
	    (strcmp(fdb_rhnode_src->fdb_ifinfo.core_ifinfo.b_dev->name, skb->dev->name))) {
		if (fdb_rhnode_src) {
			pbb_l2vpn_fdb_rhnode_remove(&b_priv->pbb_l2vpn_fdb_rht, &fdb_rhnode_src->fdb_rhnode_hash);
			pbb_l2vpn_fdb_rhnode_free(fdb_rhnode_src);
		}
		fdb_rhnode_src = pbb_l2vpn_fdb_rhnode_alloc();
		if (fdb_rhnode_src == NULL) {
			goto handle_failure;
		}
		memset(fdb_rhnode_src, 0, sizeof(struct pbb_l2vpn_fdb_rhnode));

		memcpy(fdb_rhnode_src, &fdb_rhnode_lkup, sizeof(struct pbb_l2vpn_fdb_rhnode));

		fdb_rhnode_src->fdb_ifinfo.core_ifinfo.b_dev = skb->dev;
		memcpy(fdb_rhnode_src->fdb_ifinfo.core_ifinfo.core_nh_mac, dot1ah_outer_eth_hdr_in->bb_smac, ETH_ALEN);
		fdb_rhnode_src->fdb_rhnode_flags = PBB_MAC_FLAGS_DYNAMIC;
		pbb_l2vpn_fdb_rhnode_insert(&b_priv->pbb_l2vpn_fdb_rht, &fdb_rhnode_src->fdb_rhnode_hash);
	}
	
	// Do basic validation of inner DMAC
	if (!is_multicast_ether_addr(dot1ad_eth_hdr->c_dmac) && !is_broadcast_ether_addr(dot1ad_eth_hdr->c_dmac)) {
		memset(&fdb_rhnode_lkup, 0, sizeof(struct pbb_l2vpn_fdb_rhnode));
		fdb_rhnode_lkup.fdb_rhnode_key.type = PBB_MAC_TYPE_EDGE;
		memcpy(&fdb_rhnode_lkup.fdb_rhnode_key.mac, dot1ad_eth_hdr->c_dmac, ETH_ALEN);
		fdb_rhnode_lkup.fdb_rhnode_key.pbb_l2vpn_bd = isid;
		struct pbb_l2vpn_fdb_rhnode *fdb_rhnode_dmac = pbb_l2vpn_fdb_rhnode_lookup(&b_priv->pbb_l2vpn_fdb_rht, &fdb_rhnode_lkup.fdb_rhnode_key);
		// TODO: Mac move not allowed as of now
		if (fdb_rhnode_dmac && strcmp(fdb_rhnode_dmac->fdb_ifinfo.edge_ifinfo.in_dev->name, skb->dev->name)) {
			goto handle_failure;
		}
	}
	
	/* Perform skb operations to decapsulate outer packet and extract inner packet and operate on it before sending it to Master bridge!
	 * TODO: Process for all cases of decap outer packet and extract/craft inner packet here!
	 */
	//skb->mac_header += sizeof(dot1ah_outer_ethhdr_in);
	if (cvlan_present || svlan_present || (cvlan_tci != -1) || (svlan_tci != -1)) {
		if ((svlan_tci > 0) || (svlan_tci < 0)) {
			skb->vlan_all = 1;
		}
		
		if (svlan_present || (svlan_tci > 0)) {
			skb->vlan_tci = (svlan_tag != -1) ? svlan_tag : svlan_tci;
			skb->protocol = skb->vlan_proto = htons(ETH_P_8021AD);
		} else if (cvlan_present || (cvlan_tci > 0)) {
			skb->vlan_tci = (cvlan_tag != -1) ? cvlan_tag : cvlan_tci;
			skb->protocol = skb->vlan_proto = htons(ETH_P_8021Q);
		}

		if (svlan_present || ((svlan_tci == 0) && cvlan_present)) {
			char *to_csvlan_proto = (char *)(&dot1ad_eth_hdr->c_svlan_proto), *from_cvlan_proto = (char *)(&dot1ad_eth_hdr->c_cvlan_proto);
			memmove(to_csvlan_proto, from_cvlan_proto, skb->len - skb_mac_offset(skb) - sizeof(dot1ah_outer_ethhdr_in) - offsetof(dot1ad_ethhdr, c_cvlan_proto));
		 }

#if 0
		 if ((svlan_tci_action == PBB_L2VPN_RHNODE_TYPE_C_STAG_INFO_ACTION_STRIP) && svlan_tci) {
			vlan_insert_tag(skb, ETH_P_8021AD, svlan_tci);
			skb_postpush_rcsum(skb, skb->data, skb->len);
		 }
#endif

		u32 old_mac_offset = skb_mac_offset(skb);
		skb_set_mac_header(skb, old_mac_offset + sizeof(dot1ah_outer_ethhdr_in));

		skb_pull_rcsum(skb, sizeof(dot1ah_outer_ethhdr_in));

		if ((svlan_tci > 0) && (cvlan_tci_action == PBB_L2VPN_RHNODE_TYPE_C_CTAG_INFO_ACTION_STRIP) && (cvlan_tci > 0)) {
#if 0
			vlan_insert_tag(skb, ETH_P_8021Q, cvlan_tci);
			skb_postpush_rcsum(skb, skb->data, skb->len);
#else
			int old_skb_len = skb->len + ETH_HLEN;

        		char *old_pkt_hdr = kmalloc(old_skb_len, GFP_KERNEL);
        		if (old_pkt_hdr == NULL) {
        		        goto handle_failure;
        		}

			//skb_copy_bits(skb, 0, old_pkt_hdr, old_skb_len);
			memcpy(old_pkt_hdr, skb_mac_header(skb), old_skb_len);
			skb_cow(skb, sizeof(dot1q_ethhdr));

			dot1q_ethhdr *new_dot1q_eth_hdr = (dot1q_ethhdr *)eth_hdr(skb);
			memset(new_dot1q_eth_hdr, 0, old_skb_len);
			memcpy(new_dot1q_eth_hdr, old_pkt_hdr, 2 * ETH_ALEN);
			new_dot1q_eth_hdr->c_cvlan_proto = htons(ETH_P_8021Q);
			new_dot1q_eth_hdr->c_cvlan_tci = htons(cvlan_tci);
			memcpy((char *)(&new_dot1q_eth_hdr->c_proto), old_pkt_hdr + (2 * ETH_ALEN), old_skb_len - (2 * ETH_ALEN));
			skb_put(skb, sizeof(u32));
			kfree(old_pkt_hdr);
#endif
		} else if (svlan_present || ((svlan_tci == 0) && cvlan_present)) {
			skb_trim(skb, skb->len - sizeof(u32));
		}
	}

#ifdef PBB_DEBUG
	pbb_qinq_dump_skb(skb, RX);
#endif // PBB_DEBUG

	len = skb->len + ETH_HLEN;
	
	skb->pkt_type = PACKET_HOST;
	*pskb = skb;
	
	ret = NET_RX_SUCCESS;
	handle_res = RX_HANDLER_ANOTHER;
	goto update_rx_stats;

handle_failure:
	if (skb) kfree(skb);
        ret = NET_RX_DROP;
        handle_res = RX_HANDLER_CONSUMED;
	if (!i_priv || !pbb_i) return handle_res;

update_rx_stats:
	/* Do Rx stats accounting for PBB_I Device */
	if (likely(ret == NET_RX_SUCCESS)) {
		struct pbb_pcpu_stats *pcpu_stats = get_cpu_ptr(i_priv->pcpu_stats);
		if (!pcpu_stats) {
			goto rx_handler_ret;
		}

                u64_stats_update_begin(&pcpu_stats->syncp);
                u64_stats_inc(&pcpu_stats->rx_packets);
                u64_stats_add(&pcpu_stats->rx_bytes, len);
		if (dot1ad_eth_hdr && is_multicast_ether_addr(dot1ad_eth_hdr->c_dmac))
                        u64_stats_inc(&pcpu_stats->rx_multicast);
                u64_stats_update_end(&pcpu_stats->syncp);
                put_cpu_ptr(pcpu_stats);
        } else {
                this_cpu_inc(i_priv->pcpu_stats->rx_errors);
        }

rx_handler_ret:
        return handle_res;
}


/***************************************** Netlink Routines ****************************************/
/***************************************** I-Driver Netlink Routines ****************************************/
static const struct device_type pbb_i_type = {
        .name = "pbbi",
};

static void pbb_i_setup(struct net_device *pbb_i)
{
	pbb_info(pbb_i, "%s: Setting Up PBB_I State:%lu",
		 __FUNCTION__, pbb_i->state);

	ether_setup(pbb_i);

	SET_NETDEV_DEVTYPE(pbb_i, &pbb_i_type);

       /* Fill in device structure with ethernet-generic values. */
        eth_hw_addr_random(pbb_i);

        pbb_i->priv_flags &= ~IFF_TX_SKB_SHARING;
        pbb_i->priv_flags |= IFF_LIVE_ADDR_CHANGE;
        pbb_i->priv_flags |= IFF_NO_QUEUE | IFF_CHANGE_PROTO_DOWN;

        pbb_i->netdev_ops = &pbb_i_netdev_ops;
        pbb_i->features |= PBB_I_FEATURES;
        pbb_i->vlan_features = pbb_i->features;

	pbb_i->needs_free_netdev = true;
//      pbb_i->priv_destructor = pbb_i_dev_free;

        pbb_i->pcpu_stat_type = NETDEV_PCPU_STAT_TSTATS;
        pbb_i->min_mtu = ETH_MIN_MTU;
        pbb_i->max_mtu = ETH_MAX_MTU;

        pbb_i->hw_features = PBB_I_FEATURES;
        pbb_i->hw_enc_features = PBB_I_FEATURES;
        pbb_i->mpls_features = NETIF_F_HW_CSUM | NETIF_F_GSO_SOFTWARE;
        netif_set_tso_max_size(pbb_i, GSO_MAX_SIZE);
	//pbb_i->tx_queue_len  = 0;
	//pbb_i->num_tx_queues = 0;
	//pbb_i->real_num_tx_queues = 0;

}

static int pbb_i_validate(struct nlattr *tb[], struct nlattr *data[],
			     struct netlink_ext_ack *extack)
{
	if (tb[IFLA_ADDRESS]) {
		if (nla_len(tb[IFLA_ADDRESS]) != ETH_ALEN) {	
			return -EINVAL;
		}
		if (!is_valid_ether_addr(nla_data(tb[IFLA_ADDRESS]))) {
			return -EADDRNOTAVAIL;
		}
	}
	if (tb[IFLA_MTU]) {
		if (nla_get_u32(tb[IFLA_MTU]) <= ETH_MAX_MTU) {
			return -EINVAL;
		}
	}

	return 0;
}

/* TODO: This Edge-Bridge Will be linkd to Core-Bridge via "ip link set"
 * (aka changelink sequence) not via "ip link add" (aka newlink sequence).
 */
static int pbb_i_newlink(struct net *src_net, struct net_device *pbb_i,
			 struct nlattr *tb[], struct nlattr *data[],
			 struct netlink_ext_ack *extack)
{
	int err = 0;

	pbb_info(pbb_i, "%s: Processing PBB_I Newlink State:%lu", __FUNCTION__, pbb_i->state);

	/*
	 * register PBB_I
	 */
	err = register_netdevice(pbb_i);
	if (err < 0)
		goto err_register_pbb_i;

	netif_carrier_off(pbb_i);

#if 0
	pbb_disable_gro(pbb_i);
#endif


	pbb_info(pbb_i, "%s: PBB_I NewLink processed successfully State:%lu",
		 __FUNCTION__, pbb_i->state);

	return 0;

err_register_pbb_i:
	pbb_err(pbb_i, "%s: PBB_B Registration failed with error:0x%x!",
		 __FUNCTION__, err);

	free_netdev(pbb_i);

	return err;
}

// FIXME TODO
static int pbb_i_changelink(struct net_device *pbb_i,
                            struct nlattr *tb[], struct nlattr *data[],
                            struct netlink_ext_ack *extack)
{
	struct net *src_net = NULL;
        struct net_device *pbb_b = NULL;
        struct pbb_i_priv *i_priv = NULL;
        struct pbb_b_priv *b_priv = NULL;
	bool pbbi_core_bridge_process = false, cvid_svid_isid_update = false;
	u8 cvid_info_action = PBB_I_VID_INFO_ACTION_MAX, svid_info_action = PBB_I_VID_INFO_ACTION_MAX, sid_type = PBB_I_ISID_TYPE_MAX, key_info_map_verify = 0;
	int err = 0;

	pbb_info(pbb_i, "%s: Processing PBB_I Changelink", __FUNCTION__);

	if (data && data[IFLA_PBB_I_CORE_BRIDGE_INFO]) {
		pbb_info(pbb_i, "%s: Processing PBB_I Core Bridge Info", __FUNCTION__);

		src_net = dev_net(pbb_i);
		if (!src_net) {
			pbb_err(pbb_i, "%s: Src Network Namespace does not exist yet!", __FUNCTION__);
			return -EINVAL;
		}

		pbb_b = __dev_get_by_index(src_net, nla_get_u32(data[IFLA_PBB_I_CORE_BRIDGE_INFO]));
		if (!pbb_b) {
			pbb_err(pbb_i, "%s: PBB_B Does not exist yet!", __FUNCTION__);
			return -ENODEV;
		}

		pbb_info(pbb_i, "%s: Linking PBB_I <-> PBB_B:%s",
			__FUNCTION__, pbb_b->name);

		/*
		 * tie the deviced together
		 */
		i_priv = netdev_priv(pbb_i);
		rcu_assign_pointer(i_priv->pbb_b, pbb_b);
		
		b_priv = netdev_priv(pbb_b);
		rcu_assign_pointer(b_priv->pbb_i, pbb_i);

		pbb_info(pbb_i, "%s: Registering Receive Handler with PBB_B:%s",
			__FUNCTION__, pbb_b->name);

		err = netdev_rx_handler_register(pbb_b, pbb_i_handle_frame_from_core, pbb_i);
	        if (err) {
	                pbb_err(pbb_i, "%s:Failed to register Rx Handler with error:%d for PBB_B:%s!",
	                        __FUNCTION__, err, pbb_b->name);
	
	                return err;
	        }

		pbbi_core_bridge_process = true;
	}

	i_priv = netdev_priv(pbb_i);
	pbb_b = rtnl_dereference(i_priv->pbb_b);
	if (!pbb_b) {
                pbb_err(pbb_i, "%s: PBB_B not linked yet!", __FUNCTION__);

		goto rx_handler_unregister;
	}
	b_priv = netdev_priv(pbb_b);
	if (!b_priv) {
		pbb_err(pbb_i, "%s: PBB_B Metadata not valid!", __FUNCTION__);

		goto rx_handler_unregister;
	}

	cvid_info_action = PBB_I_VID_INFO_ACTION_MAX;
	u8 cvlan_tci_action = 0;
	if (data && data[IFLA_PBB_I_CVID_INFO_ACTION]) {
		pbb_info(pbb_i, "%s: Processing PBB_I CVID Action Info", __FUNCTION__);

		cvid_info_action = nla_get_u8(data[IFLA_PBB_I_CVID_INFO_ACTION]);
		if (cvid_info_action == PBB_I_VID_INFO_ACTION_KEEP) {
			cvlan_tci_action = PBB_L2VPN_RHNODE_TYPE_C_CTAG_INFO_ACTION_KEEP;
		} else {
			cvlan_tci_action = PBB_L2VPN_RHNODE_TYPE_C_CTAG_INFO_ACTION_STRIP;
		}

		cvid_svid_isid_update = true;
	}

	svid_info_action = PBB_I_VID_INFO_ACTION_MAX;
	u8 svlan_tci_action = 0;
	if (data && data[IFLA_PBB_I_SVID_INFO_ACTION]) {
		pbb_info(pbb_i, "%s: Processing PBB_I SVID Action Info", __FUNCTION__);

		svid_info_action = nla_get_u8(data[IFLA_PBB_I_SVID_INFO_ACTION]);
		if (svid_info_action == PBB_I_VID_INFO_ACTION_KEEP) {
			svlan_tci_action = PBB_L2VPN_RHNODE_TYPE_C_STAG_INFO_ACTION_KEEP;
		} else {
			svlan_tci_action = PBB_L2VPN_RHNODE_TYPE_C_STAG_INFO_ACTION_STRIP;
		}

		cvid_svid_isid_update = true;
	}

	sid_type = PBB_I_ISID_TYPE_MAX;
	u8 isid_type = 0;
	if (data && data[IFLA_PBB_I_ISID_TYPE]) {
		pbb_info(pbb_i, "%s: Processing PBB_I ISID Type Info", __FUNCTION__);

		sid_type = nla_get_u8(data[IFLA_PBB_I_ISID_TYPE]);
		if (sid_type == PBB_I_ISID_TYPE_SHARED) {
			isid_type = PBB_L2VPN_RHNODE_TYPE_I_SID_TYPE_INFO_SHARED;
		} else {
			isid_type = PBB_L2VPN_RHNODE_TYPE_I_SID_TYPE_INFO_EXCL;
		}

		cvid_svid_isid_update = true;
	}

	if (data && data[IFLA_PBB_I_KEY_INFO_MAP_VERIFY]) {
		pbb_info(pbb_i, "%s: Processing PBB_B Changelink PBB_I Key Info Map Verify Notification",
			 __FUNCTION__);

		key_info_map_verify = nla_get_u8(data[IFLA_PBB_I_KEY_INFO_MAP_VERIFY]);

		cvid_svid_isid_update = true;
	}

	int c_vid_info_range_begin = -1, c_vid_info_range_end = -1, s_vid_info_range_begin = -1, s_vid_info_range_end = -1,
	    i_sid_info_range_begin = -1, i_sid_info_range_end = -1;

	if (data && data[IFLA_PBB_I_CVID_INFO_RANGE_BEGIN] && data[IFLA_PBB_I_CVID_INFO_RANGE_END]) {
		c_vid_info_range_begin = nla_get_u32(data[IFLA_PBB_I_CVID_INFO_RANGE_BEGIN]);
		c_vid_info_range_end = nla_get_u32(data[IFLA_PBB_I_CVID_INFO_RANGE_END]);

		cvid_svid_isid_update = true;
	}

	if (data && data[IFLA_PBB_I_SVID_INFO_RANGE_BEGIN] && data[IFLA_PBB_I_SVID_INFO_RANGE_END]) {
		s_vid_info_range_begin = nla_get_u32(data[IFLA_PBB_I_SVID_INFO_RANGE_BEGIN]);
		s_vid_info_range_end = nla_get_u32(data[IFLA_PBB_I_SVID_INFO_RANGE_END]);

		cvid_svid_isid_update = true;
	}

	if (data && data[IFLA_PBB_I_ISID_INFO_RANGE_BEGIN] && data[IFLA_PBB_I_ISID_INFO_RANGE_END]) {
		i_sid_info_range_begin = nla_get_u32(data[IFLA_PBB_I_ISID_INFO_RANGE_BEGIN]);
		i_sid_info_range_end = nla_get_u32(data[IFLA_PBB_I_ISID_INFO_RANGE_END]);

		cvid_svid_isid_update = true;
	}

	if (cvid_svid_isid_update == false) {
		goto return_success;
	}
	
	if (((c_vid_info_range_begin == -1) || (c_vid_info_range_end == -1) || (s_vid_info_range_begin != -1) || (s_vid_info_range_end != -1) ||
	    ((i_sid_info_range_begin != -1) || (i_sid_info_range_end == -1))) &&
	    ((cvid_info_action == PBB_I_VID_INFO_ACTION_MAX) || (svid_info_action == PBB_I_VID_INFO_ACTION_MAX) || (sid_type == PBB_I_ISID_TYPE_MAX))) {
		pbb_err(pbb_i, "%s: C-VID Range:%d-%d and/or S-VID Range:%d-%d and/or I-SID Range:%d-%d and/or "
				"C-VID Action:%d and/or S-VID Action:%d and/or I-SID Type:%d all are not defined!",
				__FUNCTION__,
				c_vid_info_range_begin, c_vid_info_range_end,
				s_vid_info_range_begin, s_vid_info_range_end,
				i_sid_info_range_begin, i_sid_info_range_end,
				cvid_info_action, svid_info_action, sid_type);

		err = -EINVAL;
		// TODO: Implement graceful return!
		goto rx_handler_unregister;
	}

	pbb_info(pbb_i, "%s: Processing PBB_B Changelink C,S->I_SID Map Notification", __FUNCTION__);

	pbb_info(pbb_i, "%s: C-VID Range:%d-%d, S-VID Range:%d-%d, I-SID Range:%d-%d, "
			"C-VID Action:%d, S-VID Action:%d, I-SID Type:%d, Key-Info-Map-Dump:%d",
			__FUNCTION__,
			c_vid_info_range_begin, c_vid_info_range_end,
			s_vid_info_range_begin, s_vid_info_range_end,
			i_sid_info_range_begin, i_sid_info_range_end,
			cvid_info_action, svid_info_action, sid_type,
			key_info_map_verify);

	struct pbb_l2vpn_ah_rhnode ah_rhnode_core = {0};
	struct pbb_l2vpn_ah_rhnode *ah_rhnode_core1 = NULL, *ah_rhnode_core2 = NULL;
	u32 c_vid = c_vid_info_range_begin, s_vid = s_vid_info_range_begin, i_sid = i_sid_info_range_begin;
	/* FIXME: Make this logic more free flowing and optimized */
	do {
		err = 0;
		/* Create and add/Verify [c,s -> c_action,s_action,isid] Mapping */
		if (key_info_map_verify == 0) {
			ah_rhnode_core1 = pbb_l2vpn_ah_rhnode_alloc();
			if (!ah_rhnode_core1) {
				pbb_err(pbb_i, "%s: Failed to allocate PBB L2VPN AH RHNode!", __FUNCTION__);
	
				err = -ENOMEM;
				goto rx_handler_unregister;
			}
	
			memset(ah_rhnode_core1, 0, sizeof(struct pbb_l2vpn_ah_rhnode));
			ah_rhnode_core1->pbb_b = pbb_b;
		} else {
			ah_rhnode_core1 = &ah_rhnode_core;
		}

		err = pbb_l2vpn_ah_rhnode_type_c_cstag_key_add(&ah_rhnode_core1->rhnode_key, c_vid, s_vid);
		if (err) {
			pbb_err(pbb_i, "%s: Failed to add [key-s_vid:%d,c_vid%d] to PBB L2VPN AH RHNode with err:0x%x!",
				 __FUNCTION__,
				 s_vid, c_vid,
				 err);
	
			goto free_pbb_l2vpn_rhnodes;
		}

		err = pbb_l2vpn_ah_rhnode_c_qinq_edge_info_add(&ah_rhnode_core1->rhnode_info, i_sid, isid_type, cvlan_tci_action, svlan_tci_action);
		if (err) {
			pbb_err(pbb_i, "%s: Failed to add [info-isid_type:%d,svid_action:%d,cvid_action:%d,i_sid:%d] to PBB L2VPN AH RHNode with err:0x%x!",
				 __FUNCTION__,
				 isid_type, svlan_tci_action, cvlan_tci_action, i_sid,
				 err);
	
			goto free_pbb_l2vpn_rhnodes;
		}

		err = -EINVAL;
		if (key_info_map_verify == 0) {
			err = pbb_l2vpn_ah_rhnode_insert(&b_priv->pbb_l2vpn_ah_rht, &ah_rhnode_core1->rhnode_hash);
		} else {
			ah_rhnode_core1 = pbb_l2vpn_ah_rhnode_lookup(&b_priv->pbb_l2vpn_ah_rht, &ah_rhnode_core1->rhnode_key);
			if (ah_rhnode_core1 && (ah_rhnode_core.rhnode_info.c_qinq_edge_hash_info == ah_rhnode_core1->rhnode_info.c_qinq_edge_hash_info)) {
				err = 0;
			}
		}
		if (err) {
			pbb_err(pbb_i, "%s: Failed to %s [key-s_vid:%d,c_vid:%d -> info-isid_type:%d,svid_action:%d,cvid_action:%d,i_sid:%d] mapping to PBB L2VPN AH RHT with err:0x%x! ptr:%p",
				__FUNCTION__, key_info_map_verify ? "verify" : "insert",
				s_vid, c_vid,
				isid_type, cvlan_tci_action, svlan_tci_action, i_sid,
				err, ah_rhnode_core1);
	
			goto free_pbb_l2vpn_rhnodes;
		} else {
			pbb_info(pbb_i, "%s: Successfully %s [key-s_vid:%d,c_vid:%d -> info-isid_type:%d,svid_action:%d,cvid_action:%d,i_sid:%d] mapping as HASH[key-0x%x -> info-0x%x] to PBB P2VPN AH RHT",
				 __FUNCTION__, key_info_map_verify ? "verified" : "inserted",
				 s_vid, c_vid,
				 isid_type, svlan_tci_action, cvlan_tci_action, i_sid,
				 ah_rhnode_core1->rhnode_key, ah_rhnode_core1->rhnode_info.c_qinq_edge_hash_info);
		}

		if (isid_type == PBB_L2VPN_RHNODE_TYPE_I_SID_TYPE_INFO_SHARED) {
			pbb_info(pbb_i, "%s: Not %s key-i_sid:%d(edge) -> info-svid_action:%d,cvid_action:%d,s_vid:%d,c_vid:%d]mapping for shared ISID:%d",
				 __FUNCTION__, key_info_map_verify ? "verifying" : "inserting", i_sid, svlan_tci_action, cvlan_tci_action, s_vid, c_vid, i_sid);

			goto get_next_iter;
		}

		err = 0;
		/* Create and add/Verify [isid(edge) -> c_action,s_action,c,s] Mapping */
		if (key_info_map_verify == 0) {
			ah_rhnode_core2 = pbb_l2vpn_ah_rhnode_alloc();
			if (!ah_rhnode_core2) {
				pbb_err(pbb_i, "%s: Failed to allocate PBB L2VPN AH RHNode!", __FUNCTION__);
	
				err = -ENOMEM;
				goto free_pbb_l2vpn_rhnodes;
			}
	
			memset(ah_rhnode_core2, 0, sizeof(struct pbb_l2vpn_ah_rhnode));
			ah_rhnode_core2->pbb_b = pbb_b;
		} else {
			memset(&ah_rhnode_core, 0, sizeof(ah_rhnode_core));
			ah_rhnode_core2 = &ah_rhnode_core;
		}

		err = pbb_l2vpn_ah_rhnode_type_i_sid_key_add(&ah_rhnode_core2->rhnode_key, i_sid, PBB_L2VPN_RHNODE_TYPE_I_SID_KEY_DIR_EDGE);
		if (err) {
			pbb_err(pbb_i, "%s: Failed to add [key-isid:%d(edge)] to PBB L2VPN AH RHNode with err:0x%x!",
				 __FUNCTION__,
				 i_sid,
				 err);
	
			goto free_pbb_l2vpn_rhnodes;
		}
	
		err = pbb_l2vpn_ah_rhnode_c_qinq_core_info_add(&ah_rhnode_core2->rhnode_info, c_vid, s_vid, cvlan_tci_action, svlan_tci_action);
		if (err) {
			pbb_err(pbb_i, "%s: Failed to add [info-svid_action:%d,cvid_action:%d,s_vid:%d,c_vid:%d] to PBB L2VPN AH RHNode with err:0x%x!",
				 __FUNCTION__,
				 svlan_tci_action, cvlan_tci_action, s_vid, c_vid,
				 err);
	
			goto free_pbb_l2vpn_rhnodes;
		}

		err = -EINVAL;
		if (key_info_map_verify == 0) {
			err = pbb_l2vpn_ah_rhnode_insert(&b_priv->pbb_l2vpn_ah_rht, &ah_rhnode_core2->rhnode_hash);
		} else {
			ah_rhnode_core2 = pbb_l2vpn_ah_rhnode_lookup(&b_priv->pbb_l2vpn_ah_rht, &ah_rhnode_core2->rhnode_key);
			if (ah_rhnode_core2 && (ah_rhnode_core.rhnode_info.c_qinq_core_hash_info == ah_rhnode_core2->rhnode_info.c_qinq_core_hash_info)) {
				err = 0;
			}
		}
		if (err) {
			pbb_err(pbb_i, "%s: Failed to %s [key-i_sid:%d(edge) -> info-svid_action:%d,cvid_action:%d,s_vid:%d,c_vid:%d] mapping to PBB L2VPN AH RHT with err:0x%x!",
				__FUNCTION__, key_info_map_verify ? "verify" : "insert",
				i_sid,
				svlan_tci_action, cvlan_tci_action, s_vid, c_vid,
				err);
	
			goto free_pbb_l2vpn_rhnodes;
		} else {
			pbb_info(pbb_i, "%s: Successfully %s [key-i_sid:%d(edge) -> info-svid_action:%d,cvid_action:%d,s_vid:%d,c_vid:%d]mapping as HASH[key-0x%x -> info-0x%x] to PBB P2VPN AH RHT",
				 __FUNCTION__, key_info_map_verify ? "verified" : "inserted", 
				 i_sid,
				 svlan_tci_action, cvlan_tci_action, s_vid, c_vid,
				 ah_rhnode_core2->rhnode_key, ah_rhnode_core2->rhnode_info.c_qinq_core_hash_info);
		}

get_next_iter:
		/* Now Iterate next */
		if (c_vid <= c_vid_info_range_end) c_vid++;
		if (s_vid <= s_vid_info_range_end) s_vid++;
		if (i_sid <= i_sid_info_range_end) i_sid++;
	} while ((c_vid <= c_vid_info_range_end) || (s_vid <= s_vid_info_range_end));

return_success:
	return 0;

free_pbb_l2vpn_rhnodes:
	if ((key_info_map_verify == 0) && ah_rhnode_core1) pbb_l2vpn_ah_rhnode_free(ah_rhnode_core1);
	if ((key_info_map_verify == 0) && ah_rhnode_core2) pbb_l2vpn_ah_rhnode_free(ah_rhnode_core2);
	
rx_handler_unregister:
	if (pbbi_core_bridge_process) netdev_rx_handler_unregister(pbb_b);

	return err;
}

static void pbb_i_dellink(struct net_device *pbb_i, struct list_head *head)
{
	struct pbb_i_priv *i_priv = NULL;
	struct pbb_b_priv *b_priv = NULL;
	struct net_device *pbb_b = NULL;

	pbb_info(pbb_i, "%s: Processing PBB_I Dellink", __FUNCTION__);

	i_priv = netdev_priv(pbb_i);
	pbb_b = i_priv ? rtnl_dereference(i_priv->pbb_b) : NULL;

	RCU_INIT_POINTER(i_priv->pbb_b, NULL);
	unregister_netdevice_queue(pbb_i, head);

	/* Note : dellink() is called from default_device_exit_batch(),
	 * before a rcu_synchronize() point. The devices are guaranteed
	 * not being freed before one RCU grace period.
	 */
	if (pbb_b) {
		pbb_info(pbb_b, "%s: Also Processing Peer PBB_B Dellink",
		         __FUNCTION__);

		b_priv = netdev_priv(pbb_b);
		RCU_INIT_POINTER(b_priv->pbb_i, NULL);
		pbb_b->rtnl_link_ops->dellink(pbb_b, NULL);
		//unregister_netdevice_queue(pbb_b, head);
	}
}

const struct nla_policy pbb_i_policy[IFLA_PBB_I_MAX] = {
	[IFLA_PBB_I_CORE_BRIDGE_INFO]  		= { .type = NLA_U32 },
};

static struct rtnl_link_ops pbb_i_link_ops;

int pbb_i_rtnl_link_register(void) {
        pbb_i_link_ops.kind		= PBB_I_DRV_NAME;
        pbb_i_link_ops.priv_size	= sizeof(struct pbb_i_priv);
        pbb_i_link_ops.setup		= pbb_i_setup;
        pbb_i_link_ops.validate		= pbb_i_validate;
        pbb_i_link_ops.newlink		= pbb_i_newlink;
        pbb_i_link_ops.changelink	= pbb_i_changelink;
        pbb_i_link_ops.dellink		= pbb_i_dellink;
        pbb_i_link_ops.policy		= pbb_i_policy;
        pbb_i_link_ops.maxtype		= IFLA_PBB_I_MAX-1;

        return rtnl_link_register(&pbb_i_link_ops);
}

void pbb_i_rtnl_link_unregister(void) {
        rtnl_link_unregister(&pbb_i_link_ops);
}
