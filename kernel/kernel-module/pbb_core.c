// SPDX-License-Identifier: GPL-2.0-only
/*
 *  drivers/net/pbb_core.c
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

/***************************************** Generic PBB-B Routines ***********************************************/
static int pbb_b_sync_address(struct net_device *pbb_b,
			      const unsigned char *addr)
{
	struct pbb_b_priv *b_priv = netdev_priv(pbb_b);
	struct net_device *lowerdev = b_priv ? b_priv->lowerdev : NULL;
	struct pbb_b_port *pbb_b_port = b_priv ? b_priv->pbb_b_port : NULL;

	if (!b_priv || !lowerdev || !pbb_b_port) {
		return -EINVAL;
	}

	/* Just copy in the new address */
	eth_hw_addr_set(pbb_b, addr);

	ether_addr_copy(pbb_b_port->perm_addr, lowerdev->dev_addr);

	return 0;
}

static inline struct net_device *
pbb_b_get_lowerdev(const struct net_device *pbb_b)
{
        struct pbb_b_priv *b_priv = netdev_priv(pbb_b);
	struct net_device *lowerdev = b_priv ? b_priv->lowerdev : NULL;

	if (!b_priv || !lowerdev) {
		return NULL;
	}

        return lowerdev;
}

/***************************************** B-Driver Netdevice Routines ****************************************/
static void pbb_b_port_destroy(struct net_device *lowerdev);

static int pbb_b_init(struct net_device *pbb_b)
{
        struct pbb_b_priv *b_priv = netdev_priv(pbb_b);
        struct net_device *lowerdev = b_priv->lowerdev;

	pbb_info(pbb_b, "%s: Processing PBB_B Device Init", __FUNCTION__);

	pbb_info(pbb_b, "%s: Lowerdev:%s", __FUNCTION__,
		 lowerdev ? lowerdev->name : "NULL");

	pbb_b->state		= (pbb_b->state & ~PBB_B_STATE_MASK);
        pbb_b->features		= PBB_B_FEATURES;
        pbb_b->features		|= PBB_B_ALWAYS_ON_FEATURES;
        pbb_b->hw_features	|= NETIF_F_LRO;
        pbb_b->vlan_features	= PBB_B_FEATURES;
        pbb_b->vlan_features	|= PBB_B_ALWAYS_ON_OFFLOADS;
        pbb_b->hw_enc_features	|= pbb_b->features;
	pbb_b->priv_flags	|= IFF_PBB_B;

	if (lowerdev) {
		pbb_b->state |= (lowerdev->state & PBB_B_STATE_MASK);
		pbb_b->features |= lowerdev->features;
		pbb_b->vlan_features |= lowerdev->vlan_features;
	        netif_inherit_tso_max(pbb_b, lowerdev);
        	pbb_b->hard_header_len = lowerdev->hard_header_len;
		/* Get PBB_B's reference to lowerdev */
		netdev_hold(lowerdev, &b_priv->dev_tracker, GFP_KERNEL);
	}

	if (!b_priv->pcpu_stats) { 
		b_priv->pcpu_stats = netdev_alloc_pcpu_stats(struct pbb_pcpu_stats);
	}
	if (!b_priv->pcpu_stats) {
		pbb_err(pbb_b, "%s: Failed to allocate PBB_B pcpu stats!",
			__FUNCTION__);

		return -ENOMEM;
	}
	
	return 0;
}

//FIXME: To be filled later once PBB_B and PBB_I code is in
static void pbb_b_uninit(struct net_device *pbb_b)
{
	struct pbb_b_priv *b_priv = NULL;
	struct pbb_b_port *pbb_b_port = NULL;
	struct net_device *lowerdev = NULL;

	if (!pbb_b) {
		printk(KERN_ERR "%s: PBB_B invalid!", __FUNCTION__);

		return;
	}

	pbb_info(pbb_b, "%s: Processing PBB_B Device Uninit", __FUNCTION__);

	b_priv = netdev_priv(pbb_b);
	pbb_b_port = b_priv ? b_priv->pbb_b_port : NULL;

	if (!b_priv || !pbb_b_port) {
		pbb_err(pbb_b, "%s: PBB_B Private Metadata:%p or PBB_B Port:%p invalid!",
			__FUNCTION__, b_priv, pbb_b_port);

		return;
	}

	if (b_priv->pcpu_stats) {
        	free_percpu(b_priv->pcpu_stats);
		b_priv->pcpu_stats = NULL;
	}

	lowerdev = pbb_b_port->lowerdev;
	if (pbb_b_port && lowerdev) {
		pbb_info(pbb_b, "%s: Actually cleaning up Lowerdev:%s now",
			 __FUNCTION__, lowerdev->name);

        	pbb_b_port_destroy(lowerdev);
		//RCU_INIT_POINTER(b_priv->lowerdev, NULL);
		RCU_INIT_POINTER(b_priv->pbb_b_port, NULL);
	}

	pbb_l2vpn_ah_rht_deinit(&b_priv->pbb_l2vpn_ah_rht);

	pbb_b->priv_flags &= ~IFF_PBB_B;
}

static int pbb_b_open(struct net_device *pbb_b)
{
	struct pbb_b_priv *b_priv = netdev_priv(pbb_b);
	struct net_device *pbb_i = b_priv ? rtnl_dereference(b_priv->pbb_i) : NULL;
	struct net_device *lowerdev = b_priv ? rtnl_dereference(b_priv->lowerdev) : NULL;
	int err = 0;

	pbb_info(pbb_b, "%s: Processing PBB_B Device Open", __FUNCTION__);

	if (!pbb_i) {
		pbb_err(pbb_b, "%s: PBB_I is not yet connected", __FUNCTION__);

		return -ENOTCONN;
	}

	/* FIXME: Is carrier on/off required for PBB_B Device?
	 * Keep for now, remove later if not applicable.
	 */
	if (pbb_i->flags & IFF_UP) {
		pbb_info(pbb_b, "%s: Setting PBB_B and PBB_I:%s Carrier On",
			 __FUNCTION__, pbb_i->name);

		netif_carrier_on(pbb_i);
		netif_carrier_on(pbb_b);
	}


	// This can happen (right?)
	if (!lowerdev) {
		pbb_info(pbb_b, "%s: PBB_B does not have any Lowerdev connected yet",
			 __FUNCTION__);

		return 0;
	}

	err = dev_uc_add(lowerdev, pbb_b->dev_addr);
	if (err < 0) {
		pbb_err(pbb_b, "%s: Could not set Lowerdev:%s Secondary UC Address!",
			__FUNCTION__, lowerdev->name);

		goto set_uc_addr_fail;
	}


	err = dev_set_promiscuity(lowerdev, 1);
	if (err < 0) {
		pbb_err(pbb_b, "%s: Could not set Lowerdev:%s to promiscuous mode!",
			__FUNCTION__, lowerdev->name);

		goto set_promisc_fail;
	}

/*
	TODO: Is below required for PBB_B Lowerdev?
	if (pbb_b->flags & IFF_ALLMULTI) {
		err = dev_set_allmulti(lowerdev, 1);
		if (err < 0) {
			pbb_err(pbb_b, "%s: Could not set Lowerdev:%s to Multicast mode!",
				__FUNCTION__, lowerdev->name);

			goto set_promisc_fail;
		}
	}
*/
	pbb_info(pbb_b, "%s: PBB_B Open Successfull", __FUNCTION__);

	return 0;

set_uc_addr_fail:
	netif_carrier_off(pbb_b);

set_promisc_fail:
	dev_uc_del(lowerdev, pbb_b->dev_addr);

	pbb_info(pbb_b, "%s: PBB_B Open failed with error:0x%x",
		 __FUNCTION__, err);

	return err;
}

static int pbb_b_stop(struct net_device *pbb_b)
{
	struct pbb_b_priv *b_priv = netdev_priv(pbb_b);
	struct net_device *pbb_i = rtnl_dereference(b_priv->pbb_i);
	struct net_device *lowerdev = b_priv ? b_priv->lowerdev : NULL;

	pbb_info(pbb_b, "%s: Processing PBB_B Device Stop", __FUNCTION__);

	if (!pbb_i) {
		pbb_err(pbb_b, "%s: PBB_I is not connected", __FUNCTION__);
	}

	if (pbb_i) {
		pbb_info(pbb_b, "%s: Setting carrier Off for PBB_I:%s",
	        	 __FUNCTION__, pbb_i->name);

		netif_carrier_off(pbb_i);
	}

	pbb_info(pbb_b, "%s: Setting carrier Off for PBB_B", __FUNCTION__);
	netif_carrier_off(pbb_b);

	if (!lowerdev) {
		pbb_info(pbb_b, "%s: PBB_B does not have any Lowerdev connected yet",
			 __FUNCTION__);

		return 0;
	}

        dev_uc_unsync(lowerdev, pbb_b);

	/*TODO: Is below required for PBB_B Lowerdev?
        dev_mc_unsync(lowerdev, pbb_b);

        if (dev->flags & IFF_ALLMULTI)
                dev_set_allmulti(lowerdev, -1);
	*/

        dev_set_promiscuity(lowerdev, -1);

        dev_uc_del(lowerdev, pbb_b->dev_addr);

	pbb_info(pbb_b, "%s: PBB_B Stopped successfully!", __FUNCTION__);

	return 0;

}

// For now return Underlying Device for PBB_B
// FIXME: To return PBB_B Peer PBB_I ifindex, instead (or self ifindex)?
static int pbb_b_get_iflink(const struct net_device *pbb_b)
{
	struct pbb_b_priv *b_priv = netdev_priv(pbb_b);
	struct net_device *lowerdev = b_priv ? rtnl_dereference(b_priv->lowerdev) : NULL;
	int lowerdev_ifindex = lowerdev ? lowerdev->ifindex : pbb_b->ifindex;

	return lowerdev_ifindex;
}

// Return Underlying PBB_I Device for PBB_B Instance
static struct net_device *pbb_b_get_peer_dev(struct net_device *pbb_b)
{
	struct pbb_b_priv *b_priv = netdev_priv(pbb_b);
	struct net_device *pbb_i = rtnl_dereference(b_priv->pbb_i);

	if (!pbb_i) {
		pbb_err(pbb_b, "%s: PBB_B Peer Not Assigned!",
			__FUNCTION__);
	}

	return pbb_i;
}

/* FIXME/TODO: Perform the following functions -
 * Verify 8021ah header (session_id) as per session_id membership.
 * Translate session_id to fetch bridge vid-tag (as per pbb core config).
 * Add 8021q/8021ad outer tag to 8021ah header (as per pbb core config).
 * Hand over final packet to lowerdev xmit routine for physical transmit over PBB Core network.
 */
static netdev_tx_t pbb_b_xmit(struct sk_buff *skb, struct net_device *pbb_b)
{
	struct pbb_b_priv *b_priv = netdev_priv(pbb_b);
	struct net_device *lowerdev = b_priv->lowerdev;
	unsigned int len = skb ? skb->len : 0;
	int ret = NETDEV_TX_OK;

	if (len == 0) {
		return NET_XMIT_DROP;
	}

	if (!lowerdev) {
		return NET_XMIT_DROP;
	}

#ifdef PBB_DEBUG
	pbb_dump_skb(skb, TX);
#endif // PBB_DEBUG

	/* PBB Core Tx Processing */
	u32 isid = 0;
	dot1ah_outer_ethhdr *dot1ah_outer_eth_hdr = (dot1ah_outer_ethhdr *)skb_eth_hdr(skb);
	isid = ntohl(dot1ah_outer_eth_hdr->bb_1ah_isid);
	if ((htons(dot1ah_outer_eth_hdr->bb_1ah_proto) != ETH_P_8021AH) ||
	    (isid == 0)) {
		return NET_XMIT_DROP;
	}

	u32 rhnode_key = 0;
	ret = pbb_l2vpn_ah_rhnode_type_i_sid_key_add(&rhnode_key, isid, PBB_L2VPN_RHNODE_TYPE_I_SID_KEY_DIR_CORE);
        if (ret) {
		return NET_XMIT_DROP;
	}
	struct pbb_l2vpn_ah_rhnode *ah_rhnode_core = pbb_l2vpn_ah_rhnode_lookup(&b_priv->pbb_l2vpn_ah_rht, &rhnode_key);
	if (ah_rhnode_core == NULL) {
		return NET_XMIT_DROP;
	}
	u32 bvlan_tci = ah_rhnode_core->rhnode_info.b_vid_hash_info & PBB_L2VPN_RHNODE_TYPE_B_VID_INFO_MASK;

        if (!is_multicast_ether_addr(dot1ah_outer_eth_hdr->bb_dmac) && !is_broadcast_ether_addr(dot1ah_outer_eth_hdr->bb_dmac)) {
                // Detect and extract the destination mac and do a lookup based on [core,bvid,dmac] below
                struct pbb_l2vpn_fdb_rhnode_key fdb_rhnode_core_ulay_key = {0};
                fdb_rhnode_core_ulay_key.type = PBB_MAC_TYPE_CORE_ULAY;
                memcpy(fdb_rhnode_core_ulay_key.mac, dot1ah_outer_eth_hdr->bb_dmac, ETH_ALEN);
                fdb_rhnode_core_ulay_key.pbb_l2vpn_bd = bvlan_tci;
		struct pbb_l2vpn_fdb_rhnode *fdb_rhnode_core_ulay_dmac = pbb_l2vpn_fdb_rhnode_lookup(&b_priv->pbb_l2vpn_fdb_rht, &fdb_rhnode_core_ulay_key);

        	if ((fdb_rhnode_core_ulay_dmac &&
		     (strcmp(fdb_rhnode_core_ulay_dmac->fdb_ifinfo.core_ulay_ifinfo.lowerdev->name, lowerdev->name))) ||
        	    (fdb_rhnode_core_ulay_dmac == NULL)) {
			return NET_XMIT_DROP;
        	} 
	}

	dot1ah_outer_eth_hdr->bb_vlan_tci = htons(bvlan_tci);

#ifdef PBB_DEBUG
	pbb_dump_skb(skb, TX);
#endif // PBB_DEBUG

	// Handoff to appropriate Lowerdev device driver instance
	skb->dev = lowerdev;

	ret = dev_queue_xmit(skb);

	/* Do Tx stats accounting for PBB_B Device */
	struct pbb_pcpu_stats *pcpu_stats = this_cpu_ptr(b_priv->pcpu_stats);
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

void pbb_get_stats64(struct net_device *pbb, struct rtnl_link_stats64 *stats)
{
	struct pbb_b_priv *b_priv = NULL;
	struct pbb_i_priv *i_priv = NULL;
	struct pbb_pcpu_stats *p_stats = NULL;

	if (netif_is_pbb_b(pbb)) {
		b_priv = netdev_priv(pbb);
		if (b_priv->pcpu_stats && stats) {
			p_stats = b_priv->pcpu_stats;	
		} else {
			return;
		}
	} else if (netif_is_pbb_i(pbb)) {
		i_priv = netdev_priv(pbb);
		if (i_priv->pcpu_stats && stats) {
			p_stats = i_priv->pcpu_stats;	
		} else {
			return;
		}
	} else {
		return;
	}

	if (p_stats) {
		struct pbb_pcpu_stats *pcpu_stats = NULL;
		u64 rx_packets, rx_bytes, rx_multicast , tx_packets , tx_bytes;
		u32 rx_errors = 0 , tx_dropped = 0;
		unsigned int start = 0;
		int i;

		for_each_possible_cpu(i) {
			pcpu_stats = per_cpu_ptr(p_stats, i);
			do {
				start = u64_stats_fetch_begin(&pcpu_stats->syncp);
				rx_packets	= u64_stats_read(&pcpu_stats->rx_packets);
				rx_bytes	= u64_stats_read(&pcpu_stats->rx_bytes);
				rx_multicast	= u64_stats_read(&pcpu_stats->rx_multicast);
				tx_packets	= u64_stats_read(&pcpu_stats->tx_packets);
				tx_bytes	= u64_stats_read(&pcpu_stats->tx_bytes);
			} while (u64_stats_fetch_retry(&pcpu_stats->syncp, start));

			stats->rx_packets	+= rx_packets;
			stats->rx_bytes		+= rx_bytes;
			stats->multicast	+= rx_multicast;
			stats->tx_packets	+= tx_packets;
			stats->tx_bytes		+= tx_bytes;
			/* rx_errors & tx_dropped are u32, updated
			 * without syncp protection.
			 */
			rx_errors	+= READ_ONCE(pcpu_stats->rx_errors);
			tx_dropped	+= READ_ONCE(pcpu_stats->tx_dropped);
		}
		stats->rx_errors	= rx_errors;
		stats->rx_dropped	= rx_errors;
		stats->tx_dropped	= tx_dropped;
	}
}

static int pbb_b_set_mac_address(struct net_device *pbb_b, void *p)
{
	struct pbb_b_priv *b_priv	= netdev_priv(pbb_b);
	struct net_device *lowerdev	= b_priv->lowerdev;
	struct sockaddr *addr		= p;
	int err = 0;

	pbb_info(pbb_b, "%s: Processing PBB_B Set Mac Address", __FUNCTION__);

	if (!is_valid_ether_addr(addr->sa_data))
		return -EADDRNOTAVAIL;

	if (!lowerdev) {
		pbb_err(pbb_b, "%s: PBB_B does not have any Lowerdev connected yet",
			__FUNCTION__);

		return -ENOTCONN;
	}
	
	/* If the addresses are the same, this is a no-op */
	if (ether_addr_equal(pbb_b->dev_addr, addr->sa_data)) {
		pbb_info(pbb_b, "%s: Mac:%pM already configured on PBB_B",
			 __FUNCTION__, pbb_b->dev_addr);

		return 0;
	}

	// TODO: Set any flags or check if address currently in-use?

	//Start Mac address housekeeping
	// TODO: Is below sufficient?
	err = dev_set_mac_address(lowerdev, addr, NULL);
	/* FIXME: Confirm if below is required as well
	if (err == 0) {
		eth_hw_addr_set(pbb_b, addr);
	}
	*/

	return err;
}

static int pbb_b_change_mtu(struct net_device *pbb_b, int new_mtu)
{
	struct pbb_b_priv *b_priv	= netdev_priv(pbb_b);
	struct net_device *lowerdev	= b_priv ? b_priv->lowerdev : NULL;

	pbb_info(pbb_b, "%s: Processing PBB_B Change MTU", __FUNCTION__);

	if (!b_priv || !lowerdev) {
		pbb_err(pbb_b, "%s: PBB_B Private Metadata:%p or Lowerdev:%p not initialized properly!",
			__FUNCTION__, b_priv, lowerdev->name);

		return -EINVAL;
	}

        if (lowerdev->mtu < new_mtu) {
		pbb_err(pbb_b, "%s: PBB_B MTU %d cannot be greater than Lowerdev:%s MTU:%d",
			__FUNCTION__, new_mtu, lowerdev->name, lowerdev->mtu);

                return -EINVAL;
	}

        pbb_b->mtu = new_mtu;

        return 0;
}

// TODO: The fuck does this do???
static netdev_features_t pbb_b_fix_features(struct net_device *pbb_b,
					    netdev_features_t features)
{
        struct pbb_b_priv *b_priv = netdev_priv(pbb_b);
        netdev_features_t lowerdev_features;
        netdev_features_t mask;

	pbb_info(pbb_b, "%s: Processing PBB_B Fix Features", __FUNCTION__);

	if (!b_priv || !b_priv->lowerdev) {
		pbb_err(pbb_b, "%s: PBB_B Private Metadata:%p or Lowerdev:%p not initialized properly!",
			__FUNCTION__, b_priv, b_priv ? b_priv->lowerdev : NULL);

		goto ret_pbb_b_features;
	}

        lowerdev_features = b_priv->lowerdev->features;

        features |= NETIF_F_ALL_FOR_ALL;
        features &= (b_priv->set_features | ~PBB_B_FEATURES);
        mask = features;

        lowerdev_features &= (features | ~NETIF_F_LRO);
        features = netdev_increment_features(lowerdev_features, features, mask);
ret_pbb_b_features:
        features |= PBB_B_ALWAYS_ON_FEATURES;
        features &= (PBB_B_ALWAYS_ON_FEATURES | PBB_B_FEATURES);

        return features;
}

static void pbb_b_change_rx_flags(struct net_device *pbb_b, int change)
{
        struct pbb_b_priv *b_priv = netdev_priv(pbb_b);
        struct net_device *lowerdev = b_priv ? b_priv->lowerdev : NULL;

	pbb_info(pbb_b, "%s: Processing PBB_B Change Rx Flags", __FUNCTION__);

	if (!b_priv || !lowerdev) {
		pbb_err(pbb_b, "%s: PBB_B Private Metadata:%p or Lowerdev:%p not initialized properly!",
			__FUNCTION__, b_priv, lowerdev);

		return;
	}

        if (pbb_b->flags & IFF_UP) {
		// FIXME: Check if below required?
                if (0/*change & IFF_ALLMULTI*/)
                        dev_set_allmulti(lowerdev, pbb_b->flags & IFF_ALLMULTI ? 1 : -1);
        }
}

static int pbb_b_hwtstamp_get(struct net_device *pbb_b,
                                struct kernel_hwtstamp_config *cfg)
{
        struct net_device *lowerdev = pbb_b_get_lowerdev(pbb_b);

	if (!lowerdev) {
		return -EINVAL;
	}

        return generic_hwtstamp_get_lower(lowerdev, cfg);
}

static int pbb_b_hwtstamp_set(struct net_device *pbb_b,
                                struct kernel_hwtstamp_config *cfg,
                                struct netlink_ext_ack *extack)
{
        struct net_device *lowerdev = pbb_b_get_lowerdev(pbb_b);

	if (!lowerdev) {
		return -EINVAL;
	}

        if (!net_eq(dev_net(pbb_b), &init_net))
                return -EOPNOTSUPP;

        return generic_hwtstamp_set_lower(lowerdev, cfg, extack);
}

// TODO: The hell does this do???
static void pbb_b_set_mac_lists(struct net_device *pbb_b)
{
        struct pbb_b_priv *b_priv = netdev_priv(pbb_b);
	struct net_device *lowerdev = b_priv ? b_priv->lowerdev : NULL;

	pbb_info(pbb_b, "%s: Processing PBB_B Set Mac Lists", __FUNCTION__);

	if (!b_priv || !lowerdev) {
		pbb_err(pbb_b, "%s: PBB_B Private Metadata:%p or Lowerdev:%p invalid",
			__FUNCTION__, b_priv, lowerdev);

		return;
	}

        dev_uc_sync(lowerdev, pbb_b);
        dev_mc_sync(lowerdev, pbb_b);
}

static const struct net_device_ops pbb_b_netdev_ops = {
        .ndo_init		= pbb_b_init,
	.ndo_uninit		= pbb_b_uninit,
        .ndo_open		= pbb_b_open,
        .ndo_stop		= pbb_b_stop,
	.ndo_start_xmit         = pbb_b_xmit,
	.ndo_change_mtu         = pbb_b_change_mtu,
        .ndo_fix_features       = pbb_b_fix_features,
        .ndo_change_rx_flags    = pbb_b_change_rx_flags,
        .ndo_set_rx_mode        = pbb_b_set_mac_lists,
        .ndo_validate_addr      = eth_validate_addr,
        .ndo_get_iflink		= pbb_b_get_iflink,
	.ndo_get_peer_dev	= pbb_b_get_peer_dev,
        .ndo_features_check	= passthru_features_check,
	.ndo_get_stats64        = pbb_get_stats64,
        .ndo_set_mac_address    = pbb_b_set_mac_address,
        .ndo_hwtstamp_get       = pbb_b_hwtstamp_get,
        .ndo_hwtstamp_set       = pbb_b_hwtstamp_set,
};

/***************************************** B-Driver Core Routines ************************************/
static struct pbb_b_port *pbb_b_port_get_rcu(const struct net_device *lowerdev)
{
	if (!lowerdev)
		return NULL;

        return rcu_dereference(lowerdev->rx_handler_data);
}

static struct pbb_b_port *pbb_b_port_get_rtnl(const struct net_device *lowerdev)
{
	if (!lowerdev)
		return NULL;

        return rtnl_dereference(lowerdev->rx_handler_data);
}

/* called under rcu_read_lock() from netif_receive_skb */
static rx_handler_result_t pbb_b_handle_frame_from_core(struct sk_buff **pskb)
{
	struct pbb_b_port *pbb_b_port = NULL;
	struct net_device *pbb_b = NULL, *lowerdev = NULL, *pbb_i = NULL;
	struct pbb_b_priv *b_priv = NULL;
	struct sk_buff *skb = NULL;
	unsigned int len = 0;
	int ret = NET_RX_SUCCESS;
	rx_handler_result_t handle_res = RX_HANDLER_CONSUMED;
	int err = 0;

	if (!pskb || !*pskb) {
		ret = NET_RX_DROP;
		handle_res = RX_HANDLER_CONSUMED;
		goto rx_handler_ret;
	}

	skb = *pskb;

        /* Packets from dev_loopback_xmit() do not have L2 header, bail out */
        if (unlikely(skb->pkt_type == PACKET_LOOPBACK)) {
		goto handle_failure;
	}

        pbb_b_port = pbb_b_port_get_rcu(skb->dev);
	if (!pbb_b_port) {
		goto handle_failure;
	}

	pbb_b = pbb_b_port->pbb_b;
	if (!pbb_b) {
		goto handle_failure;
	}

	lowerdev = pbb_b_port->lowerdev;
	if (!lowerdev) {
		goto handle_failure;
	}

	b_priv = netdev_priv(pbb_b);
	if (!b_priv) {
		goto handle_failure;
	}

	pbb_i = rtnl_dereference(b_priv->pbb_i);
	if (!pbb_i) {
		goto handle_failure;
	}

	if (!(pbb_b->flags & IFF_UP) || !(pbb_i->flags & IFF_UP)) {
		goto handle_failure;
        }

	/* TODO: PBB-B Core Receive Path Processing Routine as per 8021ah.
	*/
	dot1ah_outer_ethhdr_in *dot1ah_outer_eth_hdr_in = (dot1ah_outer_ethhdr_in *)eth_hdr(skb);

	if (dot1ah_outer_eth_hdr_in == NULL) {
		goto handle_failure;
	}

	if (skb->dev == NULL) {
		goto handle_failure;
	}

#ifdef PBB_DEBUG
	pbb_dump_skb(skb, RX);
#endif // PBB_DEBUG

	if (!is_multicast_ether_addr(dot1ah_outer_eth_hdr_in->bb_dmac) &&
	    !is_multicast_ether_addr(dot1ah_outer_eth_hdr_in->bb_dmac) &&
	    memcmp(dot1ah_outer_eth_hdr_in->bb_dmac, pbb_b->dev_addr, ETH_ALEN)) {

	        len = skb->len + ETH_HLEN;
		ret = NET_RX_DROP;
		handle_res = RX_HANDLER_PASS;

		goto rx_handler_ret;
	}


	if (is_multicast_ether_addr(dot1ah_outer_eth_hdr_in->bb_smac) || is_broadcast_ether_addr(dot1ah_outer_eth_hdr_in->bb_smac)) {
		goto handle_failure;
	}

	if (!skb_vlan_tag_present(skb) ||
	    ((htons(skb->vlan_proto) == ETH_P_8021Q) && (pbb_b_port->flags != PBB_B_PORT_FLAGS_MODE_DOT1Q)) ||
	    ((htons(skb->vlan_proto) == ETH_P_8021AD) && (pbb_b_port->flags != PBB_B_PORT_FLAGS_MODE_DOT1AD))) {
		goto handle_failure;
	}

	u16 bb_vlan_tci = skb_vlan_tag_get_id(skb);

	if (htons(dot1ah_outer_eth_hdr_in->bb_1ah_proto) != ETH_P_8021AH) {
		goto handle_failure;
	}

	u32 isid = htonl(dot1ah_outer_eth_hdr_in->bb_1ah_isid);

        u32 rhnode_key = 0;
        ret = pbb_l2vpn_ah_rhnode_type_i_sid_key_add(&rhnode_key, isid, PBB_L2VPN_RHNODE_TYPE_I_SID_KEY_DIR_CORE);
        if (ret) {
		goto handle_failure;
        }
        struct pbb_l2vpn_ah_rhnode *ah_rhnode_core = pbb_l2vpn_ah_rhnode_lookup(&b_priv->pbb_l2vpn_ah_rht, &rhnode_key);
        if (ah_rhnode_core == NULL) {
		goto handle_failure;
        }

        if (bb_vlan_tci != (ah_rhnode_core->rhnode_info.b_vid_hash_info & PBB_L2VPN_RHNODE_TYPE_B_VID_INFO_MASK)) {
		goto handle_failure;
	}
    
	struct pbb_l2vpn_fdb_rhnode_key fdb_rhnode_key = {0};
        fdb_rhnode_key.type = PBB_MAC_TYPE_CORE_ULAY;
        memcpy(fdb_rhnode_key.mac, dot1ah_outer_eth_hdr_in->bb_smac, ETH_ALEN);
        fdb_rhnode_key.pbb_l2vpn_bd = bb_vlan_tci;

        struct pbb_l2vpn_fdb_rhnode *fdb_rhnode_dest_ulay = pbb_l2vpn_fdb_rhnode_lookup(&b_priv->pbb_l2vpn_fdb_rht, &fdb_rhnode_key);
	if (fdb_rhnode_dest_ulay &&
	    (strcmp(fdb_rhnode_dest_ulay->fdb_ifinfo.core_ulay_ifinfo.lowerdev->name, lowerdev->name) ||
	    !(fdb_rhnode_dest_ulay->fdb_rhnode_flags & PBB_MAC_FLAGS_DYNAMIC))) {
		goto handle_failure;
	}

	if (!fdb_rhnode_dest_ulay) {
		fdb_rhnode_dest_ulay = pbb_l2vpn_fdb_rhnode_alloc();
        	if (fdb_rhnode_dest_ulay == NULL) {
			goto handle_failure;
        	}

        	memset(fdb_rhnode_dest_ulay, 0, sizeof(struct pbb_l2vpn_fdb_rhnode));

        	fdb_rhnode_dest_ulay->fdb_rhnode_key.type = PBB_MAC_TYPE_CORE_ULAY;
        	memcpy(fdb_rhnode_dest_ulay->fdb_rhnode_key.mac, dot1ah_outer_eth_hdr_in->bb_smac, ETH_ALEN);
        	fdb_rhnode_dest_ulay->fdb_rhnode_key.pbb_l2vpn_bd = bb_vlan_tci;

        	fdb_rhnode_dest_ulay->fdb_ifinfo.core_ulay_ifinfo.lowerdev = lowerdev;
        	fdb_rhnode_dest_ulay->fdb_rhnode_flags = PBB_MAC_FLAGS_DYNAMIC;
        	err = pbb_l2vpn_fdb_rhnode_insert(&b_priv->pbb_l2vpn_fdb_rht, &fdb_rhnode_dest_ulay->fdb_rhnode_hash);
		if (err != 0) {
			goto handle_failure;

		}
	}

#if 0
	skb->vlan_all = 0;
	skb->vlan_tci = 0;
	skb_pull(skb, VLAN_HLEN);
#else
	__vlan_hwaccel_clear_tag(skb);
	//skb_pull(skb, VLAN_HLEN);
#endif

#ifdef PBB_DEBUG
	pbb_dump_skb(skb, RX);
#endif // PBB_DEBUG

	skb->dev = pbb_b;

	len = skb->len + ETH_HLEN;
/*	TODO: Is below required?
	skb = skb_share_check(skb, GFP_ATOMIC);
	if (!skb) {
		ret = NET_RX_DROP;
		handle_res = RX_HANDLER_CONSUMED;
		goto update_rx_stats;
	}
*/

        skb->pkt_type = PACKET_HOST;
        *pskb = skb;

	ret = NET_RX_SUCCESS;
	handle_res = RX_HANDLER_ANOTHER;
	goto update_rx_stats;

handle_failure:
	len = skb ? skb->len + ETH_HLEN : ETH_HLEN;
	if (skb) kfree(skb);
	ret = NET_RX_DROP;
	handle_res = RX_HANDLER_CONSUMED;
	if (!b_priv || !pbb_b) return handle_res;

update_rx_stats:
	/* Do Rx stats accounting for PBB_B Device */
	// FIXME: Why likely required???
	if (likely(ret == NET_RX_SUCCESS)) {
        	struct pbb_pcpu_stats *pcpu_stats = get_cpu_ptr(b_priv->pcpu_stats);
		if (!pcpu_stats) {
			goto rx_handler_ret;
		}

                u64_stats_update_begin(&pcpu_stats->syncp);
                u64_stats_inc(&pcpu_stats->rx_packets);
                u64_stats_add(&pcpu_stats->rx_bytes, len);
                if (dot1ah_outer_eth_hdr_in && is_multicast_ether_addr(dot1ah_outer_eth_hdr_in->bb_dmac))
			u64_stats_inc(&pcpu_stats->rx_multicast);
		u64_stats_update_end(&pcpu_stats->syncp);
		put_cpu_ptr(pcpu_stats);
        } else {
                this_cpu_inc(b_priv->pcpu_stats->rx_errors);
        }

rx_handler_ret:
        return handle_res;
}

/***************************************** B-Driver Netlink Routines ****************************************/
static const struct device_type pbb_b_type = {
        .name = "pbbb",
};

static int pbb_b_hard_header(struct sk_buff *skb, struct net_device *pbb_b,
                             unsigned short type, const void *daddr,
                             const void *saddr, unsigned len)
{
        struct pbb_b_priv *b_priv = netdev_priv(pbb_b);
        struct net_device *lowerdev = b_priv->lowerdev;

	if (!pbb_b || !lowerdev || !skb) {
		return -EINVAL;
	}

        return dev_hard_header(skb, lowerdev, type, daddr,
                               saddr ? : pbb_b->dev_addr, len);
}

static const struct header_ops pbb_b_hard_header_ops = {
        .create         = pbb_b_hard_header,
        .parse          = eth_header_parse,
        .cache          = eth_header_cache,
        .cache_update   = eth_header_cache_update,
        .parse_protocol = eth_header_parse_protocol,
};

static void pbb_b_free(struct net_device *pbb_b)
{
	struct pbb_b_priv *b_priv = NULL;

	if (!pbb_b) {
		printk(KERN_ERR "%s: PBB_B invalid!", __FUNCTION__);

		return;
	}

	b_priv = netdev_priv(pbb_b);

	pbb_info(pbb_b, "%s: Processing PBB_B Free", __FUNCTION__);

	if (b_priv->lowerdev) {
        	/* Get rid of PBB_B's reference to lowerdev */
        	netdev_put(b_priv->lowerdev, &b_priv->dev_tracker);
	}
}

static void pbb_b_setup(struct net_device *pbb_b)
{
	//struct pbb_b_priv *b_priv = netdev_priv(pbb_b); //TODO: Uncomment only if required

	pbb_info(pbb_b, "%s: Setting Up PBB_B", __FUNCTION__);

	ether_setup(pbb_b);

	SET_NETDEV_DEVTYPE(pbb_b, &pbb_b_type);

       /* Fill in device structure with ethernet-generic values. */
        eth_hw_addr_random(pbb_b);

	/* ether_setup() has set dev->min_mtu to ETH_MIN_MTU. */
        pbb_b->min_mtu		= ETH_MIN_MTU;
	pbb_b->max_mtu		= ETH_MAX_MTU;

	pbb_b->priv_flags	|= IFF_NO_QUEUE;
        pbb_b->priv_flags	|= IFF_UNICAST_FLT | IFF_CHANGE_PROTO_DOWN;
	pbb_b->priv_flags	&= ~IFF_TX_SKB_SHARING;

	netif_keep_dst(pbb_b);

	pbb_b->needs_free_netdev= true;
	pbb_b->priv_destructor	= pbb_b_free;
	pbb_b->netdev_ops	= &pbb_b_netdev_ops;
	pbb_b->header_ops	= &pbb_b_hard_header_ops;

	pbb_b->pcpu_stat_type = NETDEV_PCPU_STAT_TSTATS;
}

static int pbb_b_validate(struct nlattr *tb[], struct nlattr *data[],
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

#if 0
static void pbb_disable_gro(struct net_device *pbb)
{
        pbb->features &= ~NETIF_F_GRO;
        pbb->wanted_features &= ~NETIF_F_GRO;
        netdev_update_features(pbb);
	pbb_info(pbb, "%s: PBB Update feature", __FUNCTION__);
}
#endif

/* TODO: Lowerdev will be added via "ip link set" (aka changelink sequence)
 * not via "ip link add" (aka newlink sequence)
 */
static int pbb_b_newlink(struct net *src_net, struct net_device *pbb_b,
			 struct nlattr *tb[], struct nlattr *data[],
			 struct netlink_ext_ack *extack)
{
	int ret = 0;
	struct pbb_b_priv *b_priv = NULL;

	pbb_info(pbb_b, "%s: Processing PBB_B Newlink", __FUNCTION__);

	/*
	 * register PBB_B
	 */
	ret = register_netdevice(pbb_b);
	if (ret < 0)
		goto err_register_pbb_b;

	b_priv = netdev_priv(pbb_b);

	ret = pbb_l2vpn_ah_rht_init(&b_priv->pbb_l2vpn_ah_rht);
	if (ret) {
		pbb_err(pbb_b, "%s: Failed to initialize PBB L2VPN AH RHT error:%d!",
			__FUNCTION__, ret);

		goto err_ah_rht_init_pbb_b;
	}

	ret = pbb_l2vpn_fdb_rht_init(&b_priv->pbb_l2vpn_fdb_rht);
	if (ret) {
		pbb_err(pbb_b, "%s: Failed to initialize PBB L2VPN FDB RHT error:%d!",
			__FUNCTION__, ret);

		goto err_fdb_rht_init_pbb_b;
	}

	netif_carrier_off(pbb_b);

#if 0
	pbb_disable_gro(pbb_b);
#endif

	pbb_info(pbb_b, "%s: PBB_B NewLink processed successfully",
		 __FUNCTION__);

	return 0;

err_fdb_rht_init_pbb_b:
	rhashtable_destroy(&b_priv->pbb_l2vpn_fdb_rht);

	unregister_netdevice(pbb_b);

err_ah_rht_init_pbb_b:
	rhashtable_destroy(&b_priv->pbb_l2vpn_ah_rht);

	unregister_netdevice(pbb_b);

err_register_pbb_b:
	pbb_err(pbb_b, "%s: PBB_B Registration failed with error:0x%x!",
		 __FUNCTION__, ret);

	free_netdev(pbb_b);

	return ret;
}

static int pbb_b_port_create(struct net_device *lowerdev, struct net_device *pbb_b)
{
	struct pbb_b_port *pbb_b_port = NULL;
	int err = 0;

	if (!lowerdev || !pbb_b) {
		printk(KERN_ERR "%s: Invalid Lowerdev:%p or PBB_B:%p instance!",
		       __FUNCTION__, lowerdev, pbb_b);

		return -EINVAL;
	}

	if ((lowerdev->type != ARPHRD_ETHER) || (lowerdev->flags & IFF_LOOPBACK)) {
		pbb_err(pbb_b, "%s: Lowerdev:%s requires ARPHDR support (type:%d) and should not be loopback (flags:0x%x)!",
			__FUNCTION__, lowerdev->name, lowerdev->type, lowerdev->flags);

		return -EINVAL;
	}

	if (netdev_is_rx_handler_busy(lowerdev)) {
		pbb_err(pbb_b, "%s: Lowerdev:%s Rx Handler already in-use!",
			__FUNCTION__, lowerdev->name);

		return -EBUSY;
	}

	pbb_b_port = kzalloc(sizeof(*pbb_b_port), GFP_KERNEL);
	if (pbb_b_port == NULL) {
		pbb_err(pbb_b, "%s: Failed to allocate PBB_B Port Memory for Lowerdev:%s device",
			__FUNCTION__, lowerdev->name);

		return -ENOMEM;
	}

	rcu_assign_pointer(pbb_b_port->lowerdev, lowerdev);
	rcu_assign_pointer(pbb_b_port->pbb_b, pbb_b);

	// Save a backup of Lowerdev address to be restored back later once lowerdev gets unlinked with PBB_B
	ether_addr_copy(pbb_b_port->perm_addr, lowerdev->dev_addr);

	// FIXME: Implement netdev_rx_handler_unregister!
	err = netdev_rx_handler_register(lowerdev, pbb_b_handle_frame_from_core, pbb_b_port);
	if (err) {
		pbb_err(pbb_b, "%s:Failed to register Rx Handler with error:%d for Lowerdev:%s!",
			__FUNCTION__, err, lowerdev->name);
		kfree(pbb_b_port);

		return err;
	} else {
		lowerdev->priv_flags |= IFF_PBB_B_PORT;
	}

	pbb_info(pbb_b, "%s: PBB Port Create with Lowerdev:%s linked successfull",
		__FUNCTION__, lowerdev->name);

	return 0;
}

static void pbb_b_port_destroy(struct net_device *lowerdev)
{
	struct pbb_b_port *pbb_b_port = lowerdev ? pbb_b_port_get_rtnl(lowerdev) : NULL;
	struct net_device *pbb_b = NULL;
        struct pbb_b_priv *b_priv = NULL;

	if (!pbb_b_port) {
		printk(KERN_ERR "%s: Lowerdev:%p OR PBB_B_Port seems invalid, failed to unlink",
		       __FUNCTION__, lowerdev);
		return;
	}

	pbb_b = rtnl_dereference(pbb_b_port->pbb_b);
	if (!pbb_b) {
		printk(KERN_ERR "%s: PBB_B_Port seems invalid, failed to unlink!",
		       __FUNCTION__);
		return;
	}

	b_priv = netdev_priv(pbb_b);
	if (!b_priv) {
		printk(KERN_ERR "%s: PBB_B Priv seems invalid!",
		       __FUNCTION__);
		return;
	}

	lowerdev->priv_flags &= ~IFF_PBB_B_PORT;
	netdev_rx_handler_unregister(lowerdev);

	/* If the lower device address has been changed, put it back.
	 */
	if (!ether_addr_equal(pbb_b_port->lowerdev->dev_addr, pbb_b_port->perm_addr)) {
		struct sockaddr sa;

		sa.sa_family = pbb_b_port->lowerdev->type;
		memcpy(&sa.sa_data, pbb_b_port->perm_addr, pbb_b_port->lowerdev->addr_len);
		dev_set_mac_address(pbb_b_port->lowerdev, &sa, NULL);
	}

	kfree(pbb_b_port);
	b_priv->pbb_b_port = NULL;

	pbb_info(pbb_b, "%s: PBB Port Destroyed with Lowerdev:%s unlinked successfull",
		__FUNCTION__, lowerdev->name);
}

static int pbb_b_changelink(struct net_device *pbb_b,
                            struct nlattr *tb[], struct nlattr *data[],
                            struct netlink_ext_ack *extack)
{
	struct net *src_net = NULL;
        struct pbb_b_priv *b_priv = netdev_priv(pbb_b);
	struct pbb_b_port *pbb_b_port = NULL;
	struct net_device *lowerdev = NULL;
	bool skip_pbb_b_link_processing = false, sid_bvid_update = false;
	u8 b_vid_mode = PBB_B_MODE_MAX, key_info_map_verify = 0;
	int err = 0;
	int i = 0;

	pbb_info(pbb_b, "%s: Processing PBB_B Changelink", __FUNCTION__);
	for (i = 0; i < __IFLA_MAX; i++) {
		if (tb[i]) {
			printk(KERN_ERR "%s: %d set", __FUNCTION__, i);
		}
	}

	if (data && data[IFLA_PBB_B_LINK]) {
		pbb_info(pbb_b, "%s: Processing PBB_B Changelink Link Notification",
			 __FUNCTION__);

		src_net = dev_net(pbb_b);
		if (!src_net) {
		        pbb_err(pbb_b, "%s: Src Network Namespace does not exist yet!", __FUNCTION__);
		        return -EINVAL;
		}
		
		lowerdev = __dev_get_by_index(src_net, nla_get_u32(data[IFLA_PBB_B_LINK]));
		if (lowerdev == NULL) {
			pbb_err(pbb_b, "%s: Lowerdev device does not exist!", __FUNCTION__);
			return -ENODEV;
		}

		/*
		 * Nested PBB devices are not supported for now.
		 */
		if (netif_is_pbb_b(lowerdev) || netif_is_pbb_i(lowerdev)) {
			pbb_err(pbb_b, "%s: Lowerdev device %s cannot be a PBB Instance!",
				__FUNCTION__, lowerdev->name);
			return -ENOTSUPP;
		}

		if ((lowerdev->priv_flags & IFF_PBB_B_PORT) && (b_priv->lowerdev == lowerdev)) {
			pbb_info(pbb_b, "%s: Lowerdev:%s already linked to this PBB_B!",
				 __FUNCTION__, lowerdev->name);
			
			skip_pbb_b_link_processing = true;
			err = -EINVAL;

			goto parse_next_arg;
		} else if (lowerdev->priv_flags & IFF_PBB_B_PORT) {
			pbb_err(pbb_b, "%s: Lowerdev:%s already linked to some other PBB_B!",
				__FUNCTION__, lowerdev->name);

			return -EINVAL;
		}
	
		if (!tb[IFLA_MTU])
			pbb_b->mtu = lowerdev->mtu;
		else if (pbb_b->mtu > lowerdev->mtu) {
			pbb_err(pbb_b, "%s: PBB_B Device MTU %d cannot be greated than Lowerdev device %s MTU %d",
				__FUNCTION__, pbb_b->mtu, lowerdev->name, lowerdev->mtu);
			return -EINVAL;
		}
		
		/* MTU range: 68 - lowerdev->max_mtu */
		pbb_b->min_mtu = ETH_MIN_MTU; // FIXME: Remove this as already done in pbb_b_setup()?
		pbb_b->max_mtu = lowerdev->max_mtu;
		
		if (!tb[IFLA_ADDRESS]) {
			pbb_info(pbb_b, "%s: Setting random Mac address for PBB_B", __FUNCTION__);
			eth_hw_addr_random(pbb_b);
		}
	
		err = pbb_b_port_create(lowerdev, pbb_b);
		if (err < 0) {
			pbb_err(pbb_b, "%s: PBB_B Port Create for Lowerdev %s",
				__FUNCTION__, lowerdev->name);

			return err;
		}

		pbb_b_port = pbb_b_port_get_rtnl(lowerdev);
		
		b_priv->lowerdev 	= lowerdev;
		b_priv->self_pbb_b	= pbb_b;
		b_priv->pbb_b_port	= pbb_b_port;
		
		eth_hw_addr_inherit(pbb_b, lowerdev);
	
		// FIXME: Hold RTNL lock?
		err = netdev_upper_dev_link(lowerdev, pbb_b, extack);
		if (err)
			goto destroy_pbb_b_port;
	
		netif_stacked_transfer_operstate(lowerdev, pbb_b);
		linkwatch_fire_event(pbb_b);

		pbb_info(pbb_b, "%s: Lowerdev:%s linking successfull",
			__FUNCTION__, lowerdev->name);

		pbb_info(pbb_b, "%s: Calling pbb_b_init() again after Lowerdev:%s linking!",
			 __FUNCTION__, lowerdev->name);
		pbb_b_init(pbb_b);
	}

parse_next_arg:
	if (data && data[IFLA_PBB_B_B_VID_MODE]) {
		b_vid_mode = nla_get_u8(data[IFLA_PBB_B_B_VID_MODE]);

		struct pbb_b_port *pbb_b_port = b_priv->pbb_b_port;

		pbb_info(pbb_b, "%s: Processing PBB_B Changelink PBB_B B-VID Mode Notification",
			 __FUNCTION__);

		if (pbb_b_port) {
			if (b_vid_mode == PBB_B_MODE_DOT1Q)
				pbb_b_port->flags |= PBB_B_PORT_FLAGS_MODE_DOT1Q;
			else
				pbb_b_port->flags |= PBB_B_PORT_FLAGS_MODE_DOT1AD;

			pbb_info(pbb_b, "%s: PBB_B Port:%s B-Vid Mode:%d in flags:0x%x set successfully!",
				 __FUNCTION__, pbb_b_port->lowerdev->name, b_vid_mode, pbb_b_port->flags);
		} else {
			pbb_err(pbb_b, "%s: PBB_B Port not initialized yet, unable to set PBB_B Port B-Vid Mode to %d!",
				__FUNCTION__, b_vid_mode);

			err = -ENODEV;
			goto destroy_pbb_b_port;
		}

		sid_bvid_update = true;
	}

	if (data && data[IFLA_PBB_B_KEY_INFO_MAP_VERIFY]) {
		pbb_info(pbb_b, "%s: Processing PBB_B Changelink PBB_B Key Info Map Dump Notification",
			 __FUNCTION__);

		key_info_map_verify = nla_get_u8(data[IFLA_PBB_B_KEY_INFO_MAP_VERIFY]);

		sid_bvid_update = true;
	}

	u32 i_sid_info_range_begin = 0, i_sid_info_range_end = 0, b_vid_info_range_begin = 0, b_vid_info_range_end = 0;
	if (data && data[IFLA_PBB_B_ISID_INFO_RANGE_BEGIN] && data[IFLA_PBB_B_ISID_INFO_RANGE_END]) {
		i_sid_info_range_begin = nla_get_u32(data[IFLA_PBB_B_ISID_INFO_RANGE_BEGIN]);
		i_sid_info_range_end = nla_get_u32(data[IFLA_PBB_B_ISID_INFO_RANGE_END]);

		sid_bvid_update = true;
	}

	if (data && data[IFLA_PBB_B_VID_INFO_RANGE_BEGIN] && data[IFLA_PBB_B_VID_INFO_RANGE_END]) {
		b_vid_info_range_begin = nla_get_u32(data[IFLA_PBB_B_VID_INFO_RANGE_BEGIN]);
		b_vid_info_range_end = nla_get_u32(data[IFLA_PBB_B_VID_INFO_RANGE_END]);

		sid_bvid_update = true;
	}

	if (sid_bvid_update == false) {
		goto return_success;
	}
	
	if ((!i_sid_info_range_begin || !i_sid_info_range_end || !b_vid_info_range_begin || !b_vid_info_range_end) ||
	    ((b_vid_mode == PBB_B_MODE_MAX) && (key_info_map_verify == 0))) {
		pbb_err(pbb_b, "%s: ISID Range:%d-%d and/or B-VID Range:%d-%d and/or B-VID_Mode:%d all are not defined!",
			__FUNCTION__, i_sid_info_range_begin, i_sid_info_range_end,
			b_vid_info_range_begin, b_vid_info_range_end, b_vid_mode);

		err = -EINVAL;
		goto destroy_pbb_b_port;
	}

	pbb_info(pbb_b, "%s: Processing PBB_B Changelink ISID->B_VID %s Notification",
		__FUNCTION__, key_info_map_verify ? "Dump" : "Map");

	pbb_info(pbb_b, "%s: ISID Range:%d-%d, B-VID Range:%d-%d, B-VID_Mode:%d Key_Info_Map_Dump:%d",
		 __FUNCTION__, i_sid_info_range_begin, i_sid_info_range_end,
		 b_vid_info_range_begin, b_vid_info_range_end, b_vid_mode, key_info_map_verify);

	struct pbb_l2vpn_ah_rhnode ah_rhnode_core = {0};
	struct pbb_l2vpn_ah_rhnode *ah_rhnode_core1 = NULL;
	u32 i_sid = 0, b_vid = b_vid_info_range_begin;
	/* FIXME: Make this logic more free flowing and optimized */
	/* Create and add [isid(core) -> bvid] Mapping */
	for (i_sid = i_sid_info_range_begin; i_sid <= i_sid_info_range_end; i_sid++) {
		err = 0;

		if (key_info_map_verify == 0) {
			ah_rhnode_core1 = pbb_l2vpn_ah_rhnode_alloc();
			if (!ah_rhnode_core1) {
				pbb_err(pbb_b, "%s: Failed to allocate PBB L2VPN AH RHNode!", __FUNCTION__);
	
				err = -ENOMEM;
				goto destroy_pbb_b_port;
			}
	
			memset(ah_rhnode_core1, 0, sizeof(struct pbb_l2vpn_ah_rhnode));
			ah_rhnode_core1->pbb_b = pbb_b;
		} else {
			ah_rhnode_core1 = &ah_rhnode_core;
		}

		err = pbb_l2vpn_ah_rhnode_type_i_sid_key_add(&ah_rhnode_core1->rhnode_key, i_sid, PBB_L2VPN_RHNODE_TYPE_I_SID_KEY_DIR_CORE);
		if (err) {
			pbb_err(pbb_b, "%s: Failed to add [key-i_sid:%d(core)] to PBB L2VPN AH RHNode with err:0x%x!",
				 __FUNCTION__, i_sid, err);
	
			goto free_pbb_l2vpn_rhnodes;
		}
	
		err = pbb_l2vpn_ah_rhnode_type_b_vid_info_add(&ah_rhnode_core1->rhnode_info, b_vid);
		if (err) {
			pbb_err(pbb_b, "%s: Failed to add [info-b_vid:%d] to PBB L2VPN AH RHNode with err:0x%x!",
				 __FUNCTION__, b_vid, err);
	
			goto free_pbb_l2vpn_rhnodes;
		}
	
		err = -EINVAL;
		if (key_info_map_verify == 0) {
			err = pbb_l2vpn_ah_rhnode_insert(&b_priv->pbb_l2vpn_ah_rht, &ah_rhnode_core1->rhnode_hash);
		} else {
			ah_rhnode_core1 = pbb_l2vpn_ah_rhnode_lookup(&b_priv->pbb_l2vpn_ah_rht, &ah_rhnode_core1->rhnode_key);
			if (ah_rhnode_core1 && (ah_rhnode_core.rhnode_info.b_vid_hash_info == ah_rhnode_core1->rhnode_info.b_vid_hash_info)) {
				err = 0;
			}
		}
		if (err) {
			pbb_err(pbb_b, "%s: Failed to %s [key-i_sid:%d(core) -> info-b_vid:%d] mapping to PBB L2VPN AH RHT with err:0x%x!",
				__FUNCTION__, key_info_map_verify ? "verify" : "insert",
				i_sid,
				b_vid,
				err);
	
			goto free_pbb_l2vpn_rhnodes;
		} else {
			pbb_info(pbb_b, "%s: Successfully %s [key-i_sid:%d(core) -> info-b_vid:%d] mapping as HASH[key-0x%x -> info-0x%x] to PBB P2VPN AH RHT",
				 __FUNCTION__, key_info_map_verify ? "verified" : "inserted",
				 i_sid,
				 b_vid,
				 ah_rhnode_core1->rhnode_key, ah_rhnode_core1->rhnode_info.b_vid_hash_info);
		}

		/* TODO: Not required to create and add [bvid -> isid] Mapping for now
		 * Implement in future iff required */
	
		/* Now Iterate next */
		if (b_vid < b_vid_info_range_end) b_vid++;
	}

return_success:
	return 0;

free_pbb_l2vpn_rhnodes:
	if ((key_info_map_verify == 0) && ah_rhnode_core1) pbb_l2vpn_ah_rhnode_free(ah_rhnode_core1);

destroy_pbb_b_port:
	//pbb_b_port->pbb_b->rtnl_link_ops->dellink(pbb_b, NULL);
	/* pbb_b_uninit would free the PBB_B Port */
	//unregister_netdevice(pbb_b);

	if ((skip_pbb_b_link_processing == false) && pbb_b_port && lowerdev) {
		pbb_b_port_destroy(pbb_b_port->lowerdev);
	}

	pbb_err(pbb_b, "%s: changelink failed with error 0x%x",
		__FUNCTION__, err);

	return err;
}

static void pbb_b_dellink(struct net_device *pbb_b, struct list_head *head)
{
	struct pbb_b_priv *b_priv = NULL;
	struct pbb_i_priv *i_priv = NULL;
	struct net_device *pbb_i = NULL, *lowerdev = NULL;

	pbb_info(pbb_b, "%s: Processing PBB_B Dellink", __FUNCTION__);

	b_priv = netdev_priv(pbb_b);

	if (!b_priv) {
		pbb_err(pbb_b, "%s: PBB_B Private Metadata not valid anymore!", __FUNCTION__);

		return;
	}

	/* Note : dellink() is called from default_device_exit_batch(),
	 * before a rcu_synchronize() point. The devices are guaranteed
	 * not being freed before one RCU grace period.
	 */
	pbb_i = rtnl_dereference(b_priv->pbb_i);
	if (pbb_i) {
		pbb_info(pbb_i, "%s: Also Processing Peer PBB_I Dellink",
		         __FUNCTION__);
		i_priv = netdev_priv(pbb_i);
		RCU_INIT_POINTER(i_priv->pbb_b, NULL);
		unregister_netdevice_queue(pbb_i, head);
	}
	RCU_INIT_POINTER(b_priv->pbb_i, NULL);

	lowerdev = rtnl_dereference(b_priv->lowerdev);
	if (lowerdev) {
		pbb_info(pbb_b, "%s: Unlinking lowerdev:%s link",
			 __FUNCTION__, lowerdev->name);

		netdev_upper_dev_unlink(lowerdev, pbb_b);
		/* FIXME: Do in pbb_b_uninit instead?
		RCU_INIT_POINTER(b_priv->lowerdev, NULL);
		RCU_INIT_POINTER(b_priv->pbb_b_port, NULL);
		 */
	}
	unregister_netdevice_queue(pbb_b, head);
}

static struct net *pbb_b_get_link_net(const struct net_device *pbb_b)
{
	const struct net_device *dev = pbb_b_get_lowerdev(pbb_b);
	
	if (!dev) {
		dev = pbb_b;
	}

        return dev_net(dev);
}

static size_t pbb_b_get_size(const struct net_device *pbb_b)
{
        return (0
                + nla_total_size(4) /* IFLA_PBB_B_LINK */
                + nla_total_size(4) /* IFLA_PBB_B_ISID_INFO_RANGE_BEGIN */
                + nla_total_size(4) /* IFLA_PBB_B_ISID_INFO_RANGE_END */
                + nla_total_size(1) /* IFLA_PBB_B_B_VID_MODE */
                + nla_total_size(4) /* IFLA_PBB_B_VID_INFO_RANGE_BEGIN */
                + nla_total_size(4) /* IFLA_PBB_B_VID_INFO_RANGE_END */
                );
}

const struct nla_policy pbb_b_policy[IFLA_PBB_B_MAX] = {
	[IFLA_PBB_B_LINK]			= { .type = NLA_U32 },
	[IFLA_PBB_B_ISID_INFO_RANGE_BEGIN]	= { .type = NLA_U32 },
	[IFLA_PBB_B_ISID_INFO_RANGE_END]	= { .type = NLA_U32 },
	[IFLA_PBB_B_B_VID_MODE]  		= { .type = NLA_U8 },
	[IFLA_PBB_B_VID_INFO_RANGE_BEGIN]	= { .type = NLA_U32 },
	[IFLA_PBB_B_VID_INFO_RANGE_END]		= { .type = NLA_U32 },
};

static struct rtnl_link_ops pbb_b_link_ops;

int pbb_b_rtnl_link_register(void) {
	pbb_b_link_ops.kind		= PBB_B_DRV_NAME;
	pbb_b_link_ops.priv_size	= sizeof(struct pbb_b_priv);
	pbb_b_link_ops.setup		= pbb_b_setup;
	pbb_b_link_ops.validate		= pbb_b_validate;
	pbb_b_link_ops.newlink		= pbb_b_newlink;
	pbb_b_link_ops.changelink	= pbb_b_changelink;
	pbb_b_link_ops.dellink		= pbb_b_dellink;
	pbb_b_link_ops.get_link_net	= pbb_b_get_link_net,
	pbb_b_link_ops.get_size		= pbb_b_get_size,
	pbb_b_link_ops.policy		= pbb_b_policy;
	pbb_b_link_ops.maxtype		= IFLA_PBB_B_MAX-1;

	return rtnl_link_register(&pbb_b_link_ops);
}

void pbb_b_rtnl_link_unregister(void) {
	rtnl_link_unregister(&pbb_b_link_ops);
}


/***************************************** B-Driver Netdevice Notifier Routines ****************************************/
static int pbb_b_handle_notifier_event(struct notifier_block *unused,
				       unsigned long event, void *ptr)
{
	struct net_device *lowerdev = netdev_notifier_info_to_dev(ptr);
	struct net_device *pbb_b = NULL;
	struct pbb_b_port *pbb_b_port = NULL;

	if (!lowerdev) {
		return -EINVAL;
	}
	
	if (!netif_is_pbb_b_port(lowerdev)) {
		return NOTIFY_DONE;
	}

	pbb_b_port = pbb_b_port_get_rtnl(lowerdev);
	if (!pbb_b_port) {
		return -EINVAL;
	}

	pbb_b = rtnl_dereference(pbb_b_port->pbb_b);
	if (!pbb_b) {
		return -EINVAL;
	}

	switch (event) {
		case NETDEV_UP:
		case NETDEV_DOWN:
		case NETDEV_CHANGE:
			netif_stacked_transfer_operstate(lowerdev,
							 pbb_b);

			break;

		case NETDEV_FEAT_CHANGE:
			netif_inherit_tso_max(pbb_b, lowerdev);
			netdev_update_features(pbb_b);

			break;

		case NETDEV_CHANGEMTU:
			if (pbb_b->mtu > lowerdev->mtu)
				dev_set_mtu(pbb_b, lowerdev->mtu);
			break;

		case NETDEV_CHANGEADDR:
			/* TODO: Implement PBB_B Mac Address Hierarchy design and inheritance,
			 * then complete below accordingly.
			 */
			if (pbb_b_port && pbb_b_sync_address(pbb_b, lowerdev->dev_addr))
				return NOTIFY_BAD;

			break;//Make stupid compiler happy

		case NETDEV_UNREGISTER:
			if (lowerdev->reg_state != NETREG_UNREGISTERING) {
				break;
			}

			pbb_b_port->pbb_b->rtnl_link_ops->dellink(pbb_b, NULL);
			//FIXME: Uncomment this code and fix lowerdev del issue
			//unregister_netdevice(lowerdev);

			break;

		case NETDEV_PRE_TYPE_CHANGE:
			/* Forbid underlying device to change its type. */
			return NOTIFY_BAD;

		/* FIXME: Any use keeping below? */
		case NETDEV_NOTIFY_PEERS:
		case NETDEV_BONDING_FAILOVER:
		case NETDEV_RESEND_IGMP:
			call_netdevice_notifiers(event, pbb_b);
	}

	return NOTIFY_DONE;
}

static struct notifier_block pbb_b_notifier_block __read_mostly = {
	.notifier_call	= pbb_b_handle_notifier_event,
};


void pbb_b_netdev_notifier_register(void) {
	register_netdevice_notifier(&pbb_b_notifier_block);
}

void pbb_b_netdev_notifier_unregister(void) {
	unregister_netdevice_notifier(&pbb_b_notifier_block);
}
