/*
 * Copyright (c) 2011-2012 Xsigo Systems. All rights reserved
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "xve.h"

static void xve_get_drvinfo(struct net_device *netdev,
			    struct ethtool_drvinfo *drvinfo)
{
	strncpy(drvinfo->driver, "xve", sizeof(drvinfo->driver) - 1);
	strncpy(drvinfo->version, XVE_DRIVER_VERSION, 32);
	strncpy(drvinfo->fw_version, "N/A", 32);
	strncpy(drvinfo->bus_info, "N/A", 32);
}

static int xve_get_coalesce(struct net_device *dev,
			    struct ethtool_coalesce *coal)
{
	struct xve_dev_priv *priv = netdev_priv(dev);

	coal->rx_coalesce_usecs = priv->ethtool.coalesce_usecs;
	coal->tx_coalesce_usecs = priv->ethtool.coalesce_usecs;
	coal->rx_max_coalesced_frames = priv->ethtool.max_coalesced_frames;
	coal->tx_max_coalesced_frames = priv->ethtool.max_coalesced_frames;

	return 0;
}

static int xve_set_coalesce(struct net_device *dev,
			    struct ethtool_coalesce *coal)
{
	struct xve_dev_priv *priv = netdev_priv(dev);
	int ret;

	/*
	 * Since Xve uses a single CQ for both rx and tx, we assume
	 * that rx params dictate the configuration.  These values are
	 * saved in the private data and returned when xve_get_coalesce()
	 * is called.
	 */
	if (coal->rx_coalesce_usecs > 0xffff ||
	    coal->rx_max_coalesced_frames > 0xffff)
		return -EINVAL;

	if (coal->rx_max_coalesced_frames | coal->rx_coalesce_usecs) {
		if (!coal->rx_max_coalesced_frames)
			coal->rx_max_coalesced_frames = 0xffff;
		else if (!coal->rx_coalesce_usecs)
			coal->rx_coalesce_usecs = 0xffff;
	}

	ret = ib_modify_cq(priv->recv_cq, coal->rx_max_coalesced_frames,
			   coal->rx_coalesce_usecs);

	if (ret) {
		xve_warn(priv, "failed modifying CQ (%d)\n", ret);
		return ret;
	}

	coal->tx_coalesce_usecs = coal->rx_coalesce_usecs;
	coal->tx_max_coalesced_frames = coal->rx_max_coalesced_frames;
	priv->ethtool.coalesce_usecs = coal->rx_coalesce_usecs;
	priv->ethtool.max_coalesced_frames = coal->rx_max_coalesced_frames;

	return 0;
}

static const char xve_stats_keys[][ETH_GSTRING_LEN] = {
	"rx_packets", "rx_bytes", "rx_errors", "rx_drops",
	"tx_packets", "tx_bytes", "tx_errors", "tx_drops",
	"LRO aggregated", "LRO flushed",
	"LRO avg aggr", "LRO no desc"
};

static void xve_get_strings(struct net_device *netdev, u32 stringset, u8 *data)
{
	switch (stringset) {
	case ETH_SS_STATS:
		memcpy(data, *xve_stats_keys, sizeof(xve_stats_keys));
		break;
	}
}

static int xve_get_sset_count(struct net_device *dev, int sset)
{
	switch (sset) {
	case ETH_SS_STATS:
		return ARRAY_SIZE(xve_stats_keys);
	default:
		return -EOPNOTSUPP;
	}
}

static void xve_get_ethtool_stats(struct net_device *dev,
				  struct ethtool_stats *stats, uint64_t *data)
{
	struct xve_dev_priv *priv = netdev_priv(dev);
	int index = 0;

	/* Get LRO statistics */
	data[index++] = dev->stats.rx_packets;
	data[index++] = dev->stats.rx_bytes;
	data[index++] = dev->stats.rx_errors;
	data[index++] = dev->stats.rx_dropped;

	data[index++] = dev->stats.tx_packets;
	data[index++] = dev->stats.tx_bytes;
	data[index++] = dev->stats.tx_errors;
	data[index++] = dev->stats.tx_dropped;

	data[index++] = priv->lro.lro_mgr.stats.aggregated;
	data[index++] = priv->lro.lro_mgr.stats.flushed;
	if (priv->lro.lro_mgr.stats.flushed)
		data[index++] = priv->lro.lro_mgr.stats.aggregated /
		    priv->lro.lro_mgr.stats.flushed;
	else
		data[index++] = 0;
	data[index++] = priv->lro.lro_mgr.stats.no_desc;
}

static int xve_get_settings(struct net_device *netdev, struct ethtool_cmd *ecmd)
{
	struct xve_dev_priv *xvep = netdev_priv(netdev);

	ecmd->autoneg = 0;
	ecmd->speed = SPEED_10000;
	ecmd->duplex = DUPLEX_FULL;	/* Duplex is hard coded */
	if (netif_carrier_ok(netdev)) {
		ecmd->speed = xvep->port_speed;
		ecmd->advertising = ADVERTISED_10000baseT_Full;
		ecmd->supported = SUPPORTED_10000baseT_Full |
		    SUPPORTED_FIBRE | SUPPORTED_Autoneg;
		ecmd->port = PORT_FIBRE;
		ecmd->transceiver = XCVR_EXTERNAL;

	}
	return 0;
}

static const struct ethtool_ops xve_ethtool_ops = {
	.get_settings = xve_get_settings,
	.get_drvinfo = xve_get_drvinfo,
	.get_coalesce = xve_get_coalesce,
	.set_coalesce = xve_set_coalesce,
	.get_strings = xve_get_strings,
	.get_sset_count = xve_get_sset_count,
	.get_ethtool_stats = xve_get_ethtool_stats,
	.get_link = ethtool_op_get_link,
};

void xve_set_ethtool_ops(struct net_device *dev)
{
	dev->ethtool_ops = &xve_ethtool_ops;
}
