/* QLogic qed NIC Driver
 * Copyright (c) 2015 QLogic Corporation
 *
 * This software is available under the terms of the GNU General Public License
 * (GPL) Version 2, available from the file COPYING in the main directory of
 * this source tree.
 */

#ifndef _QED_HSI_H
#define _QED_HSI_H

#include <linux/types.h>
#include <linux/io.h>
#include <linux/bitops.h>
#include <linux/delay.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/qed/common_hsi.h>
#include <linux/qed/eth_common.h>

struct qed_hwfn;
struct qed_ptt;

/* opcodes for the event ring */
enum common_event_opcode {
	COMMON_EVENT_PF_START,
	COMMON_EVENT_PF_STOP,
	COMMON_EVENT_VF_START,
	COMMON_EVENT_VF_STOP,
	COMMON_EVENT_VF_PF_CHANNEL,
	COMMON_EVENT_VF_FLR,
	COMMON_EVENT_PF_UPDATE,
	COMMON_EVENT_MALICIOUS_VF,
	COMMON_EVENT_RL_UPDATE,
	COMMON_EVENT_EMPTY,
	MAX_COMMON_EVENT_OPCODE
};

/* Common Ramrod Command IDs */
enum common_ramrod_cmd_id {
	COMMON_RAMROD_UNUSED,
	COMMON_RAMROD_PF_START,
	COMMON_RAMROD_PF_STOP,
	COMMON_RAMROD_VF_START,
	COMMON_RAMROD_VF_STOP,
	COMMON_RAMROD_PF_UPDATE,
	COMMON_RAMROD_RL_UPDATE,
	COMMON_RAMROD_EMPTY,
	MAX_COMMON_RAMROD_CMD_ID
};

/* The core storm context for the Ystorm */
struct ystorm_core_conn_st_ctx {
	__le32 reserved[4];
};

/* The core storm context for the Pstorm */
struct pstorm_core_conn_st_ctx {
	__le32 reserved[4];
};

/* Core Slowpath Connection storm context of Xstorm */
struct xstorm_core_conn_st_ctx {
	__le32 spq_base_lo;
	__le32 spq_base_hi;
	struct regpair consolid_base_addr;
	__le16 spq_cons;
	__le16 consolid_cons;
	__le32 reserved0[55];
};

struct xstorm_core_conn_ag_ctx {
	u8 reserved0;
	u8 core_state;
	u8 flags0;
#define XSTORM_CORE_CONN_AG_CTX_EXIST_IN_QM0_MASK	0x1
#define XSTORM_CORE_CONN_AG_CTX_EXIST_IN_QM0_SHIFT	0
#define XSTORM_CORE_CONN_AG_CTX_RESERVED1_MASK		0x1
#define XSTORM_CORE_CONN_AG_CTX_RESERVED1_SHIFT		1
#define XSTORM_CORE_CONN_AG_CTX_RESERVED2_MASK		0x1
#define XSTORM_CORE_CONN_AG_CTX_RESERVED2_SHIFT		2
#define XSTORM_CORE_CONN_AG_CTX_EXIST_IN_QM3_MASK	0x1
#define XSTORM_CORE_CONN_AG_CTX_EXIST_IN_QM3_SHIFT	3
#define XSTORM_CORE_CONN_AG_CTX_RESERVED3_MASK		0x1
#define XSTORM_CORE_CONN_AG_CTX_RESERVED3_SHIFT		4
#define XSTORM_CORE_CONN_AG_CTX_RESERVED4_MASK		0x1
#define XSTORM_CORE_CONN_AG_CTX_RESERVED4_SHIFT		5
#define XSTORM_CORE_CONN_AG_CTX_RESERVED5_MASK		0x1
#define XSTORM_CORE_CONN_AG_CTX_RESERVED5_SHIFT		6
#define XSTORM_CORE_CONN_AG_CTX_RESERVED6_MASK		0x1
#define XSTORM_CORE_CONN_AG_CTX_RESERVED6_SHIFT		7
	u8 flags1;
#define XSTORM_CORE_CONN_AG_CTX_RESERVED7_MASK		0x1
#define XSTORM_CORE_CONN_AG_CTX_RESERVED7_SHIFT		0
#define XSTORM_CORE_CONN_AG_CTX_RESERVED8_MASK		0x1
#define XSTORM_CORE_CONN_AG_CTX_RESERVED8_SHIFT		1
#define XSTORM_CORE_CONN_AG_CTX_RESERVED9_MASK		0x1
#define XSTORM_CORE_CONN_AG_CTX_RESERVED9_SHIFT		2
#define XSTORM_CORE_CONN_AG_CTX_BIT11_MASK		0x1
#define XSTORM_CORE_CONN_AG_CTX_BIT11_SHIFT		3
#define XSTORM_CORE_CONN_AG_CTX_BIT12_MASK		0x1
#define XSTORM_CORE_CONN_AG_CTX_BIT12_SHIFT		4
#define XSTORM_CORE_CONN_AG_CTX_BIT13_MASK		0x1
#define XSTORM_CORE_CONN_AG_CTX_BIT13_SHIFT		5
#define XSTORM_CORE_CONN_AG_CTX_TX_RULE_ACTIVE_MASK	0x1
#define XSTORM_CORE_CONN_AG_CTX_TX_RULE_ACTIVE_SHIFT	6
#define XSTORM_CORE_CONN_AG_CTX_DQ_CF_ACTIVE_MASK	0x1
#define XSTORM_CORE_CONN_AG_CTX_DQ_CF_ACTIVE_SHIFT	7
	u8 flags2;
#define XSTORM_CORE_CONN_AG_CTX_CF0_MASK	0x3
#define XSTORM_CORE_CONN_AG_CTX_CF0_SHIFT	0
#define XSTORM_CORE_CONN_AG_CTX_CF1_MASK	0x3
#define XSTORM_CORE_CONN_AG_CTX_CF1_SHIFT	2
#define XSTORM_CORE_CONN_AG_CTX_CF2_MASK	0x3
#define XSTORM_CORE_CONN_AG_CTX_CF2_SHIFT	4
#define XSTORM_CORE_CONN_AG_CTX_CF3_MASK	0x3
#define XSTORM_CORE_CONN_AG_CTX_CF3_SHIFT	6
	u8 flags3;
#define XSTORM_CORE_CONN_AG_CTX_CF4_MASK	0x3
#define XSTORM_CORE_CONN_AG_CTX_CF4_SHIFT	0
#define XSTORM_CORE_CONN_AG_CTX_CF5_MASK	0x3
#define XSTORM_CORE_CONN_AG_CTX_CF5_SHIFT	2
#define XSTORM_CORE_CONN_AG_CTX_CF6_MASK	0x3
#define XSTORM_CORE_CONN_AG_CTX_CF6_SHIFT	4
#define XSTORM_CORE_CONN_AG_CTX_CF7_MASK	0x3
#define XSTORM_CORE_CONN_AG_CTX_CF7_SHIFT	6
	u8 flags4;
#define XSTORM_CORE_CONN_AG_CTX_CF8_MASK	0x3
#define XSTORM_CORE_CONN_AG_CTX_CF8_SHIFT	0
#define XSTORM_CORE_CONN_AG_CTX_CF9_MASK	0x3
#define XSTORM_CORE_CONN_AG_CTX_CF9_SHIFT	2
#define XSTORM_CORE_CONN_AG_CTX_CF10_MASK	0x3
#define XSTORM_CORE_CONN_AG_CTX_CF10_SHIFT	4
#define XSTORM_CORE_CONN_AG_CTX_CF11_MASK	0x3
#define XSTORM_CORE_CONN_AG_CTX_CF11_SHIFT	6
	u8 flags5;
#define XSTORM_CORE_CONN_AG_CTX_CF12_MASK	0x3
#define XSTORM_CORE_CONN_AG_CTX_CF12_SHIFT	0
#define XSTORM_CORE_CONN_AG_CTX_CF13_MASK	0x3
#define XSTORM_CORE_CONN_AG_CTX_CF13_SHIFT	2
#define XSTORM_CORE_CONN_AG_CTX_CF14_MASK	0x3
#define XSTORM_CORE_CONN_AG_CTX_CF14_SHIFT	4
#define XSTORM_CORE_CONN_AG_CTX_CF15_MASK	0x3
#define XSTORM_CORE_CONN_AG_CTX_CF15_SHIFT	6
	u8 flags6;
#define XSTORM_CORE_CONN_AG_CTX_CONSOLID_PROD_CF_MASK	0x3
#define XSTORM_CORE_CONN_AG_CTX_CONSOLID_PROD_CF_SHIFT	0
#define XSTORM_CORE_CONN_AG_CTX_CF17_MASK		0x3
#define XSTORM_CORE_CONN_AG_CTX_CF17_SHIFT		2
#define XSTORM_CORE_CONN_AG_CTX_DQ_CF_MASK		0x3
#define XSTORM_CORE_CONN_AG_CTX_DQ_CF_SHIFT		4
#define XSTORM_CORE_CONN_AG_CTX_TERMINATE_CF_MASK	0x3
#define XSTORM_CORE_CONN_AG_CTX_TERMINATE_CF_SHIFT	6
	u8 flags7;
#define XSTORM_CORE_CONN_AG_CTX_FLUSH_Q0_MASK		0x3
#define XSTORM_CORE_CONN_AG_CTX_FLUSH_Q0_SHIFT		0
#define XSTORM_CORE_CONN_AG_CTX_RESERVED10_MASK		0x3
#define XSTORM_CORE_CONN_AG_CTX_RESERVED10_SHIFT	2
#define XSTORM_CORE_CONN_AG_CTX_SLOW_PATH_MASK		0x3
#define XSTORM_CORE_CONN_AG_CTX_SLOW_PATH_SHIFT		4
#define XSTORM_CORE_CONN_AG_CTX_CF0EN_MASK		0x1
#define XSTORM_CORE_CONN_AG_CTX_CF0EN_SHIFT		6
#define XSTORM_CORE_CONN_AG_CTX_CF1EN_MASK		0x1
#define XSTORM_CORE_CONN_AG_CTX_CF1EN_SHIFT		7
	u8 flags8;
#define XSTORM_CORE_CONN_AG_CTX_CF2EN_MASK	0x1
#define XSTORM_CORE_CONN_AG_CTX_CF2EN_SHIFT	0
#define XSTORM_CORE_CONN_AG_CTX_CF3EN_MASK	0x1
#define XSTORM_CORE_CONN_AG_CTX_CF3EN_SHIFT	1
#define XSTORM_CORE_CONN_AG_CTX_CF4EN_MASK	0x1
#define XSTORM_CORE_CONN_AG_CTX_CF4EN_SHIFT	2
#define XSTORM_CORE_CONN_AG_CTX_CF5EN_MASK	0x1
#define XSTORM_CORE_CONN_AG_CTX_CF5EN_SHIFT	3
#define XSTORM_CORE_CONN_AG_CTX_CF6EN_MASK	0x1
#define XSTORM_CORE_CONN_AG_CTX_CF6EN_SHIFT	4
#define XSTORM_CORE_CONN_AG_CTX_CF7EN_MASK	0x1
#define XSTORM_CORE_CONN_AG_CTX_CF7EN_SHIFT	5
#define XSTORM_CORE_CONN_AG_CTX_CF8EN_MASK	0x1
#define XSTORM_CORE_CONN_AG_CTX_CF8EN_SHIFT	6
#define XSTORM_CORE_CONN_AG_CTX_CF9EN_MASK	0x1
#define XSTORM_CORE_CONN_AG_CTX_CF9EN_SHIFT	7
	u8 flags9;
#define XSTORM_CORE_CONN_AG_CTX_CF10EN_MASK			0x1
#define XSTORM_CORE_CONN_AG_CTX_CF10EN_SHIFT			0
#define XSTORM_CORE_CONN_AG_CTX_CF11EN_MASK			0x1
#define XSTORM_CORE_CONN_AG_CTX_CF11EN_SHIFT			1
#define XSTORM_CORE_CONN_AG_CTX_CF12EN_MASK			0x1
#define XSTORM_CORE_CONN_AG_CTX_CF12EN_SHIFT			2
#define XSTORM_CORE_CONN_AG_CTX_CF13EN_MASK			0x1
#define XSTORM_CORE_CONN_AG_CTX_CF13EN_SHIFT			3
#define XSTORM_CORE_CONN_AG_CTX_CF14EN_MASK			0x1
#define XSTORM_CORE_CONN_AG_CTX_CF14EN_SHIFT			4
#define XSTORM_CORE_CONN_AG_CTX_CF15EN_MASK			0x1
#define XSTORM_CORE_CONN_AG_CTX_CF15EN_SHIFT			5
#define XSTORM_CORE_CONN_AG_CTX_CONSOLID_PROD_CF_EN_MASK	0x1
#define XSTORM_CORE_CONN_AG_CTX_CONSOLID_PROD_CF_EN_SHIFT	6
#define XSTORM_CORE_CONN_AG_CTX_CF17EN_MASK			0x1
#define XSTORM_CORE_CONN_AG_CTX_CF17EN_SHIFT			7
	u8 flags10;
#define XSTORM_CORE_CONN_AG_CTX_DQ_CF_EN_MASK		0x1
#define XSTORM_CORE_CONN_AG_CTX_DQ_CF_EN_SHIFT		0
#define XSTORM_CORE_CONN_AG_CTX_TERMINATE_CF_EN_MASK	0x1
#define XSTORM_CORE_CONN_AG_CTX_TERMINATE_CF_EN_SHIFT	1
#define XSTORM_CORE_CONN_AG_CTX_FLUSH_Q0_EN_MASK	0x1
#define XSTORM_CORE_CONN_AG_CTX_FLUSH_Q0_EN_SHIFT	2
#define XSTORM_CORE_CONN_AG_CTX_RESERVED11_MASK		0x1
#define XSTORM_CORE_CONN_AG_CTX_RESERVED11_SHIFT	3
#define XSTORM_CORE_CONN_AG_CTX_SLOW_PATH_EN_MASK	0x1
#define XSTORM_CORE_CONN_AG_CTX_SLOW_PATH_EN_SHIFT	4
#define XSTORM_CORE_CONN_AG_CTX_CF23EN_MASK		0x1
#define XSTORM_CORE_CONN_AG_CTX_CF23EN_SHIFT		5
#define XSTORM_CORE_CONN_AG_CTX_RESERVED12_MASK		0x1
#define XSTORM_CORE_CONN_AG_CTX_RESERVED12_SHIFT	6
#define XSTORM_CORE_CONN_AG_CTX_RESERVED13_MASK		0x1
#define XSTORM_CORE_CONN_AG_CTX_RESERVED13_SHIFT	7
	u8 flags11;
#define XSTORM_CORE_CONN_AG_CTX_RESERVED14_MASK		0x1
#define XSTORM_CORE_CONN_AG_CTX_RESERVED14_SHIFT	0
#define XSTORM_CORE_CONN_AG_CTX_RESERVED15_MASK		0x1
#define XSTORM_CORE_CONN_AG_CTX_RESERVED15_SHIFT	1
#define XSTORM_CORE_CONN_AG_CTX_TX_DEC_RULE_EN_MASK	0x1
#define XSTORM_CORE_CONN_AG_CTX_TX_DEC_RULE_EN_SHIFT	2
#define XSTORM_CORE_CONN_AG_CTX_RULE5EN_MASK		0x1
#define XSTORM_CORE_CONN_AG_CTX_RULE5EN_SHIFT		3
#define XSTORM_CORE_CONN_AG_CTX_RULE6EN_MASK		0x1
#define XSTORM_CORE_CONN_AG_CTX_RULE6EN_SHIFT		4
#define XSTORM_CORE_CONN_AG_CTX_RULE7EN_MASK		0x1
#define XSTORM_CORE_CONN_AG_CTX_RULE7EN_SHIFT		5
#define XSTORM_CORE_CONN_AG_CTX_A0_RESERVED1_MASK	0x1
#define XSTORM_CORE_CONN_AG_CTX_A0_RESERVED1_SHIFT	6
#define XSTORM_CORE_CONN_AG_CTX_RULE9EN_MASK		0x1
#define XSTORM_CORE_CONN_AG_CTX_RULE9EN_SHIFT		7
	u8 flags12;
#define XSTORM_CORE_CONN_AG_CTX_RULE10EN_MASK		0x1
#define XSTORM_CORE_CONN_AG_CTX_RULE10EN_SHIFT		0
#define XSTORM_CORE_CONN_AG_CTX_RULE11EN_MASK		0x1
#define XSTORM_CORE_CONN_AG_CTX_RULE11EN_SHIFT		1
#define XSTORM_CORE_CONN_AG_CTX_A0_RESERVED2_MASK	0x1
#define XSTORM_CORE_CONN_AG_CTX_A0_RESERVED2_SHIFT	2
#define XSTORM_CORE_CONN_AG_CTX_A0_RESERVED3_MASK	0x1
#define XSTORM_CORE_CONN_AG_CTX_A0_RESERVED3_SHIFT	3
#define XSTORM_CORE_CONN_AG_CTX_RULE14EN_MASK		0x1
#define XSTORM_CORE_CONN_AG_CTX_RULE14EN_SHIFT		4
#define XSTORM_CORE_CONN_AG_CTX_RULE15EN_MASK		0x1
#define XSTORM_CORE_CONN_AG_CTX_RULE15EN_SHIFT		5
#define XSTORM_CORE_CONN_AG_CTX_RULE16EN_MASK		0x1
#define XSTORM_CORE_CONN_AG_CTX_RULE16EN_SHIFT		6
#define XSTORM_CORE_CONN_AG_CTX_RULE17EN_MASK		0x1
#define XSTORM_CORE_CONN_AG_CTX_RULE17EN_SHIFT		7
	u8 flags13;
#define XSTORM_CORE_CONN_AG_CTX_RULE18EN_MASK		0x1
#define XSTORM_CORE_CONN_AG_CTX_RULE18EN_SHIFT		0
#define XSTORM_CORE_CONN_AG_CTX_RULE19EN_MASK		0x1
#define XSTORM_CORE_CONN_AG_CTX_RULE19EN_SHIFT		1
#define XSTORM_CORE_CONN_AG_CTX_A0_RESERVED4_MASK	0x1
#define XSTORM_CORE_CONN_AG_CTX_A0_RESERVED4_SHIFT	2
#define XSTORM_CORE_CONN_AG_CTX_A0_RESERVED5_MASK	0x1
#define XSTORM_CORE_CONN_AG_CTX_A0_RESERVED5_SHIFT	3
#define XSTORM_CORE_CONN_AG_CTX_A0_RESERVED6_MASK	0x1
#define XSTORM_CORE_CONN_AG_CTX_A0_RESERVED6_SHIFT	4
#define XSTORM_CORE_CONN_AG_CTX_A0_RESERVED7_MASK	0x1
#define XSTORM_CORE_CONN_AG_CTX_A0_RESERVED7_SHIFT	5
#define XSTORM_CORE_CONN_AG_CTX_A0_RESERVED8_MASK	0x1
#define XSTORM_CORE_CONN_AG_CTX_A0_RESERVED8_SHIFT	6
#define XSTORM_CORE_CONN_AG_CTX_A0_RESERVED9_MASK	0x1
#define XSTORM_CORE_CONN_AG_CTX_A0_RESERVED9_SHIFT	7
	u8 flags14;
#define XSTORM_CORE_CONN_AG_CTX_BIT16_MASK	0x1
#define XSTORM_CORE_CONN_AG_CTX_BIT16_SHIFT	0
#define XSTORM_CORE_CONN_AG_CTX_BIT17_MASK	0x1
#define XSTORM_CORE_CONN_AG_CTX_BIT17_SHIFT	1
#define XSTORM_CORE_CONN_AG_CTX_BIT18_MASK	0x1
#define XSTORM_CORE_CONN_AG_CTX_BIT18_SHIFT	2
#define XSTORM_CORE_CONN_AG_CTX_BIT19_MASK	0x1
#define XSTORM_CORE_CONN_AG_CTX_BIT19_SHIFT	3
#define XSTORM_CORE_CONN_AG_CTX_BIT20_MASK	0x1
#define XSTORM_CORE_CONN_AG_CTX_BIT20_SHIFT	4
#define XSTORM_CORE_CONN_AG_CTX_BIT21_MASK	0x1
#define XSTORM_CORE_CONN_AG_CTX_BIT21_SHIFT	5
#define XSTORM_CORE_CONN_AG_CTX_CF23_MASK	0x3
#define XSTORM_CORE_CONN_AG_CTX_CF23_SHIFT	6
	u8 byte2;
	__le16 physical_q0;
	__le16 consolid_prod;
	__le16 reserved16;
	__le16 tx_bd_cons;
	__le16 tx_bd_or_spq_prod;
	__le16 word5;
	__le16 conn_dpi;
	u8 byte3;
	u8 byte4;
	u8 byte5;
	u8 byte6;
	__le32 reg0;
	__le32 reg1;
	__le32 reg2;
	__le32 reg3;
	__le32 reg4;
	__le32 reg5;
	__le32 reg6;
	__le16 word7;
	__le16 word8;
	__le16 word9;
	__le16 word10;
	__le32 reg7;
	__le32 reg8;
	__le32 reg9;
	u8 byte7;
	u8 byte8;
	u8 byte9;
	u8 byte10;
	u8 byte11;
	u8 byte12;
	u8 byte13;
	u8 byte14;
	u8 byte15;
	u8 byte16;
	__le16 word11;
	__le32 reg10;
	__le32 reg11;
	__le32 reg12;
	__le32 reg13;
	__le32 reg14;
	__le32 reg15;
	__le32 reg16;
	__le32 reg17;
	__le32 reg18;
	__le32 reg19;
	__le16 word12;
	__le16 word13;
	__le16 word14;
	__le16 word15;
};

struct tstorm_core_conn_ag_ctx {
	u8 byte0;
	u8 byte1;
	u8 flags0;
#define TSTORM_CORE_CONN_AG_CTX_BIT0_MASK	0x1
#define TSTORM_CORE_CONN_AG_CTX_BIT0_SHIFT	0
#define TSTORM_CORE_CONN_AG_CTX_BIT1_MASK	0x1
#define TSTORM_CORE_CONN_AG_CTX_BIT1_SHIFT	1
#define TSTORM_CORE_CONN_AG_CTX_BIT2_MASK	0x1
#define TSTORM_CORE_CONN_AG_CTX_BIT2_SHIFT	2
#define TSTORM_CORE_CONN_AG_CTX_BIT3_MASK	0x1
#define TSTORM_CORE_CONN_AG_CTX_BIT3_SHIFT	3
#define TSTORM_CORE_CONN_AG_CTX_BIT4_MASK	0x1
#define TSTORM_CORE_CONN_AG_CTX_BIT4_SHIFT	4
#define TSTORM_CORE_CONN_AG_CTX_BIT5_MASK	0x1
#define TSTORM_CORE_CONN_AG_CTX_BIT5_SHIFT	5
#define TSTORM_CORE_CONN_AG_CTX_CF0_MASK	0x3
#define TSTORM_CORE_CONN_AG_CTX_CF0_SHIFT	6
	u8 flags1;
#define TSTORM_CORE_CONN_AG_CTX_CF1_MASK	0x3
#define TSTORM_CORE_CONN_AG_CTX_CF1_SHIFT	0
#define TSTORM_CORE_CONN_AG_CTX_CF2_MASK	0x3
#define TSTORM_CORE_CONN_AG_CTX_CF2_SHIFT	2
#define TSTORM_CORE_CONN_AG_CTX_CF3_MASK	0x3
#define TSTORM_CORE_CONN_AG_CTX_CF3_SHIFT	4
#define TSTORM_CORE_CONN_AG_CTX_CF4_MASK	0x3
#define TSTORM_CORE_CONN_AG_CTX_CF4_SHIFT	6
	u8 flags2;
#define TSTORM_CORE_CONN_AG_CTX_CF5_MASK	0x3
#define TSTORM_CORE_CONN_AG_CTX_CF5_SHIFT	0
#define TSTORM_CORE_CONN_AG_CTX_CF6_MASK	0x3
#define TSTORM_CORE_CONN_AG_CTX_CF6_SHIFT	2
#define TSTORM_CORE_CONN_AG_CTX_CF7_MASK	0x3
#define TSTORM_CORE_CONN_AG_CTX_CF7_SHIFT	4
#define TSTORM_CORE_CONN_AG_CTX_CF8_MASK	0x3
#define TSTORM_CORE_CONN_AG_CTX_CF8_SHIFT	6
	u8 flags3;
#define TSTORM_CORE_CONN_AG_CTX_CF9_MASK	0x3
#define TSTORM_CORE_CONN_AG_CTX_CF9_SHIFT	0
#define TSTORM_CORE_CONN_AG_CTX_CF10_MASK	0x3
#define TSTORM_CORE_CONN_AG_CTX_CF10_SHIFT	2
#define TSTORM_CORE_CONN_AG_CTX_CF0EN_MASK	0x1
#define TSTORM_CORE_CONN_AG_CTX_CF0EN_SHIFT	4
#define TSTORM_CORE_CONN_AG_CTX_CF1EN_MASK	0x1
#define TSTORM_CORE_CONN_AG_CTX_CF1EN_SHIFT	5
#define TSTORM_CORE_CONN_AG_CTX_CF2EN_MASK	0x1
#define TSTORM_CORE_CONN_AG_CTX_CF2EN_SHIFT	6
#define TSTORM_CORE_CONN_AG_CTX_CF3EN_MASK	0x1
#define TSTORM_CORE_CONN_AG_CTX_CF3EN_SHIFT	7
	u8 flags4;
#define TSTORM_CORE_CONN_AG_CTX_CF4EN_MASK	0x1
#define TSTORM_CORE_CONN_AG_CTX_CF4EN_SHIFT	0
#define TSTORM_CORE_CONN_AG_CTX_CF5EN_MASK	0x1
#define TSTORM_CORE_CONN_AG_CTX_CF5EN_SHIFT	1
#define TSTORM_CORE_CONN_AG_CTX_CF6EN_MASK	0x1
#define TSTORM_CORE_CONN_AG_CTX_CF6EN_SHIFT	2
#define TSTORM_CORE_CONN_AG_CTX_CF7EN_MASK	0x1
#define TSTORM_CORE_CONN_AG_CTX_CF7EN_SHIFT	3
#define TSTORM_CORE_CONN_AG_CTX_CF8EN_MASK	0x1
#define TSTORM_CORE_CONN_AG_CTX_CF8EN_SHIFT	4
#define TSTORM_CORE_CONN_AG_CTX_CF9EN_MASK	0x1
#define TSTORM_CORE_CONN_AG_CTX_CF9EN_SHIFT	5
#define TSTORM_CORE_CONN_AG_CTX_CF10EN_MASK	0x1
#define TSTORM_CORE_CONN_AG_CTX_CF10EN_SHIFT	6
#define TSTORM_CORE_CONN_AG_CTX_RULE0EN_MASK	0x1
#define TSTORM_CORE_CONN_AG_CTX_RULE0EN_SHIFT	7
	u8 flags5;
#define TSTORM_CORE_CONN_AG_CTX_RULE1EN_MASK	0x1
#define TSTORM_CORE_CONN_AG_CTX_RULE1EN_SHIFT	0
#define TSTORM_CORE_CONN_AG_CTX_RULE2EN_MASK	0x1
#define TSTORM_CORE_CONN_AG_CTX_RULE2EN_SHIFT	1
#define TSTORM_CORE_CONN_AG_CTX_RULE3EN_MASK	0x1
#define TSTORM_CORE_CONN_AG_CTX_RULE3EN_SHIFT	2
#define TSTORM_CORE_CONN_AG_CTX_RULE4EN_MASK	0x1
#define TSTORM_CORE_CONN_AG_CTX_RULE4EN_SHIFT	3
#define TSTORM_CORE_CONN_AG_CTX_RULE5EN_MASK	0x1
#define TSTORM_CORE_CONN_AG_CTX_RULE5EN_SHIFT	4
#define TSTORM_CORE_CONN_AG_CTX_RULE6EN_MASK	0x1
#define TSTORM_CORE_CONN_AG_CTX_RULE6EN_SHIFT	5
#define TSTORM_CORE_CONN_AG_CTX_RULE7EN_MASK	0x1
#define TSTORM_CORE_CONN_AG_CTX_RULE7EN_SHIFT	6
#define TSTORM_CORE_CONN_AG_CTX_RULE8EN_MASK	0x1
#define TSTORM_CORE_CONN_AG_CTX_RULE8EN_SHIFT	7
	__le32 reg0;
	__le32 reg1;
	__le32 reg2;
	__le32 reg3;
	__le32 reg4;
	__le32 reg5;
	__le32 reg6;
	__le32 reg7;
	__le32 reg8;
	u8 byte2;
	u8 byte3;
	__le16 word0;
	u8 byte4;
	u8 byte5;
	__le16 word1;
	__le16 word2;
	__le16 word3;
	__le32 reg9;
	__le32 reg10;
};

struct ustorm_core_conn_ag_ctx {
	u8 reserved;
	u8 byte1;
	u8 flags0;
#define USTORM_CORE_CONN_AG_CTX_BIT0_MASK	0x1
#define USTORM_CORE_CONN_AG_CTX_BIT0_SHIFT	0
#define USTORM_CORE_CONN_AG_CTX_BIT1_MASK	0x1
#define USTORM_CORE_CONN_AG_CTX_BIT1_SHIFT	1
#define USTORM_CORE_CONN_AG_CTX_CF0_MASK	0x3
#define USTORM_CORE_CONN_AG_CTX_CF0_SHIFT	2
#define USTORM_CORE_CONN_AG_CTX_CF1_MASK	0x3
#define USTORM_CORE_CONN_AG_CTX_CF1_SHIFT	4
#define USTORM_CORE_CONN_AG_CTX_CF2_MASK	0x3
#define USTORM_CORE_CONN_AG_CTX_CF2_SHIFT	6
	u8 flags1;
#define USTORM_CORE_CONN_AG_CTX_CF3_MASK	0x3
#define USTORM_CORE_CONN_AG_CTX_CF3_SHIFT	0
#define USTORM_CORE_CONN_AG_CTX_CF4_MASK	0x3
#define USTORM_CORE_CONN_AG_CTX_CF4_SHIFT	2
#define USTORM_CORE_CONN_AG_CTX_CF5_MASK	0x3
#define USTORM_CORE_CONN_AG_CTX_CF5_SHIFT	4
#define USTORM_CORE_CONN_AG_CTX_CF6_MASK	0x3
#define USTORM_CORE_CONN_AG_CTX_CF6_SHIFT	6
	u8 flags2;
#define USTORM_CORE_CONN_AG_CTX_CF0EN_MASK	0x1
#define USTORM_CORE_CONN_AG_CTX_CF0EN_SHIFT	0
#define USTORM_CORE_CONN_AG_CTX_CF1EN_MASK	0x1
#define USTORM_CORE_CONN_AG_CTX_CF1EN_SHIFT	1
#define USTORM_CORE_CONN_AG_CTX_CF2EN_MASK	0x1
#define USTORM_CORE_CONN_AG_CTX_CF2EN_SHIFT	2
#define USTORM_CORE_CONN_AG_CTX_CF3EN_MASK	0x1
#define USTORM_CORE_CONN_AG_CTX_CF3EN_SHIFT	3
#define USTORM_CORE_CONN_AG_CTX_CF4EN_MASK	0x1
#define USTORM_CORE_CONN_AG_CTX_CF4EN_SHIFT	4
#define USTORM_CORE_CONN_AG_CTX_CF5EN_MASK	0x1
#define USTORM_CORE_CONN_AG_CTX_CF5EN_SHIFT	5
#define USTORM_CORE_CONN_AG_CTX_CF6EN_MASK	0x1
#define USTORM_CORE_CONN_AG_CTX_CF6EN_SHIFT	6
#define USTORM_CORE_CONN_AG_CTX_RULE0EN_MASK	0x1
#define USTORM_CORE_CONN_AG_CTX_RULE0EN_SHIFT	7
	u8 flags3;
#define USTORM_CORE_CONN_AG_CTX_RULE1EN_MASK	0x1
#define USTORM_CORE_CONN_AG_CTX_RULE1EN_SHIFT	0
#define USTORM_CORE_CONN_AG_CTX_RULE2EN_MASK	0x1
#define USTORM_CORE_CONN_AG_CTX_RULE2EN_SHIFT	1
#define USTORM_CORE_CONN_AG_CTX_RULE3EN_MASK	0x1
#define USTORM_CORE_CONN_AG_CTX_RULE3EN_SHIFT	2
#define USTORM_CORE_CONN_AG_CTX_RULE4EN_MASK	0x1
#define USTORM_CORE_CONN_AG_CTX_RULE4EN_SHIFT	3
#define USTORM_CORE_CONN_AG_CTX_RULE5EN_MASK	0x1
#define USTORM_CORE_CONN_AG_CTX_RULE5EN_SHIFT	4
#define USTORM_CORE_CONN_AG_CTX_RULE6EN_MASK	0x1
#define USTORM_CORE_CONN_AG_CTX_RULE6EN_SHIFT	5
#define USTORM_CORE_CONN_AG_CTX_RULE7EN_MASK	0x1
#define USTORM_CORE_CONN_AG_CTX_RULE7EN_SHIFT	6
#define USTORM_CORE_CONN_AG_CTX_RULE8EN_MASK	0x1
#define USTORM_CORE_CONN_AG_CTX_RULE8EN_SHIFT	7
	u8 byte2;
	u8 byte3;
	__le16 word0;
	__le16 word1;
	__le32 rx_producers;
	__le32 reg1;
	__le32 reg2;
	__le32 reg3;
	__le16 word2;
	__le16 word3;
};

/* The core storm context for the Mstorm */
struct mstorm_core_conn_st_ctx {
	__le32 reserved[24];
};

/* The core storm context for the Ustorm */
struct ustorm_core_conn_st_ctx {
	__le32 reserved[4];
};

/* core connection context */
struct core_conn_context {
	struct ystorm_core_conn_st_ctx ystorm_st_context;
	struct regpair ystorm_st_padding[2];
	struct pstorm_core_conn_st_ctx pstorm_st_context;
	struct regpair pstorm_st_padding[2];
	struct xstorm_core_conn_st_ctx xstorm_st_context;
	struct xstorm_core_conn_ag_ctx xstorm_ag_context;
	struct tstorm_core_conn_ag_ctx tstorm_ag_context;
	struct ustorm_core_conn_ag_ctx ustorm_ag_context;
	struct mstorm_core_conn_st_ctx mstorm_st_context;
	struct ustorm_core_conn_st_ctx ustorm_st_context;
	struct regpair ustorm_st_padding[2];
};

struct eth_mstorm_per_pf_stat {
	struct regpair gre_discard_pkts;
	struct regpair vxlan_discard_pkts;
	struct regpair geneve_discard_pkts;
	struct regpair lb_discard_pkts;
};

struct eth_mstorm_per_queue_stat {
	struct regpair ttl0_discard;
	struct regpair packet_too_big_discard;
	struct regpair no_buff_discard;
	struct regpair not_active_discard;
	struct regpair tpa_coalesced_pkts;
	struct regpair tpa_coalesced_events;
	struct regpair tpa_aborts_num;
	struct regpair tpa_coalesced_bytes;
};

/* Ethernet TX Per PF */
struct eth_pstorm_per_pf_stat {
	struct regpair sent_lb_ucast_bytes;
	struct regpair sent_lb_mcast_bytes;
	struct regpair sent_lb_bcast_bytes;
	struct regpair sent_lb_ucast_pkts;
	struct regpair sent_lb_mcast_pkts;
	struct regpair sent_lb_bcast_pkts;
	struct regpair sent_gre_bytes;
	struct regpair sent_vxlan_bytes;
	struct regpair sent_geneve_bytes;
	struct regpair sent_gre_pkts;
	struct regpair sent_vxlan_pkts;
	struct regpair sent_geneve_pkts;
	struct regpair gre_drop_pkts;
	struct regpair vxlan_drop_pkts;
	struct regpair geneve_drop_pkts;
};

/* Ethernet TX Per Queue Stats */
struct eth_pstorm_per_queue_stat {
	struct regpair sent_ucast_bytes;
	struct regpair sent_mcast_bytes;
	struct regpair sent_bcast_bytes;
	struct regpair sent_ucast_pkts;
	struct regpair sent_mcast_pkts;
	struct regpair sent_bcast_pkts;
	struct regpair error_drop_pkts;
};

/* ETH Rx producers data */
struct eth_rx_rate_limit {
	__le16 mult;
	__le16 cnst;
	u8 add_sub_cnst;
	u8 reserved0;
	__le16 reserved1;
};

struct eth_ustorm_per_pf_stat {
	struct regpair rcv_lb_ucast_bytes;
	struct regpair rcv_lb_mcast_bytes;
	struct regpair rcv_lb_bcast_bytes;
	struct regpair rcv_lb_ucast_pkts;
	struct regpair rcv_lb_mcast_pkts;
	struct regpair rcv_lb_bcast_pkts;
	struct regpair rcv_gre_bytes;
	struct regpair rcv_vxlan_bytes;
	struct regpair rcv_geneve_bytes;
	struct regpair rcv_gre_pkts;
	struct regpair rcv_vxlan_pkts;
	struct regpair rcv_geneve_pkts;
};

struct eth_ustorm_per_queue_stat {
	struct regpair rcv_ucast_bytes;
	struct regpair rcv_mcast_bytes;
	struct regpair rcv_bcast_bytes;
	struct regpair rcv_ucast_pkts;
	struct regpair rcv_mcast_pkts;
	struct regpair rcv_bcast_pkts;
};

/* Event Ring Next Page Address */
struct event_ring_next_addr {
	struct regpair addr;
	__le32 reserved[2];
};

/* Event Ring Element */
union event_ring_element {
	struct event_ring_entry entry;
	struct event_ring_next_addr next_addr;
};

/* Major and Minor hsi Versions */
struct hsi_fp_ver_struct {
	u8 minor_ver_arr[2];
	u8 major_ver_arr[2];
};

/* Mstorm non-triggering VF zone */
struct mstorm_non_trigger_vf_zone {
	struct eth_mstorm_per_queue_stat eth_queue_stat;
	struct eth_rx_prod_data eth_rx_queue_producers[ETH_MAX_NUM_RX_QUEUES_PER_VF];
};

/* Mstorm VF zone */
struct mstorm_vf_zone {
	struct mstorm_non_trigger_vf_zone non_trigger;

};

/* personality per PF */
enum personality_type {
	BAD_PERSONALITY_TYP,
	PERSONALITY_RESERVED,
	PERSONALITY_RESERVED2,
	PERSONALITY_RDMA_AND_ETH,
	PERSONALITY_RESERVED3,
	PERSONALITY_CORE,
	PERSONALITY_ETH,
	PERSONALITY_RESERVED4,
	MAX_PERSONALITY_TYPE
};

/* tunnel configuration */
struct pf_start_tunnel_config {
	u8 set_vxlan_udp_port_flg;
	u8 set_geneve_udp_port_flg;
	u8 tx_enable_vxlan;
	u8 tx_enable_l2geneve;
	u8 tx_enable_ipgeneve;
	u8 tx_enable_l2gre;
	u8 tx_enable_ipgre;
	u8 tunnel_clss_vxlan;
	u8 tunnel_clss_l2geneve;
	u8 tunnel_clss_ipgeneve;
	u8 tunnel_clss_l2gre;
	u8 tunnel_clss_ipgre;
	__le16 vxlan_udp_port;
	__le16 geneve_udp_port;
};

/* Ramrod data for PF start ramrod */
struct pf_start_ramrod_data {
	struct regpair event_ring_pbl_addr;
	struct regpair consolid_q_pbl_addr;
	struct pf_start_tunnel_config tunnel_config;
	__le16 event_ring_sb_id;
	u8 base_vf_id;
	u8 num_vfs;
	u8 event_ring_num_pages;
	u8 event_ring_sb_index;
	u8 path_id;
	u8 warning_as_error;
	u8 dont_log_ramrods;
	u8 personality;
	__le16 log_type_mask;
	u8 mf_mode;
	u8 integ_phase;
	u8 allow_npar_tx_switching;
	u8 inner_to_outer_pri_map[8];
	u8 pri_map_valid;
	__le32 outer_tag;
	struct hsi_fp_ver_struct hsi_fp_ver;

};

struct protocol_dcb_data {
	u8 dcb_enable_flag;
	u8 dcb_priority;
	u8 dcb_tc;
	u8 reserved;
};

struct pf_update_tunnel_config {
	u8 update_rx_pf_clss;
	u8 update_tx_pf_clss;
	u8 set_vxlan_udp_port_flg;
	u8 set_geneve_udp_port_flg;
	u8 tx_enable_vxlan;
	u8 tx_enable_l2geneve;
	u8 tx_enable_ipgeneve;
	u8 tx_enable_l2gre;
	u8 tx_enable_ipgre;
	u8 tunnel_clss_vxlan;
	u8 tunnel_clss_l2geneve;
	u8 tunnel_clss_ipgeneve;
	u8 tunnel_clss_l2gre;
	u8 tunnel_clss_ipgre;
	__le16 vxlan_udp_port;
	__le16 geneve_udp_port;
	__le16 reserved[3];
};

struct pf_update_ramrod_data {
	u8 pf_id;
	u8 update_eth_dcb_data_flag;
	u8 update_fcoe_dcb_data_flag;
	u8 update_iscsi_dcb_data_flag;
	u8 update_roce_dcb_data_flag;
	u8 update_iwarp_dcb_data_flag;
	u8 update_mf_vlan_flag;
	u8 reserved;
	struct protocol_dcb_data eth_dcb_data;
	struct protocol_dcb_data fcoe_dcb_data;
	struct protocol_dcb_data iscsi_dcb_data;
	struct protocol_dcb_data roce_dcb_data;
	struct protocol_dcb_data iwarp_dcb_data;
	__le16 mf_vlan;
	__le16 reserved2;
	struct pf_update_tunnel_config tunnel_config;
};

/* Ports mode */
enum ports_mode {
	ENGX2_PORTX1,
	ENGX2_PORTX2,
	ENGX1_PORTX1,
	ENGX1_PORTX2,
	ENGX1_PORTX4,
	MAX_PORTS_MODE
};

/* use to index in hsi_fp_[major|minor]_ver_arr per protocol */
enum protocol_version_array_key {
	ETH_VER_KEY = 0,
	ROCE_VER_KEY,
	MAX_PROTOCOL_VERSION_ARRAY_KEY
};

/* Pstorm non-triggering VF zone */
struct pstorm_non_trigger_vf_zone {
	struct eth_pstorm_per_queue_stat eth_queue_stat;
	struct regpair reserved[2];
};

/* Pstorm VF zone */
struct pstorm_vf_zone {
	struct pstorm_non_trigger_vf_zone non_trigger;
	struct regpair reserved[7];
};

/* Ramrod Header of SPQE */
struct ramrod_header {
	__le32 cid;
	u8 cmd_id;
	u8 protocol_id;
	__le16 echo;
};

/* Slowpath Element (SPQE) */
struct slow_path_element {
	struct ramrod_header hdr;
	struct regpair data_ptr;
};

/* Tstorm non-triggering VF zone */
struct tstorm_non_trigger_vf_zone {
	struct regpair reserved[2];
};

struct tstorm_per_port_stat {
	struct regpair trunc_error_discard;
	struct regpair mac_error_discard;
	struct regpair mftag_filter_discard;
	struct regpair eth_mac_filter_discard;
	struct regpair reserved[5];
	struct regpair eth_irregular_pkt;
	struct regpair reserved1[2];
	struct regpair eth_gre_tunn_filter_discard;
	struct regpair eth_vxlan_tunn_filter_discard;
	struct regpair eth_geneve_tunn_filter_discard;
};

/* Tstorm VF zone */
struct tstorm_vf_zone {
	struct tstorm_non_trigger_vf_zone non_trigger;
};

/* Tunnel classification scheme */
enum tunnel_clss {
	TUNNEL_CLSS_MAC_VLAN = 0,
	TUNNEL_CLSS_MAC_VNI,
	TUNNEL_CLSS_INNER_MAC_VLAN,
	TUNNEL_CLSS_INNER_MAC_VNI,
	TUNNEL_CLSS_MAC_VLAN_DUAL_STAGE,
	MAX_TUNNEL_CLSS
};

/* Ustorm non-triggering VF zone */
struct ustorm_non_trigger_vf_zone {
	struct eth_ustorm_per_queue_stat eth_queue_stat;
	struct regpair vf_pf_msg_addr;
};

/* Ustorm triggering VF zone */
struct ustorm_trigger_vf_zone {
	u8 vf_pf_msg_valid;
	u8 reserved[7];
};

/* Ustorm VF zone */
struct ustorm_vf_zone {
	struct ustorm_non_trigger_vf_zone non_trigger;
	struct ustorm_trigger_vf_zone trigger;
};

/* VF-PF channel data */
struct vf_pf_channel_data {
	__le32 ready;
	u8 valid;
	u8 reserved0;
	__le16 reserved1;
};

/* Ramrod data for VF start ramrod */
struct vf_start_ramrod_data {
	u8 vf_id;
	u8 enable_flr_ack;
	__le16 opaque_fid;
	u8 personality;
	u8 reserved[7];
	struct hsi_fp_ver_struct hsi_fp_ver;

};

/* Ramrod data for VF start ramrod */
struct vf_stop_ramrod_data {
	u8 vf_id;
	u8 reserved0;
	__le16 reserved1;
	__le32 reserved2;
};

/* Attentions status block */
struct atten_status_block {
	__le32 atten_bits;
	__le32 atten_ack;
	__le16 reserved0;
	__le16 sb_index;
	__le32 reserved1;
};

enum command_type_bit {
	IGU_COMMAND_TYPE_NOP = 0,
	IGU_COMMAND_TYPE_SET = 1,
	MAX_COMMAND_TYPE_BIT
};

/* DMAE command */
struct dmae_cmd {
	__le32 opcode;
#define DMAE_CMD_SRC_MASK		0x1
#define DMAE_CMD_SRC_SHIFT		0
#define DMAE_CMD_DST_MASK		0x3
#define DMAE_CMD_DST_SHIFT		1
#define DMAE_CMD_C_DST_MASK		0x1
#define DMAE_CMD_C_DST_SHIFT		3
#define DMAE_CMD_CRC_RESET_MASK		0x1
#define DMAE_CMD_CRC_RESET_SHIFT	4
#define DMAE_CMD_SRC_ADDR_RESET_MASK	0x1
#define DMAE_CMD_SRC_ADDR_RESET_SHIFT	5
#define DMAE_CMD_DST_ADDR_RESET_MASK	0x1
#define DMAE_CMD_DST_ADDR_RESET_SHIFT	6
#define DMAE_CMD_COMP_FUNC_MASK		0x1
#define DMAE_CMD_COMP_FUNC_SHIFT	7
#define DMAE_CMD_COMP_WORD_EN_MASK	0x1
#define DMAE_CMD_COMP_WORD_EN_SHIFT	8
#define DMAE_CMD_COMP_CRC_EN_MASK	0x1
#define DMAE_CMD_COMP_CRC_EN_SHIFT	9
#define DMAE_CMD_COMP_CRC_OFFSET_MASK	0x7
#define DMAE_CMD_COMP_CRC_OFFSET_SHIFT 10
#define DMAE_CMD_RESERVED1_MASK		0x1
#define DMAE_CMD_RESERVED1_SHIFT	13
#define DMAE_CMD_ENDIANITY_MODE_MASK	0x3
#define DMAE_CMD_ENDIANITY_MODE_SHIFT	14
#define DMAE_CMD_ERR_HANDLING_MASK	0x3
#define DMAE_CMD_ERR_HANDLING_SHIFT	16
#define DMAE_CMD_PORT_ID_MASK		0x3
#define DMAE_CMD_PORT_ID_SHIFT		18
#define DMAE_CMD_SRC_PF_ID_MASK		0xF
#define DMAE_CMD_SRC_PF_ID_SHIFT	20
#define DMAE_CMD_DST_PF_ID_MASK		0xF
#define DMAE_CMD_DST_PF_ID_SHIFT	24
#define DMAE_CMD_SRC_VF_ID_VALID_MASK	0x1
#define DMAE_CMD_SRC_VF_ID_VALID_SHIFT 28
#define DMAE_CMD_DST_VF_ID_VALID_MASK	0x1
#define DMAE_CMD_DST_VF_ID_VALID_SHIFT 29
#define DMAE_CMD_RESERVED2_MASK		0x3
#define DMAE_CMD_RESERVED2_SHIFT	30
	__le32 src_addr_lo;
	__le32 src_addr_hi;
	__le32 dst_addr_lo;
	__le32 dst_addr_hi;
	__le16 length_dw;
	__le16 opcode_b;
#define DMAE_CMD_SRC_VF_ID_MASK		0xFF
#define DMAE_CMD_SRC_VF_ID_SHIFT	0
#define DMAE_CMD_DST_VF_ID_MASK		0xFF
#define DMAE_CMD_DST_VF_ID_SHIFT	8
	__le32 comp_addr_lo;
	__le32 comp_addr_hi;
	__le32 comp_val;
	__le32 crc32;
	__le32 crc_32_c;
	__le16 crc16;
	__le16 crc16_c;
	__le16 crc10;
	__le16 reserved;
	__le16 xsum16;
	__le16 xsum8;
};

enum dmae_cmd_comp_crc_en_enum {
	dmae_cmd_comp_crc_disabled,
	dmae_cmd_comp_crc_enabled,
	MAX_DMAE_CMD_COMP_CRC_EN_ENUM
};

enum dmae_cmd_comp_func_enum {
	dmae_cmd_comp_func_to_src,
	dmae_cmd_comp_func_to_dst,
	MAX_DMAE_CMD_COMP_FUNC_ENUM
};

enum dmae_cmd_comp_word_en_enum {
	dmae_cmd_comp_word_disabled,
	dmae_cmd_comp_word_enabled,
	MAX_DMAE_CMD_COMP_WORD_EN_ENUM
};

enum dmae_cmd_c_dst_enum {
	dmae_cmd_c_dst_pcie,
	dmae_cmd_c_dst_grc,
	MAX_DMAE_CMD_C_DST_ENUM
};

enum dmae_cmd_dst_enum {
	dmae_cmd_dst_none_0,
	dmae_cmd_dst_pcie,
	dmae_cmd_dst_grc,
	dmae_cmd_dst_none_3,
	MAX_DMAE_CMD_DST_ENUM
};

enum dmae_cmd_error_handling_enum {
	dmae_cmd_error_handling_send_regular_comp,
	dmae_cmd_error_handling_send_comp_with_err,
	dmae_cmd_error_handling_dont_send_comp,
	MAX_DMAE_CMD_ERROR_HANDLING_ENUM
};

enum dmae_cmd_src_enum {
	dmae_cmd_src_pcie,
	dmae_cmd_src_grc,
	MAX_DMAE_CMD_SRC_ENUM
};

/* IGU cleanup command */
struct igu_cleanup {
	__le32 sb_id_and_flags;
#define IGU_CLEANUP_RESERVED0_MASK	0x7FFFFFF
#define IGU_CLEANUP_RESERVED0_SHIFT	0
#define IGU_CLEANUP_CLEANUP_SET_MASK	0x1
#define IGU_CLEANUP_CLEANUP_SET_SHIFT	27
#define IGU_CLEANUP_CLEANUP_TYPE_MASK	0x7
#define IGU_CLEANUP_CLEANUP_TYPE_SHIFT	28
#define IGU_CLEANUP_COMMAND_TYPE_MASK	0x1
#define IGU_CLEANUP_COMMAND_TYPE_SHIFT	31
	__le32 reserved1;
};

/* IGU firmware driver command */
union igu_command {
	struct igu_prod_cons_update prod_cons_update;
	struct igu_cleanup cleanup;
};

/* IGU firmware driver command */
struct igu_command_reg_ctrl {
	__le16 opaque_fid;
	__le16 igu_command_reg_ctrl_fields;
#define IGU_COMMAND_REG_CTRL_PXP_BAR_ADDR_MASK	0xFFF
#define IGU_COMMAND_REG_CTRL_PXP_BAR_ADDR_SHIFT	0
#define IGU_COMMAND_REG_CTRL_RESERVED_MASK	0x7
#define IGU_COMMAND_REG_CTRL_RESERVED_SHIFT	12
#define IGU_COMMAND_REG_CTRL_COMMAND_TYPE_MASK	0x1
#define IGU_COMMAND_REG_CTRL_COMMAND_TYPE_SHIFT	15
};

/* IGU mapping line structure */
struct igu_mapping_line {
	__le32 igu_mapping_line_fields;
#define IGU_MAPPING_LINE_VALID_MASK		0x1
#define IGU_MAPPING_LINE_VALID_SHIFT		0
#define IGU_MAPPING_LINE_VECTOR_NUMBER_MASK	0xFF
#define IGU_MAPPING_LINE_VECTOR_NUMBER_SHIFT	1
#define IGU_MAPPING_LINE_FUNCTION_NUMBER_MASK	0xFF
#define IGU_MAPPING_LINE_FUNCTION_NUMBER_SHIFT	9
#define IGU_MAPPING_LINE_PF_VALID_MASK		0x1
#define IGU_MAPPING_LINE_PF_VALID_SHIFT		17
#define IGU_MAPPING_LINE_IPS_GROUP_MASK		0x3F
#define IGU_MAPPING_LINE_IPS_GROUP_SHIFT	18
#define IGU_MAPPING_LINE_RESERVED_MASK		0xFF
#define IGU_MAPPING_LINE_RESERVED_SHIFT		24
};

/* IGU MSIX line structure */
struct igu_msix_vector {
	struct regpair address;
	__le32 data;
	__le32 msix_vector_fields;
#define IGU_MSIX_VECTOR_MASK_BIT_MASK		0x1
#define IGU_MSIX_VECTOR_MASK_BIT_SHIFT		0
#define IGU_MSIX_VECTOR_RESERVED0_MASK		0x7FFF
#define IGU_MSIX_VECTOR_RESERVED0_SHIFT		1
#define IGU_MSIX_VECTOR_STEERING_TAG_MASK	0xFF
#define IGU_MSIX_VECTOR_STEERING_TAG_SHIFT	16
#define IGU_MSIX_VECTOR_RESERVED1_MASK		0xFF
#define IGU_MSIX_VECTOR_RESERVED1_SHIFT		24
};

struct mstorm_core_conn_ag_ctx {
	u8 byte0;
	u8 byte1;
	u8 flags0;
#define MSTORM_CORE_CONN_AG_CTX_BIT0_MASK	0x1
#define MSTORM_CORE_CONN_AG_CTX_BIT0_SHIFT	0
#define MSTORM_CORE_CONN_AG_CTX_BIT1_MASK	0x1
#define MSTORM_CORE_CONN_AG_CTX_BIT1_SHIFT	1
#define MSTORM_CORE_CONN_AG_CTX_CF0_MASK	0x3
#define MSTORM_CORE_CONN_AG_CTX_CF0_SHIFT	2
#define MSTORM_CORE_CONN_AG_CTX_CF1_MASK	0x3
#define MSTORM_CORE_CONN_AG_CTX_CF1_SHIFT	4
#define MSTORM_CORE_CONN_AG_CTX_CF2_MASK	0x3
#define MSTORM_CORE_CONN_AG_CTX_CF2_SHIFT	6
	u8 flags1;
#define MSTORM_CORE_CONN_AG_CTX_CF0EN_MASK	0x1
#define MSTORM_CORE_CONN_AG_CTX_CF0EN_SHIFT	0
#define MSTORM_CORE_CONN_AG_CTX_CF1EN_MASK	0x1
#define MSTORM_CORE_CONN_AG_CTX_CF1EN_SHIFT	1
#define MSTORM_CORE_CONN_AG_CTX_CF2EN_MASK	0x1
#define MSTORM_CORE_CONN_AG_CTX_CF2EN_SHIFT	2
#define MSTORM_CORE_CONN_AG_CTX_RULE0EN_MASK	0x1
#define MSTORM_CORE_CONN_AG_CTX_RULE0EN_SHIFT	3
#define MSTORM_CORE_CONN_AG_CTX_RULE1EN_MASK	0x1
#define MSTORM_CORE_CONN_AG_CTX_RULE1EN_SHIFT	4
#define MSTORM_CORE_CONN_AG_CTX_RULE2EN_MASK	0x1
#define MSTORM_CORE_CONN_AG_CTX_RULE2EN_SHIFT	5
#define MSTORM_CORE_CONN_AG_CTX_RULE3EN_MASK	0x1
#define MSTORM_CORE_CONN_AG_CTX_RULE3EN_SHIFT	6
#define MSTORM_CORE_CONN_AG_CTX_RULE4EN_MASK	0x1
#define MSTORM_CORE_CONN_AG_CTX_RULE4EN_SHIFT	7
	__le16 word0;
	__le16 word1;
	__le32 reg0;
	__le32 reg1;
};

/* per encapsulation type enabling flags */
struct prs_reg_encapsulation_type_en {
	u8 flags;
#define PRS_REG_ENCAPSULATION_TYPE_EN_ETH_OVER_GRE_ENABLE_MASK		0x1
#define PRS_REG_ENCAPSULATION_TYPE_EN_ETH_OVER_GRE_ENABLE_SHIFT		0
#define PRS_REG_ENCAPSULATION_TYPE_EN_IP_OVER_GRE_ENABLE_MASK		0x1
#define PRS_REG_ENCAPSULATION_TYPE_EN_IP_OVER_GRE_ENABLE_SHIFT		1
#define PRS_REG_ENCAPSULATION_TYPE_EN_VXLAN_ENABLE_MASK			0x1
#define PRS_REG_ENCAPSULATION_TYPE_EN_VXLAN_ENABLE_SHIFT		2
#define PRS_REG_ENCAPSULATION_TYPE_EN_T_TAG_ENABLE_MASK			0x1
#define PRS_REG_ENCAPSULATION_TYPE_EN_T_TAG_ENABLE_SHIFT		3
#define PRS_REG_ENCAPSULATION_TYPE_EN_ETH_OVER_GENEVE_ENABLE_MASK	0x1
#define PRS_REG_ENCAPSULATION_TYPE_EN_ETH_OVER_GENEVE_ENABLE_SHIFT	4
#define PRS_REG_ENCAPSULATION_TYPE_EN_IP_OVER_GENEVE_ENABLE_MASK	0x1
#define PRS_REG_ENCAPSULATION_TYPE_EN_IP_OVER_GENEVE_ENABLE_SHIFT	5
#define PRS_REG_ENCAPSULATION_TYPE_EN_RESERVED_MASK			0x3
#define PRS_REG_ENCAPSULATION_TYPE_EN_RESERVED_SHIFT			6
};

enum pxp_tph_st_hint {
	TPH_ST_HINT_BIDIR,
	TPH_ST_HINT_REQUESTER,
	TPH_ST_HINT_TARGET,
	TPH_ST_HINT_TARGET_PRIO,
	MAX_PXP_TPH_ST_HINT
};

/* QM hardware structure of enable bypass credit mask */
struct qm_rf_bypass_mask {
	u8 flags;
#define QM_RF_BYPASS_MASK_LINEVOQ_MASK		0x1
#define QM_RF_BYPASS_MASK_LINEVOQ_SHIFT		0
#define QM_RF_BYPASS_MASK_RESERVED0_MASK	0x1
#define QM_RF_BYPASS_MASK_RESERVED0_SHIFT	1
#define QM_RF_BYPASS_MASK_PFWFQ_MASK		0x1
#define QM_RF_BYPASS_MASK_PFWFQ_SHIFT		2
#define QM_RF_BYPASS_MASK_VPWFQ_MASK		0x1
#define QM_RF_BYPASS_MASK_VPWFQ_SHIFT		3
#define QM_RF_BYPASS_MASK_PFRL_MASK		0x1
#define QM_RF_BYPASS_MASK_PFRL_SHIFT		4
#define QM_RF_BYPASS_MASK_VPQCNRL_MASK		0x1
#define QM_RF_BYPASS_MASK_VPQCNRL_SHIFT		5
#define QM_RF_BYPASS_MASK_FWPAUSE_MASK		0x1
#define QM_RF_BYPASS_MASK_FWPAUSE_SHIFT		6
#define QM_RF_BYPASS_MASK_RESERVED1_MASK	0x1
#define QM_RF_BYPASS_MASK_RESERVED1_SHIFT	7
};

/* QM hardware structure of opportunistic credit mask */
struct qm_rf_opportunistic_mask {
	__le16 flags;
#define QM_RF_OPPORTUNISTIC_MASK_LINEVOQ_MASK		0x1
#define QM_RF_OPPORTUNISTIC_MASK_LINEVOQ_SHIFT		0
#define QM_RF_OPPORTUNISTIC_MASK_BYTEVOQ_MASK		0x1
#define QM_RF_OPPORTUNISTIC_MASK_BYTEVOQ_SHIFT		1
#define QM_RF_OPPORTUNISTIC_MASK_PFWFQ_MASK		0x1
#define QM_RF_OPPORTUNISTIC_MASK_PFWFQ_SHIFT		2
#define QM_RF_OPPORTUNISTIC_MASK_VPWFQ_MASK		0x1
#define QM_RF_OPPORTUNISTIC_MASK_VPWFQ_SHIFT		3
#define QM_RF_OPPORTUNISTIC_MASK_PFRL_MASK		0x1
#define QM_RF_OPPORTUNISTIC_MASK_PFRL_SHIFT		4
#define QM_RF_OPPORTUNISTIC_MASK_VPQCNRL_MASK		0x1
#define QM_RF_OPPORTUNISTIC_MASK_VPQCNRL_SHIFT		5
#define QM_RF_OPPORTUNISTIC_MASK_FWPAUSE_MASK		0x1
#define QM_RF_OPPORTUNISTIC_MASK_FWPAUSE_SHIFT		6
#define QM_RF_OPPORTUNISTIC_MASK_RESERVED0_MASK		0x1
#define QM_RF_OPPORTUNISTIC_MASK_RESERVED0_SHIFT	7
#define QM_RF_OPPORTUNISTIC_MASK_QUEUEEMPTY_MASK	0x1
#define QM_RF_OPPORTUNISTIC_MASK_QUEUEEMPTY_SHIFT	8
#define QM_RF_OPPORTUNISTIC_MASK_RESERVED1_MASK		0x7F
#define QM_RF_OPPORTUNISTIC_MASK_RESERVED1_SHIFT	9
};

/* QM hardware structure of QM map memory */
struct qm_rf_pq_map {
	__le32 reg;
#define QM_RF_PQ_MAP_PQ_VALID_MASK		0x1
#define QM_RF_PQ_MAP_PQ_VALID_SHIFT		0
#define QM_RF_PQ_MAP_RL_ID_MASK			0xFF
#define QM_RF_PQ_MAP_RL_ID_SHIFT		1
#define QM_RF_PQ_MAP_VP_PQ_ID_MASK		0x1FF
#define QM_RF_PQ_MAP_VP_PQ_ID_SHIFT		9
#define QM_RF_PQ_MAP_VOQ_MASK			0x1F
#define QM_RF_PQ_MAP_VOQ_SHIFT			18
#define QM_RF_PQ_MAP_WRR_WEIGHT_GROUP_MASK	0x3
#define QM_RF_PQ_MAP_WRR_WEIGHT_GROUP_SHIFT	23
#define QM_RF_PQ_MAP_RL_VALID_MASK		0x1
#define QM_RF_PQ_MAP_RL_VALID_SHIFT		25
#define QM_RF_PQ_MAP_RESERVED_MASK		0x3F
#define QM_RF_PQ_MAP_RESERVED_SHIFT		26
};

/* Completion params for aggregated interrupt completion */
struct sdm_agg_int_comp_params {
	__le16 params;
#define SDM_AGG_INT_COMP_PARAMS_AGG_INT_INDEX_MASK	0x3F
#define SDM_AGG_INT_COMP_PARAMS_AGG_INT_INDEX_SHIFT	0
#define SDM_AGG_INT_COMP_PARAMS_AGG_VECTOR_ENABLE_MASK	0x1
#define SDM_AGG_INT_COMP_PARAMS_AGG_VECTOR_ENABLE_SHIFT	6
#define SDM_AGG_INT_COMP_PARAMS_AGG_VECTOR_BIT_MASK	0x1FF
#define SDM_AGG_INT_COMP_PARAMS_AGG_VECTOR_BIT_SHIFT	7
};

/* SDM operation gen command (generate aggregative interrupt) */
struct sdm_op_gen {
	__le32 command;
#define SDM_OP_GEN_COMP_PARAM_MASK	0xFFFF
#define SDM_OP_GEN_COMP_PARAM_SHIFT	0
#define SDM_OP_GEN_COMP_TYPE_MASK	0xF
#define SDM_OP_GEN_COMP_TYPE_SHIFT	16
#define SDM_OP_GEN_RESERVED_MASK	0xFFF
#define SDM_OP_GEN_RESERVED_SHIFT	20
};

struct ystorm_core_conn_ag_ctx {
	u8 byte0;
	u8 byte1;
	u8 flags0;
#define YSTORM_CORE_CONN_AG_CTX_BIT0_MASK	0x1
#define YSTORM_CORE_CONN_AG_CTX_BIT0_SHIFT	0
#define YSTORM_CORE_CONN_AG_CTX_BIT1_MASK	0x1
#define YSTORM_CORE_CONN_AG_CTX_BIT1_SHIFT	1
#define YSTORM_CORE_CONN_AG_CTX_CF0_MASK	0x3
#define YSTORM_CORE_CONN_AG_CTX_CF0_SHIFT	2
#define YSTORM_CORE_CONN_AG_CTX_CF1_MASK	0x3
#define YSTORM_CORE_CONN_AG_CTX_CF1_SHIFT	4
#define YSTORM_CORE_CONN_AG_CTX_CF2_MASK	0x3
#define YSTORM_CORE_CONN_AG_CTX_CF2_SHIFT	6
	u8 flags1;
#define YSTORM_CORE_CONN_AG_CTX_CF0EN_MASK	0x1
#define YSTORM_CORE_CONN_AG_CTX_CF0EN_SHIFT	0
#define YSTORM_CORE_CONN_AG_CTX_CF1EN_MASK	0x1
#define YSTORM_CORE_CONN_AG_CTX_CF1EN_SHIFT	1
#define YSTORM_CORE_CONN_AG_CTX_CF2EN_MASK	0x1
#define YSTORM_CORE_CONN_AG_CTX_CF2EN_SHIFT	2
#define YSTORM_CORE_CONN_AG_CTX_RULE0EN_MASK	0x1
#define YSTORM_CORE_CONN_AG_CTX_RULE0EN_SHIFT	3
#define YSTORM_CORE_CONN_AG_CTX_RULE1EN_MASK	0x1
#define YSTORM_CORE_CONN_AG_CTX_RULE1EN_SHIFT	4
#define YSTORM_CORE_CONN_AG_CTX_RULE2EN_MASK	0x1
#define YSTORM_CORE_CONN_AG_CTX_RULE2EN_SHIFT	5
#define YSTORM_CORE_CONN_AG_CTX_RULE3EN_MASK	0x1
#define YSTORM_CORE_CONN_AG_CTX_RULE3EN_SHIFT	6
#define YSTORM_CORE_CONN_AG_CTX_RULE4EN_MASK	0x1
#define YSTORM_CORE_CONN_AG_CTX_RULE4EN_SHIFT	7
	u8 byte2;
	u8 byte3;
	__le16 word0;
	__le32 reg0;
	__le32 reg1;
	__le16 word1;
	__le16 word2;
	__le16 word3;
	__le16 word4;
	__le32 reg2;
	__le32 reg3;
};

/****************************************/
/* Debug Tools HSI constants and macros */
/****************************************/

enum block_addr {
	GRCBASE_GRC = 0x50000,
	GRCBASE_MISCS = 0x9000,
	GRCBASE_MISC = 0x8000,
	GRCBASE_DBU = 0xa000,
	GRCBASE_PGLUE_B = 0x2a8000,
	GRCBASE_CNIG = 0x218000,
	GRCBASE_CPMU = 0x30000,
	GRCBASE_NCSI = 0x40000,
	GRCBASE_OPTE = 0x53000,
	GRCBASE_BMB = 0x540000,
	GRCBASE_PCIE = 0x54000,
	GRCBASE_MCP = 0xe00000,
	GRCBASE_MCP2 = 0x52000,
	GRCBASE_PSWHST = 0x2a0000,
	GRCBASE_PSWHST2 = 0x29e000,
	GRCBASE_PSWRD = 0x29c000,
	GRCBASE_PSWRD2 = 0x29d000,
	GRCBASE_PSWWR = 0x29a000,
	GRCBASE_PSWWR2 = 0x29b000,
	GRCBASE_PSWRQ = 0x280000,
	GRCBASE_PSWRQ2 = 0x240000,
	GRCBASE_PGLCS = 0x0,
	GRCBASE_DMAE = 0xc000,
	GRCBASE_PTU = 0x560000,
	GRCBASE_TCM = 0x1180000,
	GRCBASE_MCM = 0x1200000,
	GRCBASE_UCM = 0x1280000,
	GRCBASE_XCM = 0x1000000,
	GRCBASE_YCM = 0x1080000,
	GRCBASE_PCM = 0x1100000,
	GRCBASE_QM = 0x2f0000,
	GRCBASE_TM = 0x2c0000,
	GRCBASE_DORQ = 0x100000,
	GRCBASE_BRB = 0x340000,
	GRCBASE_SRC = 0x238000,
	GRCBASE_PRS = 0x1f0000,
	GRCBASE_TSDM = 0xfb0000,
	GRCBASE_MSDM = 0xfc0000,
	GRCBASE_USDM = 0xfd0000,
	GRCBASE_XSDM = 0xf80000,
	GRCBASE_YSDM = 0xf90000,
	GRCBASE_PSDM = 0xfa0000,
	GRCBASE_TSEM = 0x1700000,
	GRCBASE_MSEM = 0x1800000,
	GRCBASE_USEM = 0x1900000,
	GRCBASE_XSEM = 0x1400000,
	GRCBASE_YSEM = 0x1500000,
	GRCBASE_PSEM = 0x1600000,
	GRCBASE_RSS = 0x238800,
	GRCBASE_TMLD = 0x4d0000,
	GRCBASE_MULD = 0x4e0000,
	GRCBASE_YULD = 0x4c8000,
	GRCBASE_XYLD = 0x4c0000,
	GRCBASE_PRM = 0x230000,
	GRCBASE_PBF_PB1 = 0xda0000,
	GRCBASE_PBF_PB2 = 0xda4000,
	GRCBASE_RPB = 0x23c000,
	GRCBASE_BTB = 0xdb0000,
	GRCBASE_PBF = 0xd80000,
	GRCBASE_RDIF = 0x300000,
	GRCBASE_TDIF = 0x310000,
	GRCBASE_CDU = 0x580000,
	GRCBASE_CCFC = 0x2e0000,
	GRCBASE_TCFC = 0x2d0000,
	GRCBASE_IGU = 0x180000,
	GRCBASE_CAU = 0x1c0000,
	GRCBASE_UMAC = 0x51000,
	GRCBASE_XMAC = 0x210000,
	GRCBASE_DBG = 0x10000,
	GRCBASE_NIG = 0x500000,
	GRCBASE_WOL = 0x600000,
	GRCBASE_BMBN = 0x610000,
	GRCBASE_IPC = 0x20000,
	GRCBASE_NWM = 0x800000,
	GRCBASE_NWS = 0x700000,
	GRCBASE_MS = 0x6a0000,
	GRCBASE_PHY_PCIE = 0x620000,
	GRCBASE_LED = 0x6b8000,
	GRCBASE_MISC_AEU = 0x8000,
	GRCBASE_BAR0_MAP = 0x1c00000,
	MAX_BLOCK_ADDR
};

enum block_id {
	BLOCK_GRC,
	BLOCK_MISCS,
	BLOCK_MISC,
	BLOCK_DBU,
	BLOCK_PGLUE_B,
	BLOCK_CNIG,
	BLOCK_CPMU,
	BLOCK_NCSI,
	BLOCK_OPTE,
	BLOCK_BMB,
	BLOCK_PCIE,
	BLOCK_MCP,
	BLOCK_MCP2,
	BLOCK_PSWHST,
	BLOCK_PSWHST2,
	BLOCK_PSWRD,
	BLOCK_PSWRD2,
	BLOCK_PSWWR,
	BLOCK_PSWWR2,
	BLOCK_PSWRQ,
	BLOCK_PSWRQ2,
	BLOCK_PGLCS,
	BLOCK_DMAE,
	BLOCK_PTU,
	BLOCK_TCM,
	BLOCK_MCM,
	BLOCK_UCM,
	BLOCK_XCM,
	BLOCK_YCM,
	BLOCK_PCM,
	BLOCK_QM,
	BLOCK_TM,
	BLOCK_DORQ,
	BLOCK_BRB,
	BLOCK_SRC,
	BLOCK_PRS,
	BLOCK_TSDM,
	BLOCK_MSDM,
	BLOCK_USDM,
	BLOCK_XSDM,
	BLOCK_YSDM,
	BLOCK_PSDM,
	BLOCK_TSEM,
	BLOCK_MSEM,
	BLOCK_USEM,
	BLOCK_XSEM,
	BLOCK_YSEM,
	BLOCK_PSEM,
	BLOCK_RSS,
	BLOCK_TMLD,
	BLOCK_MULD,
	BLOCK_YULD,
	BLOCK_XYLD,
	BLOCK_PRM,
	BLOCK_PBF_PB1,
	BLOCK_PBF_PB2,
	BLOCK_RPB,
	BLOCK_BTB,
	BLOCK_PBF,
	BLOCK_RDIF,
	BLOCK_TDIF,
	BLOCK_CDU,
	BLOCK_CCFC,
	BLOCK_TCFC,
	BLOCK_IGU,
	BLOCK_CAU,
	BLOCK_UMAC,
	BLOCK_XMAC,
	BLOCK_DBG,
	BLOCK_NIG,
	BLOCK_WOL,
	BLOCK_BMBN,
	BLOCK_IPC,
	BLOCK_NWM,
	BLOCK_NWS,
	BLOCK_MS,
	BLOCK_PHY_PCIE,
	BLOCK_LED,
	BLOCK_MISC_AEU,
	BLOCK_BAR0_MAP,
	MAX_BLOCK_ID
};

/* binary debug buffer types */
enum bin_dbg_buffer_type {
	BIN_BUF_DBG_MODE_TREE,
	BIN_BUF_DBG_DUMP_REG,
	BIN_BUF_DBG_DUMP_MEM,
	BIN_BUF_DBG_IDLE_CHK_REGS,
	BIN_BUF_DBG_IDLE_CHK_IMMS,
	BIN_BUF_DBG_IDLE_CHK_RULES,
	BIN_BUF_DBG_IDLE_CHK_PARSING_DATA,
	BIN_BUF_DBG_ATTN_BLOCKS,
	BIN_BUF_DBG_ATTN_REGS,
	BIN_BUF_DBG_ATTN_INDEXES,
	BIN_BUF_DBG_ATTN_NAME_OFFSETS,
	BIN_BUF_DBG_PARSING_STRINGS,
	MAX_BIN_DBG_BUFFER_TYPE
};

/* Chip IDs */
enum chip_ids {
	CHIP_RESERVED,
	CHIP_BB_B0,
	CHIP_RESERVED2,
	MAX_CHIP_IDS
};

/* Attention bit mapping */
struct dbg_attn_bit_mapping {
	__le16 data;
#define DBG_ATTN_BIT_MAPPING_VAL_MASK			0x7FFF
#define DBG_ATTN_BIT_MAPPING_VAL_SHIFT			0
#define DBG_ATTN_BIT_MAPPING_IS_UNUSED_BIT_CNT_MASK	0x1
#define DBG_ATTN_BIT_MAPPING_IS_UNUSED_BIT_CNT_SHIFT	15
};

/* Attention block per-type data */
struct dbg_attn_block_type_data {
	__le16 names_offset;
	__le16 reserved1;
	u8 num_regs;
	u8 reserved2;
	__le16 regs_offset;
};

/* Block attentions */
struct dbg_attn_block {
	struct dbg_attn_block_type_data per_type_data[2];
};

/* Attention register result */
struct dbg_attn_reg_result {
	__le32 data;
#define DBG_ATTN_REG_RESULT_STS_ADDRESS_MASK	0xFFFFFF
#define DBG_ATTN_REG_RESULT_STS_ADDRESS_SHIFT	0
#define DBG_ATTN_REG_RESULT_NUM_ATTN_IDX_MASK	0xFF
#define DBG_ATTN_REG_RESULT_NUM_ATTN_IDX_SHIFT	24
	__le16 attn_idx_offset;
	__le16 reserved;
	__le32 sts_val;
	__le32 mask_val;
};

/* Attention block result */
struct dbg_attn_block_result {
	u8 block_id;
	u8 data;
#define DBG_ATTN_BLOCK_RESULT_ATTN_TYPE_MASK	0x3
#define DBG_ATTN_BLOCK_RESULT_ATTN_TYPE_SHIFT	0
#define DBG_ATTN_BLOCK_RESULT_NUM_REGS_MASK	0x3F
#define DBG_ATTN_BLOCK_RESULT_NUM_REGS_SHIFT	2
	__le16 names_offset;
	struct dbg_attn_reg_result reg_results[15];
};

/* mode header */
struct dbg_mode_hdr {
	__le16 data;
#define DBG_MODE_HDR_EVAL_MODE_MASK		0x1
#define DBG_MODE_HDR_EVAL_MODE_SHIFT		0
#define DBG_MODE_HDR_MODES_BUF_OFFSET_MASK	0x7FFF
#define DBG_MODE_HDR_MODES_BUF_OFFSET_SHIFT	1
};

/* Attention register */
struct dbg_attn_reg {
	struct dbg_mode_hdr mode;
	__le16 attn_idx_offset;
	__le32 data;
#define DBG_ATTN_REG_STS_ADDRESS_MASK	0xFFFFFF
#define DBG_ATTN_REG_STS_ADDRESS_SHIFT	0
#define DBG_ATTN_REG_NUM_ATTN_IDX_MASK	0xFF
#define DBG_ATTN_REG_NUM_ATTN_IDX_SHIFT	24
	__le32 sts_clr_address;
	__le32 mask_address;
};

/* attention types */
enum dbg_attn_type {
	ATTN_TYPE_INTERRUPT,
	ATTN_TYPE_PARITY,
	MAX_DBG_ATTN_TYPE
};

/* Debug status codes */
enum dbg_status {
	DBG_STATUS_OK,
	DBG_STATUS_APP_VERSION_NOT_SET,
	DBG_STATUS_UNSUPPORTED_APP_VERSION,
	DBG_STATUS_DBG_BLOCK_NOT_RESET,
	DBG_STATUS_INVALID_ARGS,
	DBG_STATUS_OUTPUT_ALREADY_SET,
	DBG_STATUS_INVALID_PCI_BUF_SIZE,
	DBG_STATUS_PCI_BUF_ALLOC_FAILED,
	DBG_STATUS_PCI_BUF_NOT_ALLOCATED,
	DBG_STATUS_TOO_MANY_INPUTS,
	DBG_STATUS_INPUT_OVERLAP,
	DBG_STATUS_HW_ONLY_RECORDING,
	DBG_STATUS_STORM_ALREADY_ENABLED,
	DBG_STATUS_STORM_NOT_ENABLED,
	DBG_STATUS_BLOCK_ALREADY_ENABLED,
	DBG_STATUS_BLOCK_NOT_ENABLED,
	DBG_STATUS_NO_INPUT_ENABLED,
	DBG_STATUS_NO_FILTER_TRIGGER_64B,
	DBG_STATUS_FILTER_ALREADY_ENABLED,
	DBG_STATUS_TRIGGER_ALREADY_ENABLED,
	DBG_STATUS_TRIGGER_NOT_ENABLED,
	DBG_STATUS_CANT_ADD_CONSTRAINT,
	DBG_STATUS_TOO_MANY_TRIGGER_STATES,
	DBG_STATUS_TOO_MANY_CONSTRAINTS,
	DBG_STATUS_RECORDING_NOT_STARTED,
	DBG_STATUS_DATA_DIDNT_TRIGGER,
	DBG_STATUS_NO_DATA_RECORDED,
	DBG_STATUS_DUMP_BUF_TOO_SMALL,
	DBG_STATUS_DUMP_NOT_CHUNK_ALIGNED,
	DBG_STATUS_UNKNOWN_CHIP,
	DBG_STATUS_VIRT_MEM_ALLOC_FAILED,
	DBG_STATUS_BLOCK_IN_RESET,
	DBG_STATUS_INVALID_TRACE_SIGNATURE,
	DBG_STATUS_INVALID_NVRAM_BUNDLE,
	DBG_STATUS_NVRAM_GET_IMAGE_FAILED,
	DBG_STATUS_NON_ALIGNED_NVRAM_IMAGE,
	DBG_STATUS_NVRAM_READ_FAILED,
	DBG_STATUS_IDLE_CHK_PARSE_FAILED,
	DBG_STATUS_MCP_TRACE_BAD_DATA,
	DBG_STATUS_MCP_TRACE_NO_META,
	DBG_STATUS_MCP_COULD_NOT_HALT,
	DBG_STATUS_MCP_COULD_NOT_RESUME,
	DBG_STATUS_DMAE_FAILED,
	DBG_STATUS_SEMI_FIFO_NOT_EMPTY,
	DBG_STATUS_IGU_FIFO_BAD_DATA,
	DBG_STATUS_MCP_COULD_NOT_MASK_PRTY,
	DBG_STATUS_FW_ASSERTS_PARSE_FAILED,
	DBG_STATUS_REG_FIFO_BAD_DATA,
	DBG_STATUS_PROTECTION_OVERRIDE_BAD_DATA,
	DBG_STATUS_DBG_ARRAY_NOT_SET,
	MAX_DBG_STATUS
};

/********************************/
/* HSI Init Functions constants */
/********************************/

/* Number of VLAN priorities */
#define NUM_OF_VLAN_PRIORITIES	8

/* QM per-port init parameters */
struct init_qm_port_params {
	u8 active;
	u8 active_phys_tcs;
	__le16 num_pbf_cmd_lines;
	__le16 num_btb_blocks;
	__le16 reserved;
};

/* QM per-PQ init parameters */
struct init_qm_pq_params {
	u8 vport_id;
	u8 tc_id;
	u8 wrr_group;
	u8 rl_valid;
};

/* QM per-vport init parameters */
struct init_qm_vport_params {
	__le32 vport_rl;
	__le16 vport_wfq;
	__le16 first_tx_pq_id[NUM_OF_TCS];
};

/**************************************/
/* Init Tool HSI constants and macros */
/**************************************/

/* Width of GRC address in bits (addresses are specified in dwords) */
#define GRC_ADDR_BITS	23
#define MAX_GRC_ADDR	((1 << GRC_ADDR_BITS) - 1)

/* indicates an init that should be applied to any phase ID */
#define ANY_PHASE_ID	0xffff

/* Max size in dwords of a zipped array */
#define MAX_ZIPPED_SIZE	8192

enum init_modes {
	MODE_RESERVED,
	MODE_BB_B0,
	MODE_RESERVED2,
	MODE_ASIC,
	MODE_RESERVED3,
	MODE_RESERVED4,
	MODE_RESERVED5,
	MODE_RESERVED6,
	MODE_SF,
	MODE_MF_SD,
	MODE_MF_SI,
	MODE_PORTS_PER_ENG_1,
	MODE_PORTS_PER_ENG_2,
	MODE_PORTS_PER_ENG_4,
	MODE_100G,
	MODE_40G,
	MODE_RESERVED7,
	MAX_INIT_MODES
};

enum init_phases {
	PHASE_ENGINE,
	PHASE_PORT,
	PHASE_PF,
	PHASE_VF,
	PHASE_QM_PF,
	MAX_INIT_PHASES
};

enum init_split_types {
	SPLIT_TYPE_NONE,
	SPLIT_TYPE_PORT,
	SPLIT_TYPE_PF,
	SPLIT_TYPE_PORT_PF,
	SPLIT_TYPE_VF,
	MAX_INIT_SPLIT_TYPES
};

/* Binary buffer header */
struct bin_buffer_hdr {
	__le32 offset;
	__le32 length;
};

/* binary init buffer types */
enum bin_init_buffer_type {
	BIN_BUF_FW_VER_INFO,
	BIN_BUF_INIT_CMD,
	BIN_BUF_INIT_VAL,
	BIN_BUF_INIT_MODE_TREE,
	BIN_BUF_IRO,
	MAX_BIN_INIT_BUFFER_TYPE
};

/* init array header: raw */
struct init_array_raw_hdr {
	__le32 data;
#define INIT_ARRAY_RAW_HDR_TYPE_MASK	0xF
#define INIT_ARRAY_RAW_HDR_TYPE_SHIFT	0
#define INIT_ARRAY_RAW_HDR_PARAMS_MASK	0xFFFFFFF
#define INIT_ARRAY_RAW_HDR_PARAMS_SHIFT	4
};

/* init array header: standard */
struct init_array_standard_hdr {
	__le32 data;
#define INIT_ARRAY_STANDARD_HDR_TYPE_MASK	0xF
#define INIT_ARRAY_STANDARD_HDR_TYPE_SHIFT	0
#define INIT_ARRAY_STANDARD_HDR_SIZE_MASK	0xFFFFFFF
#define INIT_ARRAY_STANDARD_HDR_SIZE_SHIFT	4
};

/* init array header: zipped */
struct init_array_zipped_hdr {
	__le32 data;
#define INIT_ARRAY_ZIPPED_HDR_TYPE_MASK		0xF
#define INIT_ARRAY_ZIPPED_HDR_TYPE_SHIFT	0
#define INIT_ARRAY_ZIPPED_HDR_ZIPPED_SIZE_MASK	0xFFFFFFF
#define INIT_ARRAY_ZIPPED_HDR_ZIPPED_SIZE_SHIFT	4
};

/* init array header: pattern */
struct init_array_pattern_hdr {
	__le32 data;
#define INIT_ARRAY_PATTERN_HDR_TYPE_MASK		0xF
#define INIT_ARRAY_PATTERN_HDR_TYPE_SHIFT		0
#define INIT_ARRAY_PATTERN_HDR_PATTERN_SIZE_MASK	0xF
#define INIT_ARRAY_PATTERN_HDR_PATTERN_SIZE_SHIFT	4
#define INIT_ARRAY_PATTERN_HDR_REPETITIONS_MASK		0xFFFFFF
#define INIT_ARRAY_PATTERN_HDR_REPETITIONS_SHIFT	8
};

/* init array header union */
union init_array_hdr {
	struct init_array_raw_hdr raw;
	struct init_array_standard_hdr standard;
	struct init_array_zipped_hdr zipped;
	struct init_array_pattern_hdr pattern;
};

/* init array types */
enum init_array_types {
	INIT_ARR_STANDARD,
	INIT_ARR_ZIPPED,
	INIT_ARR_PATTERN,
	MAX_INIT_ARRAY_TYPES
};

/* init operation: callback */
struct init_callback_op {
	__le32 op_data;
#define INIT_CALLBACK_OP_OP_MASK	0xF
#define INIT_CALLBACK_OP_OP_SHIFT	0
#define INIT_CALLBACK_OP_RESERVED_MASK	0xFFFFFFF
#define INIT_CALLBACK_OP_RESERVED_SHIFT	4
	__le16 callback_id;
	__le16 block_id;
};

/* init operation: delay */
struct init_delay_op {
	__le32 op_data;
#define INIT_DELAY_OP_OP_MASK		0xF
#define INIT_DELAY_OP_OP_SHIFT		0
#define INIT_DELAY_OP_RESERVED_MASK	0xFFFFFFF
#define INIT_DELAY_OP_RESERVED_SHIFT	4
	__le32 delay;
};

/* init operation: if_mode */
struct init_if_mode_op {
	__le32 op_data;
#define INIT_IF_MODE_OP_OP_MASK			0xF
#define INIT_IF_MODE_OP_OP_SHIFT		0
#define INIT_IF_MODE_OP_RESERVED1_MASK		0xFFF
#define INIT_IF_MODE_OP_RESERVED1_SHIFT		4
#define INIT_IF_MODE_OP_CMD_OFFSET_MASK		0xFFFF
#define INIT_IF_MODE_OP_CMD_OFFSET_SHIFT	16
	__le16 reserved2;
	__le16 modes_buf_offset;
};

/* init operation: if_phase */
struct init_if_phase_op {
	__le32 op_data;
#define INIT_IF_PHASE_OP_OP_MASK		0xF
#define INIT_IF_PHASE_OP_OP_SHIFT		0
#define INIT_IF_PHASE_OP_DMAE_ENABLE_MASK	0x1
#define INIT_IF_PHASE_OP_DMAE_ENABLE_SHIFT	4
#define INIT_IF_PHASE_OP_RESERVED1_MASK		0x7FF
#define INIT_IF_PHASE_OP_RESERVED1_SHIFT	5
#define INIT_IF_PHASE_OP_CMD_OFFSET_MASK	0xFFFF
#define INIT_IF_PHASE_OP_CMD_OFFSET_SHIFT	16
	__le32 phase_data;
#define INIT_IF_PHASE_OP_PHASE_MASK		0xFF
#define INIT_IF_PHASE_OP_PHASE_SHIFT		0
#define INIT_IF_PHASE_OP_RESERVED2_MASK		0xFF
#define INIT_IF_PHASE_OP_RESERVED2_SHIFT	8
#define INIT_IF_PHASE_OP_PHASE_ID_MASK		0xFFFF
#define INIT_IF_PHASE_OP_PHASE_ID_SHIFT		16
};

/* init mode operators */
enum init_mode_ops {
	INIT_MODE_OP_NOT,
	INIT_MODE_OP_OR,
	INIT_MODE_OP_AND,
	MAX_INIT_MODE_OPS
};

/* init operation: raw */
struct init_raw_op {
	__le32 op_data;
#define INIT_RAW_OP_OP_MASK		0xF
#define INIT_RAW_OP_OP_SHIFT		0
#define INIT_RAW_OP_PARAM1_MASK		0xFFFFFFF
#define INIT_RAW_OP_PARAM1_SHIFT	4
	__le32 param2;
};

/* init array params */
struct init_op_array_params {
	__le16 size;
	__le16 offset;
};

/* Write init operation arguments */
union init_write_args {
	__le32 inline_val;
	__le32 zeros_count;
	__le32 array_offset;
	struct init_op_array_params runtime;
};

/* init operation: write */
struct init_write_op {
	__le32 data;
#define INIT_WRITE_OP_OP_MASK		0xF
#define INIT_WRITE_OP_OP_SHIFT		0
#define INIT_WRITE_OP_SOURCE_MASK	0x7
#define INIT_WRITE_OP_SOURCE_SHIFT	4
#define INIT_WRITE_OP_RESERVED_MASK	0x1
#define INIT_WRITE_OP_RESERVED_SHIFT	7
#define INIT_WRITE_OP_WIDE_BUS_MASK	0x1
#define INIT_WRITE_OP_WIDE_BUS_SHIFT	8
#define INIT_WRITE_OP_ADDRESS_MASK	0x7FFFFF
#define INIT_WRITE_OP_ADDRESS_SHIFT	9
	union init_write_args args;
};

/* init operation: read */
struct init_read_op {
	__le32 op_data;
#define INIT_READ_OP_OP_MASK		0xF
#define INIT_READ_OP_OP_SHIFT		0
#define INIT_READ_OP_POLL_TYPE_MASK	0xF
#define INIT_READ_OP_POLL_TYPE_SHIFT	4
#define INIT_READ_OP_RESERVED_MASK	0x1
#define INIT_READ_OP_RESERVED_SHIFT	8
#define INIT_READ_OP_ADDRESS_MASK	0x7FFFFF
#define INIT_READ_OP_ADDRESS_SHIFT	9
	__le32 expected_val;

};

/* Init operations union */
union init_op {
	struct init_raw_op raw;
	struct init_write_op write;
	struct init_read_op read;
	struct init_if_mode_op if_mode;
	struct init_if_phase_op if_phase;
	struct init_callback_op callback;
	struct init_delay_op delay;
};

/* Init command operation types */
enum init_op_types {
	INIT_OP_READ,
	INIT_OP_WRITE,
	INIT_OP_IF_MODE,
	INIT_OP_IF_PHASE,
	INIT_OP_DELAY,
	INIT_OP_CALLBACK,
	MAX_INIT_OP_TYPES
};

/* init polling types */
enum init_poll_types {
	INIT_POLL_NONE,
	INIT_POLL_EQ,
	INIT_POLL_OR,
	INIT_POLL_AND,
	MAX_INIT_POLL_TYPES
};

/* init source types */
enum init_source_types {
	INIT_SRC_INLINE,
	INIT_SRC_ZEROS,
	INIT_SRC_ARRAY,
	INIT_SRC_RUNTIME,
	MAX_INIT_SOURCE_TYPES
};

/* Internal RAM Offsets macro data */
struct iro {
	__le32 base;
	__le16 m1;
	__le16 m2;
	__le16 m3;
	__le16 size;
};

/**
 * @brief qed_dbg_print_attn - Prints attention registers values in the specified results struct.
 *
 * @param p_hwfn
 * @param results - Pointer to the attention read results
 *
 * @return error if one of the following holds:
 *	- the version wasn't set
 * Otherwise, returns ok.
 */
enum dbg_status qed_dbg_print_attn(struct qed_hwfn *p_hwfn,
				   struct dbg_attn_block_result *results);

#define MAX_NAME_LEN	16

/* Win 2 */
#define GTT_BAR0_MAP_REG_IGU_CMD \
	0x00f000UL

/* Win 3 */
#define GTT_BAR0_MAP_REG_TSDM_RAM \
	0x010000UL

/* Win 4 */
#define GTT_BAR0_MAP_REG_MSDM_RAM \
	0x011000UL

/* Win 5 */
#define GTT_BAR0_MAP_REG_MSDM_RAM_1024 \
	0x012000UL

/* Win 6 */
#define GTT_BAR0_MAP_REG_USDM_RAM \
	0x013000UL

/* Win 7 */
#define GTT_BAR0_MAP_REG_USDM_RAM_1024 \
	0x014000UL

/* Win 8 */
#define GTT_BAR0_MAP_REG_USDM_RAM_2048 \
	0x015000UL

/* Win 9 */
#define GTT_BAR0_MAP_REG_XSDM_RAM \
	0x016000UL

/* Win 10 */
#define GTT_BAR0_MAP_REG_YSDM_RAM \
	0x017000UL

/* Win 11 */
#define GTT_BAR0_MAP_REG_PSDM_RAM \
	0x018000UL

/**
 * @brief qed_qm_pf_mem_size - prepare QM ILT sizes
 *
 * Returns the required host memory size in 4KB units.
 * Must be called before all QM init HSI functions.
 *
 * @param pf_id - physical function ID
 * @param num_pf_cids - number of connections used by this PF
 * @param num_vf_cids - number of connections used by VFs of this PF
 * @param num_tids - number of tasks used by this PF
 * @param num_pf_pqs - number of PQs used by this PF
 * @param num_vf_pqs - number of PQs used by VFs of this PF
 *
 * @return The required host memory size in 4KB units.
 */
u32 qed_qm_pf_mem_size(u8 pf_id,
		       u32 num_pf_cids,
		       u32 num_vf_cids,
		       u32 num_tids, u16 num_pf_pqs, u16 num_vf_pqs);

struct qed_qm_common_rt_init_params {
	u8 max_ports_per_engine;
	u8 max_phys_tcs_per_port;
	bool pf_rl_en;
	bool pf_wfq_en;
	bool vport_rl_en;
	bool vport_wfq_en;
	struct init_qm_port_params *port_params;
};

int qed_qm_common_rt_init(struct qed_hwfn *p_hwfn,
			  struct qed_qm_common_rt_init_params *p_params);

struct qed_qm_pf_rt_init_params {
	u8 port_id;
	u8 pf_id;
	u8 max_phys_tcs_per_port;
	bool is_first_pf;
	u32 num_pf_cids;
	u32 num_vf_cids;
	u32 num_tids;
	u16 start_pq;
	u16 num_pf_pqs;
	u16 num_vf_pqs;
	u8 start_vport;
	u8 num_vports;
	u8 pf_wfq;
	u32 pf_rl;
	struct init_qm_pq_params *pq_params;
	struct init_qm_vport_params *vport_params;
};

int qed_qm_pf_rt_init(struct qed_hwfn *p_hwfn,
	struct qed_ptt *p_ptt,
	struct qed_qm_pf_rt_init_params *p_params);

/**
 * @brief qed_init_pf_wfq - Initializes the WFQ weight of the specified PF
 *
 * @param p_hwfn
 * @param p_ptt - ptt window used for writing the registers
 * @param pf_id - PF ID
 * @param pf_wfq - WFQ weight. Must be non-zero.
 *
 * @return 0 on success, -1 on error.
 */
int qed_init_pf_wfq(struct qed_hwfn *p_hwfn,
		    struct qed_ptt *p_ptt, u8 pf_id, u16 pf_wfq);

/**
 * @brief qed_init_pf_rl - Initializes the rate limit of the specified PF
 *
 * @param p_hwfn
 * @param p_ptt - ptt window used for writing the registers
 * @param pf_id - PF ID
 * @param pf_rl - rate limit in Mb/sec units
 *
 * @return 0 on success, -1 on error.
 */
int qed_init_pf_rl(struct qed_hwfn *p_hwfn,
		   struct qed_ptt *p_ptt, u8 pf_id, u32 pf_rl);

/**
 * @brief qed_init_vport_wfq Initializes the WFQ weight of the specified VPORT
 *
 * @param p_hwfn
 * @param p_ptt - ptt window used for writing the registers
 * @param first_tx_pq_id- An array containing the first Tx PQ ID associated
 *	  with the VPORT for each TC. This array is filled by
 *	  qed_qm_pf_rt_init
 * @param vport_wfq - WFQ weight. Must be non-zero.
 *
 * @return 0 on success, -1 on error.
 */
int qed_init_vport_wfq(struct qed_hwfn *p_hwfn,
		       struct qed_ptt *p_ptt,
		       u16 first_tx_pq_id[NUM_OF_TCS], u16 vport_wfq);

/**
 * @brief qed_init_vport_rl - Initializes the rate limit of the specified VPORT
 *
 * @param p_hwfn
 * @param p_ptt - ptt window used for writing the registers
 * @param vport_id - VPORT ID
 * @param vport_rl - rate limit in Mb/sec units
 *
 * @return 0 on success, -1 on error.
 */
int qed_init_vport_rl(struct qed_hwfn *p_hwfn,
		      struct qed_ptt *p_ptt, u8 vport_id, u32 vport_rl);
/**
 * @brief qed_send_qm_stop_cmd  Sends a stop command to the QM
 *
 * @param p_hwfn
 * @param p_ptt
 * @param is_release_cmd - true for release, false for stop.
 * @param is_tx_pq - true for Tx PQs, false for Other PQs.
 * @param start_pq - first PQ ID to stop
 * @param num_pqs - Number of PQs to stop, starting from start_pq.
 *
 * @return bool, true if successful, false if timeout occured while waiting for QM command done.
 */
bool qed_send_qm_stop_cmd(struct qed_hwfn *p_hwfn,
			  struct qed_ptt *p_ptt,
			  bool is_release_cmd,
			  bool is_tx_pq, u16 start_pq, u16 num_pqs);

/**
 * @brief qed_set_vxlan_dest_port - initializes vxlan tunnel destination udp port
 *
 * @param p_ptt - ptt window used for writing the registers.
 * @param dest_port - vxlan destination udp port.
 */
void qed_set_vxlan_dest_port(struct qed_hwfn *p_hwfn,
			     struct qed_ptt *p_ptt, u16 dest_port);

/**
 * @brief qed_set_vxlan_enable - enable or disable VXLAN tunnel in HW
 *
 * @param p_ptt - ptt window used for writing the registers.
 * @param vxlan_enable - vxlan enable flag.
 */
void qed_set_vxlan_enable(struct qed_hwfn *p_hwfn,
			  struct qed_ptt *p_ptt, bool vxlan_enable);

/**
 * @brief qed_set_gre_enable - enable or disable GRE tunnel in HW
 *
 * @param p_ptt - ptt window used for writing the registers.
 * @param eth_gre_enable - eth GRE enable enable flag.
 * @param ip_gre_enable - IP GRE enable enable flag.
 */
void qed_set_gre_enable(struct qed_hwfn *p_hwfn,
			struct qed_ptt *p_ptt,
			bool eth_gre_enable, bool ip_gre_enable);

/**
 * @brief qed_set_geneve_dest_port - initializes geneve tunnel destination udp port
 *
 * @param p_ptt - ptt window used for writing the registers.
 * @param dest_port - geneve destination udp port.
 */
void qed_set_geneve_dest_port(struct qed_hwfn *p_hwfn,
			      struct qed_ptt *p_ptt, u16 dest_port);

/**
 * @brief qed_set_gre_enable - enable or disable GRE tunnel in HW
 *
 * @param p_ptt - ptt window used for writing the registers.
 * @param eth_geneve_enable - eth GENEVE enable enable flag.
 * @param ip_geneve_enable - IP GENEVE enable enable flag.
 */
void qed_set_geneve_enable(struct qed_hwfn *p_hwfn,
			   struct qed_ptt *p_ptt,
			   bool eth_geneve_enable, bool ip_geneve_enable);

#define	YSTORM_FLOW_CONTROL_MODE_OFFSET			(IRO[0].base)
#define	YSTORM_FLOW_CONTROL_MODE_SIZE			(IRO[0].size)
#define	TSTORM_PORT_STAT_OFFSET(port_id) \
	(IRO[1].base + ((port_id) * IRO[1].m1))
#define	TSTORM_PORT_STAT_SIZE				(IRO[1].size)
#define	USTORM_VF_PF_CHANNEL_READY_OFFSET(vf_id) \
	(IRO[3].base + ((vf_id) * IRO[3].m1))
#define	USTORM_VF_PF_CHANNEL_READY_SIZE			(IRO[3].size)
#define	USTORM_FLR_FINAL_ACK_OFFSET(pf_id) \
	(IRO[4].base + (pf_id) * IRO[4].m1)
#define	USTORM_FLR_FINAL_ACK_SIZE			(IRO[4].size)
#define	USTORM_EQE_CONS_OFFSET(pf_id) \
	(IRO[5].base + ((pf_id) * IRO[5].m1))
#define	USTORM_EQE_CONS_SIZE				(IRO[5].size)
#define	USTORM_ETH_QUEUE_ZONE_OFFSET(queue_zone_id) \
	(IRO[6].base + ((queue_zone_id) * IRO[6].m1))
#define	USTORM_ETH_QUEUE_ZONE_SIZE			(IRO[6].size)
#define	USTORM_COMMON_QUEUE_CONS_OFFSET(queue_zone_id) \
	(IRO[7].base + ((queue_zone_id) * IRO[7].m1))
#define	USTORM_COMMON_QUEUE_CONS_SIZE			(IRO[7].size)
#define	MSTORM_QUEUE_STAT_OFFSET(stat_counter_id) \
	(IRO[18].base + ((stat_counter_id) * IRO[18].m1))
#define	MSTORM_QUEUE_STAT_SIZE				(IRO[18].size)
#define	MSTORM_ETH_PF_PRODS_OFFSET(queue_id) \
	(IRO[19].base + ((queue_id) * IRO[19].m1))
#define	MSTORM_ETH_PF_PRODS_SIZE			(IRO[19].size)
#define	MSTORM_TPA_TIMEOUT_US_OFFSET			(IRO[20].base)
#define	MSTORM_TPA_TIMEOUT_US_SIZE			(IRO[20].size)
#define	MSTORM_ETH_PF_STAT_OFFSET(pf_id) \
	(IRO[21].base + ((pf_id) * IRO[21].m1))
#define	MSTORM_ETH_PF_STAT_SIZE				(IRO[21].size)
#define	USTORM_QUEUE_STAT_OFFSET(stat_counter_id) \
	(IRO[22].base + ((stat_counter_id) * IRO[22].m1))
#define	USTORM_QUEUE_STAT_SIZE				(IRO[22].size)
#define	USTORM_ETH_PF_STAT_OFFSET(pf_id) \
	(IRO[23].base + ((pf_id) * IRO[23].m1))
#define	USTORM_ETH_PF_STAT_SIZE				(IRO[23].size)
#define	PSTORM_QUEUE_STAT_OFFSET(stat_counter_id) \
	(IRO[24].base + ((stat_counter_id) * IRO[24].m1))
#define	PSTORM_QUEUE_STAT_SIZE				(IRO[24].size)
#define	PSTORM_ETH_PF_STAT_OFFSET(pf_id) \
	(IRO[25].base + ((pf_id) * IRO[25].m1))
#define	PSTORM_ETH_PF_STAT_SIZE				(IRO[25].size)
#define	PSTORM_CTL_FRAME_ETHTYPE_OFFSET(ethtype) \
	(IRO[26].base + ((ethtype) * IRO[26].m1))
#define	PSTORM_CTL_FRAME_ETHTYPE_SIZE			(IRO[26].size)
#define	TSTORM_ETH_PRS_INPUT_OFFSET			(IRO[27].base)
#define	TSTORM_ETH_PRS_INPUT_SIZE			(IRO[27].size)
#define	ETH_RX_RATE_LIMIT_OFFSET(pf_id) \
	(IRO[28].base + ((pf_id) * IRO[28].m1))
#define	ETH_RX_RATE_LIMIT_SIZE				(IRO[28].size)
#define	XSTORM_ETH_QUEUE_ZONE_OFFSET(queue_id) \
	(IRO[29].base + ((queue_id) * IRO[29].m1))
#define	XSTORM_ETH_QUEUE_ZONE_SIZE			(IRO[29].size)

static const struct iro iro_arr[46] = {
	{0x0, 0x0, 0x0, 0x0, 0x8},
	{0x4cb0, 0x78, 0x0, 0x0, 0x78},
	{0x6318, 0x20, 0x0, 0x0, 0x20},
	{0xb00, 0x8, 0x0, 0x0, 0x4},
	{0xa80, 0x8, 0x0, 0x0, 0x4},
	{0x0, 0x8, 0x0, 0x0, 0x2},
	{0x80, 0x8, 0x0, 0x0, 0x4},
	{0x84, 0x8, 0x0, 0x0, 0x2},
	{0x4bc0, 0x0, 0x0, 0x0, 0x78},
	{0x3df0, 0x0, 0x0, 0x0, 0x78},
	{0x29b0, 0x0, 0x0, 0x0, 0x78},
	{0x4c38, 0x0, 0x0, 0x0, 0x78},
	{0x4a48, 0x0, 0x0, 0x0, 0x78},
	{0x7e48, 0x0, 0x0, 0x0, 0x78},
	{0xa28, 0x8, 0x0, 0x0, 0x8},
	{0x60f8, 0x10, 0x0, 0x0, 0x10},
	{0xb820, 0x30, 0x0, 0x0, 0x30},
	{0x95b8, 0x30, 0x0, 0x0, 0x30},
	{0x4c18, 0x80, 0x0, 0x0, 0x40},
	{0x1f8, 0x4, 0x0, 0x0, 0x4},
	{0xc9a8, 0x0, 0x0, 0x0, 0x4},
	{0x4c58, 0x80, 0x0, 0x0, 0x20},
	{0x8050, 0x40, 0x0, 0x0, 0x30},
	{0xe770, 0x60, 0x0, 0x0, 0x60},
	{0x2b48, 0x80, 0x0, 0x0, 0x38},
	{0xdf88, 0x78, 0x0, 0x0, 0x78},
	{0x1f8, 0x4, 0x0, 0x0, 0x4},
	{0xacf0, 0x0, 0x0, 0x0, 0xf0},
	{0xade0, 0x8, 0x0, 0x0, 0x8},
	{0x1f8, 0x8, 0x0, 0x0, 0x8},
	{0xac0, 0x8, 0x0, 0x0, 0x8},
	{0x2578, 0x8, 0x0, 0x0, 0x8},
	{0x24f8, 0x8, 0x0, 0x0, 0x8},
	{0x0, 0x8, 0x0, 0x0, 0x8},
	{0x200, 0x10, 0x8, 0x0, 0x8},
	{0xb78, 0x10, 0x8, 0x0, 0x2},
	{0xd888, 0x38, 0x0, 0x0, 0x24},
	{0x12120, 0x10, 0x0, 0x0, 0x8},
	{0x11b20, 0x38, 0x0, 0x0, 0x18},
	{0xa8c0, 0x30, 0x0, 0x0, 0x10},
	{0x86f8, 0x28, 0x0, 0x0, 0x18},
	{0xeff8, 0x10, 0x0, 0x0, 0x10},
	{0xdd08, 0x48, 0x0, 0x0, 0x38},
	{0xf460, 0x20, 0x0, 0x0, 0x20},
	{0x2b80, 0x80, 0x0, 0x0, 0x10},
	{0x5000, 0x10, 0x0, 0x0, 0x10},
};

/* Runtime array offsets */
#define DORQ_REG_PF_MAX_ICID_0_RT_OFFSET 0
#define DORQ_REG_PF_MAX_ICID_1_RT_OFFSET 1
#define DORQ_REG_PF_MAX_ICID_2_RT_OFFSET 2
#define DORQ_REG_PF_MAX_ICID_3_RT_OFFSET 3
#define DORQ_REG_PF_MAX_ICID_4_RT_OFFSET 4
#define DORQ_REG_PF_MAX_ICID_5_RT_OFFSET 5
#define DORQ_REG_PF_MAX_ICID_6_RT_OFFSET 6
#define DORQ_REG_PF_MAX_ICID_7_RT_OFFSET 7
#define DORQ_REG_VF_MAX_ICID_0_RT_OFFSET 8
#define DORQ_REG_VF_MAX_ICID_1_RT_OFFSET 9
#define DORQ_REG_VF_MAX_ICID_2_RT_OFFSET 10
#define DORQ_REG_VF_MAX_ICID_3_RT_OFFSET 11
#define DORQ_REG_VF_MAX_ICID_4_RT_OFFSET 12
#define DORQ_REG_VF_MAX_ICID_5_RT_OFFSET 13
#define DORQ_REG_VF_MAX_ICID_6_RT_OFFSET 14
#define DORQ_REG_VF_MAX_ICID_7_RT_OFFSET 15
#define DORQ_REG_PF_WAKE_ALL_RT_OFFSET 16
#define DORQ_REG_TAG1_ETHERTYPE_RT_OFFSET 17
#define IGU_REG_PF_CONFIGURATION_RT_OFFSET 18
#define IGU_REG_VF_CONFIGURATION_RT_OFFSET 19
#define IGU_REG_ATTN_MSG_ADDR_L_RT_OFFSET 20
#define IGU_REG_ATTN_MSG_ADDR_H_RT_OFFSET 21
#define IGU_REG_LEADING_EDGE_LATCH_RT_OFFSET 22
#define IGU_REG_TRAILING_EDGE_LATCH_RT_OFFSET 23
#define CAU_REG_CQE_AGG_UNIT_SIZE_RT_OFFSET 24
#define CAU_REG_SB_VAR_MEMORY_RT_OFFSET 761
#define CAU_REG_SB_VAR_MEMORY_RT_SIZE 736
#define CAU_REG_SB_VAR_MEMORY_RT_OFFSET 761
#define CAU_REG_SB_VAR_MEMORY_RT_SIZE 736
#define CAU_REG_SB_ADDR_MEMORY_RT_OFFSET 1497
#define CAU_REG_SB_ADDR_MEMORY_RT_SIZE 736
#define CAU_REG_PI_MEMORY_RT_OFFSET 2233
#define CAU_REG_PI_MEMORY_RT_SIZE 4416
#define PRS_REG_SEARCH_RESP_INITIATOR_TYPE_RT_OFFSET 6649
#define PRS_REG_TASK_ID_MAX_INITIATOR_PF_RT_OFFSET 6650
#define PRS_REG_TASK_ID_MAX_INITIATOR_VF_RT_OFFSET 6651
#define PRS_REG_TASK_ID_MAX_TARGET_PF_RT_OFFSET 6652
#define PRS_REG_TASK_ID_MAX_TARGET_VF_RT_OFFSET 6653
#define PRS_REG_SEARCH_TCP_RT_OFFSET 6654
#define PRS_REG_SEARCH_FCOE_RT_OFFSET 6655
#define PRS_REG_SEARCH_ROCE_RT_OFFSET 6656
#define PRS_REG_ROCE_DEST_QP_MAX_VF_RT_OFFSET 6657
#define PRS_REG_ROCE_DEST_QP_MAX_PF_RT_OFFSET 6658
#define PRS_REG_SEARCH_OPENFLOW_RT_OFFSET 6659
#define PRS_REG_SEARCH_NON_IP_AS_OPENFLOW_RT_OFFSET 6660
#define PRS_REG_OPENFLOW_SUPPORT_ONLY_KNOWN_OVER_IP_RT_OFFSET 6661
#define PRS_REG_OPENFLOW_SEARCH_KEY_MASK_RT_OFFSET 6662
#define PRS_REG_TAG_ETHERTYPE_0_RT_OFFSET 6663
#define PRS_REG_LIGHT_L2_ETHERTYPE_EN_RT_OFFSET 6664
#define SRC_REG_FIRSTFREE_RT_OFFSET 6665
#define SRC_REG_FIRSTFREE_RT_SIZE 2
#define SRC_REG_LASTFREE_RT_OFFSET 6667
#define SRC_REG_LASTFREE_RT_SIZE 2
#define SRC_REG_COUNTFREE_RT_OFFSET 6669
#define SRC_REG_NUMBER_HASH_BITS_RT_OFFSET 6670
#define PSWRQ2_REG_CDUT_P_SIZE_RT_OFFSET 6671
#define PSWRQ2_REG_CDUC_P_SIZE_RT_OFFSET 6672
#define PSWRQ2_REG_TM_P_SIZE_RT_OFFSET 6673
#define PSWRQ2_REG_QM_P_SIZE_RT_OFFSET 6674
#define PSWRQ2_REG_SRC_P_SIZE_RT_OFFSET 6675
#define PSWRQ2_REG_TSDM_P_SIZE_RT_OFFSET 6676
#define PSWRQ2_REG_TM_FIRST_ILT_RT_OFFSET 6677
#define PSWRQ2_REG_TM_LAST_ILT_RT_OFFSET 6678
#define PSWRQ2_REG_QM_FIRST_ILT_RT_OFFSET 6679
#define PSWRQ2_REG_QM_LAST_ILT_RT_OFFSET 6680
#define PSWRQ2_REG_SRC_FIRST_ILT_RT_OFFSET 6681
#define PSWRQ2_REG_SRC_LAST_ILT_RT_OFFSET 6682
#define PSWRQ2_REG_CDUC_FIRST_ILT_RT_OFFSET 6683
#define PSWRQ2_REG_CDUC_LAST_ILT_RT_OFFSET 6684
#define PSWRQ2_REG_CDUT_FIRST_ILT_RT_OFFSET 6685
#define PSWRQ2_REG_CDUT_LAST_ILT_RT_OFFSET 6686
#define PSWRQ2_REG_TSDM_FIRST_ILT_RT_OFFSET 6687
#define PSWRQ2_REG_TSDM_LAST_ILT_RT_OFFSET 6688
#define PSWRQ2_REG_TM_NUMBER_OF_PF_BLOCKS_RT_OFFSET 6689
#define PSWRQ2_REG_CDUT_NUMBER_OF_PF_BLOCKS_RT_OFFSET 6690
#define PSWRQ2_REG_CDUC_NUMBER_OF_PF_BLOCKS_RT_OFFSET 6691
#define PSWRQ2_REG_TM_VF_BLOCKS_RT_OFFSET 6692
#define PSWRQ2_REG_CDUT_VF_BLOCKS_RT_OFFSET 6693
#define PSWRQ2_REG_CDUC_VF_BLOCKS_RT_OFFSET 6694
#define PSWRQ2_REG_TM_BLOCKS_FACTOR_RT_OFFSET 6695
#define PSWRQ2_REG_CDUT_BLOCKS_FACTOR_RT_OFFSET 6696
#define PSWRQ2_REG_CDUC_BLOCKS_FACTOR_RT_OFFSET 6697
#define PSWRQ2_REG_VF_BASE_RT_OFFSET 6698
#define PSWRQ2_REG_VF_LAST_ILT_RT_OFFSET 6699
#define PSWRQ2_REG_WR_MBS0_RT_OFFSET 6700
#define PSWRQ2_REG_RD_MBS0_RT_OFFSET 6701
#define PSWRQ2_REG_DRAM_ALIGN_WR_RT_OFFSET 6702
#define PSWRQ2_REG_DRAM_ALIGN_RD_RT_OFFSET 6703
#define PSWRQ2_REG_ILT_MEMORY_RT_OFFSET 6704
#define PSWRQ2_REG_ILT_MEMORY_RT_SIZE 22000
#define PGLUE_REG_B_VF_BASE_RT_OFFSET 28704
#define PGLUE_REG_B_CACHE_LINE_SIZE_RT_OFFSET 28705
#define PGLUE_REG_B_PF_BAR0_SIZE_RT_OFFSET 28706
#define PGLUE_REG_B_PF_BAR1_SIZE_RT_OFFSET 28707
#define PGLUE_REG_B_VF_BAR1_SIZE_RT_OFFSET 28708
#define TM_REG_VF_ENABLE_CONN_RT_OFFSET 28709
#define TM_REG_PF_ENABLE_CONN_RT_OFFSET 28710
#define TM_REG_PF_ENABLE_TASK_RT_OFFSET 28711
#define TM_REG_GROUP_SIZE_RESOLUTION_CONN_RT_OFFSET 28712
#define TM_REG_GROUP_SIZE_RESOLUTION_TASK_RT_OFFSET 28713
#define TM_REG_CONFIG_CONN_MEM_RT_OFFSET 28714
#define TM_REG_CONFIG_CONN_MEM_RT_SIZE 416
#define TM_REG_CONFIG_TASK_MEM_RT_OFFSET 29130
#define TM_REG_CONFIG_TASK_MEM_RT_SIZE 512
#define QM_REG_MAXPQSIZE_0_RT_OFFSET 29642
#define QM_REG_MAXPQSIZE_1_RT_OFFSET 29643
#define QM_REG_MAXPQSIZE_2_RT_OFFSET 29644
#define QM_REG_MAXPQSIZETXSEL_0_RT_OFFSET 29645
#define QM_REG_MAXPQSIZETXSEL_1_RT_OFFSET 29646
#define QM_REG_MAXPQSIZETXSEL_2_RT_OFFSET 29647
#define QM_REG_MAXPQSIZETXSEL_3_RT_OFFSET 29648
#define QM_REG_MAXPQSIZETXSEL_4_RT_OFFSET 29649
#define QM_REG_MAXPQSIZETXSEL_5_RT_OFFSET 29650
#define QM_REG_MAXPQSIZETXSEL_6_RT_OFFSET 29651
#define QM_REG_MAXPQSIZETXSEL_7_RT_OFFSET 29652
#define QM_REG_MAXPQSIZETXSEL_8_RT_OFFSET 29653
#define QM_REG_MAXPQSIZETXSEL_9_RT_OFFSET 29654
#define QM_REG_MAXPQSIZETXSEL_10_RT_OFFSET 29655
#define QM_REG_MAXPQSIZETXSEL_11_RT_OFFSET 29656
#define QM_REG_MAXPQSIZETXSEL_12_RT_OFFSET 29657
#define QM_REG_MAXPQSIZETXSEL_13_RT_OFFSET 29658
#define QM_REG_MAXPQSIZETXSEL_14_RT_OFFSET 29659
#define QM_REG_MAXPQSIZETXSEL_15_RT_OFFSET 29660
#define QM_REG_MAXPQSIZETXSEL_16_RT_OFFSET 29661
#define QM_REG_MAXPQSIZETXSEL_17_RT_OFFSET 29662
#define QM_REG_MAXPQSIZETXSEL_18_RT_OFFSET 29663
#define QM_REG_MAXPQSIZETXSEL_19_RT_OFFSET 29664
#define QM_REG_MAXPQSIZETXSEL_20_RT_OFFSET 29665
#define QM_REG_MAXPQSIZETXSEL_21_RT_OFFSET 29666
#define QM_REG_MAXPQSIZETXSEL_22_RT_OFFSET 29667
#define QM_REG_MAXPQSIZETXSEL_23_RT_OFFSET 29668
#define QM_REG_MAXPQSIZETXSEL_24_RT_OFFSET 29669
#define QM_REG_MAXPQSIZETXSEL_25_RT_OFFSET 29670
#define QM_REG_MAXPQSIZETXSEL_26_RT_OFFSET 29671
#define QM_REG_MAXPQSIZETXSEL_27_RT_OFFSET 29672
#define QM_REG_MAXPQSIZETXSEL_28_RT_OFFSET 29673
#define QM_REG_MAXPQSIZETXSEL_29_RT_OFFSET 29674
#define QM_REG_MAXPQSIZETXSEL_30_RT_OFFSET 29675
#define QM_REG_MAXPQSIZETXSEL_31_RT_OFFSET 29676
#define QM_REG_MAXPQSIZETXSEL_32_RT_OFFSET 29677
#define QM_REG_MAXPQSIZETXSEL_33_RT_OFFSET 29678
#define QM_REG_MAXPQSIZETXSEL_34_RT_OFFSET 29679
#define QM_REG_MAXPQSIZETXSEL_35_RT_OFFSET 29680
#define QM_REG_MAXPQSIZETXSEL_36_RT_OFFSET 29681
#define QM_REG_MAXPQSIZETXSEL_37_RT_OFFSET 29682
#define QM_REG_MAXPQSIZETXSEL_38_RT_OFFSET 29683
#define QM_REG_MAXPQSIZETXSEL_39_RT_OFFSET 29684
#define QM_REG_MAXPQSIZETXSEL_40_RT_OFFSET 29685
#define QM_REG_MAXPQSIZETXSEL_41_RT_OFFSET 29686
#define QM_REG_MAXPQSIZETXSEL_42_RT_OFFSET 29687
#define QM_REG_MAXPQSIZETXSEL_43_RT_OFFSET 29688
#define QM_REG_MAXPQSIZETXSEL_44_RT_OFFSET 29689
#define QM_REG_MAXPQSIZETXSEL_45_RT_OFFSET 29690
#define QM_REG_MAXPQSIZETXSEL_46_RT_OFFSET 29691
#define QM_REG_MAXPQSIZETXSEL_47_RT_OFFSET 29692
#define QM_REG_MAXPQSIZETXSEL_48_RT_OFFSET 29693
#define QM_REG_MAXPQSIZETXSEL_49_RT_OFFSET 29694
#define QM_REG_MAXPQSIZETXSEL_50_RT_OFFSET 29695
#define QM_REG_MAXPQSIZETXSEL_51_RT_OFFSET 29696
#define QM_REG_MAXPQSIZETXSEL_52_RT_OFFSET 29697
#define QM_REG_MAXPQSIZETXSEL_53_RT_OFFSET 29698
#define QM_REG_MAXPQSIZETXSEL_54_RT_OFFSET 29699
#define QM_REG_MAXPQSIZETXSEL_55_RT_OFFSET 29700
#define QM_REG_MAXPQSIZETXSEL_56_RT_OFFSET 29701
#define QM_REG_MAXPQSIZETXSEL_57_RT_OFFSET 29702
#define QM_REG_MAXPQSIZETXSEL_58_RT_OFFSET 29703
#define QM_REG_MAXPQSIZETXSEL_59_RT_OFFSET 29704
#define QM_REG_MAXPQSIZETXSEL_60_RT_OFFSET 29705
#define QM_REG_MAXPQSIZETXSEL_61_RT_OFFSET 29706
#define QM_REG_MAXPQSIZETXSEL_62_RT_OFFSET 29707
#define QM_REG_MAXPQSIZETXSEL_63_RT_OFFSET 29708
#define QM_REG_BASEADDROTHERPQ_RT_OFFSET 29709
#define QM_REG_BASEADDROTHERPQ_RT_SIZE 128
#define QM_REG_VOQCRDLINE_RT_OFFSET 29837
#define QM_REG_VOQCRDLINE_RT_SIZE 20
#define QM_REG_VOQINITCRDLINE_RT_OFFSET 29857
#define QM_REG_VOQINITCRDLINE_RT_SIZE 20
#define QM_REG_AFULLQMBYPTHRPFWFQ_RT_OFFSET 29877
#define QM_REG_AFULLQMBYPTHRVPWFQ_RT_OFFSET 29878
#define QM_REG_AFULLQMBYPTHRPFRL_RT_OFFSET 29879
#define QM_REG_AFULLQMBYPTHRGLBLRL_RT_OFFSET 29880
#define QM_REG_AFULLOPRTNSTCCRDMASK_RT_OFFSET 29881
#define QM_REG_WRROTHERPQGRP_0_RT_OFFSET 29882
#define QM_REG_WRROTHERPQGRP_1_RT_OFFSET 29883
#define QM_REG_WRROTHERPQGRP_2_RT_OFFSET 29884
#define QM_REG_WRROTHERPQGRP_3_RT_OFFSET 29885
#define QM_REG_WRROTHERPQGRP_4_RT_OFFSET 29886
#define QM_REG_WRROTHERPQGRP_5_RT_OFFSET 29887
#define QM_REG_WRROTHERPQGRP_6_RT_OFFSET 29888
#define QM_REG_WRROTHERPQGRP_7_RT_OFFSET 29889
#define QM_REG_WRROTHERPQGRP_8_RT_OFFSET 29890
#define QM_REG_WRROTHERPQGRP_9_RT_OFFSET 29891
#define QM_REG_WRROTHERPQGRP_10_RT_OFFSET 29892
#define QM_REG_WRROTHERPQGRP_11_RT_OFFSET 29893
#define QM_REG_WRROTHERPQGRP_12_RT_OFFSET 29894
#define QM_REG_WRROTHERPQGRP_13_RT_OFFSET 29895
#define QM_REG_WRROTHERPQGRP_14_RT_OFFSET 29896
#define QM_REG_WRROTHERPQGRP_15_RT_OFFSET 29897
#define QM_REG_WRROTHERGRPWEIGHT_0_RT_OFFSET 29898
#define QM_REG_WRROTHERGRPWEIGHT_1_RT_OFFSET 29899
#define QM_REG_WRROTHERGRPWEIGHT_2_RT_OFFSET 29900
#define QM_REG_WRROTHERGRPWEIGHT_3_RT_OFFSET 29901
#define QM_REG_WRRTXGRPWEIGHT_0_RT_OFFSET 29902
#define QM_REG_WRRTXGRPWEIGHT_1_RT_OFFSET 29903
#define QM_REG_PQTX2PF_0_RT_OFFSET 29904
#define QM_REG_PQTX2PF_1_RT_OFFSET 29905
#define QM_REG_PQTX2PF_2_RT_OFFSET 29906
#define QM_REG_PQTX2PF_3_RT_OFFSET 29907
#define QM_REG_PQTX2PF_4_RT_OFFSET 29908
#define QM_REG_PQTX2PF_5_RT_OFFSET 29909
#define QM_REG_PQTX2PF_6_RT_OFFSET 29910
#define QM_REG_PQTX2PF_7_RT_OFFSET 29911
#define QM_REG_PQTX2PF_8_RT_OFFSET 29912
#define QM_REG_PQTX2PF_9_RT_OFFSET 29913
#define QM_REG_PQTX2PF_10_RT_OFFSET 29914
#define QM_REG_PQTX2PF_11_RT_OFFSET 29915
#define QM_REG_PQTX2PF_12_RT_OFFSET 29916
#define QM_REG_PQTX2PF_13_RT_OFFSET 29917
#define QM_REG_PQTX2PF_14_RT_OFFSET 29918
#define QM_REG_PQTX2PF_15_RT_OFFSET 29919
#define QM_REG_PQTX2PF_16_RT_OFFSET 29920
#define QM_REG_PQTX2PF_17_RT_OFFSET 29921
#define QM_REG_PQTX2PF_18_RT_OFFSET 29922
#define QM_REG_PQTX2PF_19_RT_OFFSET 29923
#define QM_REG_PQTX2PF_20_RT_OFFSET 29924
#define QM_REG_PQTX2PF_21_RT_OFFSET 29925
#define QM_REG_PQTX2PF_22_RT_OFFSET 29926
#define QM_REG_PQTX2PF_23_RT_OFFSET 29927
#define QM_REG_PQTX2PF_24_RT_OFFSET 29928
#define QM_REG_PQTX2PF_25_RT_OFFSET 29929
#define QM_REG_PQTX2PF_26_RT_OFFSET 29930
#define QM_REG_PQTX2PF_27_RT_OFFSET 29931
#define QM_REG_PQTX2PF_28_RT_OFFSET 29932
#define QM_REG_PQTX2PF_29_RT_OFFSET 29933
#define QM_REG_PQTX2PF_30_RT_OFFSET 29934
#define QM_REG_PQTX2PF_31_RT_OFFSET 29935
#define QM_REG_PQTX2PF_32_RT_OFFSET 29936
#define QM_REG_PQTX2PF_33_RT_OFFSET 29937
#define QM_REG_PQTX2PF_34_RT_OFFSET 29938
#define QM_REG_PQTX2PF_35_RT_OFFSET 29939
#define QM_REG_PQTX2PF_36_RT_OFFSET 29940
#define QM_REG_PQTX2PF_37_RT_OFFSET 29941
#define QM_REG_PQTX2PF_38_RT_OFFSET 29942
#define QM_REG_PQTX2PF_39_RT_OFFSET 29943
#define QM_REG_PQTX2PF_40_RT_OFFSET 29944
#define QM_REG_PQTX2PF_41_RT_OFFSET 29945
#define QM_REG_PQTX2PF_42_RT_OFFSET 29946
#define QM_REG_PQTX2PF_43_RT_OFFSET 29947
#define QM_REG_PQTX2PF_44_RT_OFFSET 29948
#define QM_REG_PQTX2PF_45_RT_OFFSET 29949
#define QM_REG_PQTX2PF_46_RT_OFFSET 29950
#define QM_REG_PQTX2PF_47_RT_OFFSET 29951
#define QM_REG_PQTX2PF_48_RT_OFFSET 29952
#define QM_REG_PQTX2PF_49_RT_OFFSET 29953
#define QM_REG_PQTX2PF_50_RT_OFFSET 29954
#define QM_REG_PQTX2PF_51_RT_OFFSET 29955
#define QM_REG_PQTX2PF_52_RT_OFFSET 29956
#define QM_REG_PQTX2PF_53_RT_OFFSET 29957
#define QM_REG_PQTX2PF_54_RT_OFFSET 29958
#define QM_REG_PQTX2PF_55_RT_OFFSET 29959
#define QM_REG_PQTX2PF_56_RT_OFFSET 29960
#define QM_REG_PQTX2PF_57_RT_OFFSET 29961
#define QM_REG_PQTX2PF_58_RT_OFFSET 29962
#define QM_REG_PQTX2PF_59_RT_OFFSET 29963
#define QM_REG_PQTX2PF_60_RT_OFFSET 29964
#define QM_REG_PQTX2PF_61_RT_OFFSET 29965
#define QM_REG_PQTX2PF_62_RT_OFFSET 29966
#define QM_REG_PQTX2PF_63_RT_OFFSET 29967
#define QM_REG_PQOTHER2PF_0_RT_OFFSET 29968
#define QM_REG_PQOTHER2PF_1_RT_OFFSET 29969
#define QM_REG_PQOTHER2PF_2_RT_OFFSET 29970
#define QM_REG_PQOTHER2PF_3_RT_OFFSET 29971
#define QM_REG_PQOTHER2PF_4_RT_OFFSET 29972
#define QM_REG_PQOTHER2PF_5_RT_OFFSET 29973
#define QM_REG_PQOTHER2PF_6_RT_OFFSET 29974
#define QM_REG_PQOTHER2PF_7_RT_OFFSET 29975
#define QM_REG_PQOTHER2PF_8_RT_OFFSET 29976
#define QM_REG_PQOTHER2PF_9_RT_OFFSET 29977
#define QM_REG_PQOTHER2PF_10_RT_OFFSET 29978
#define QM_REG_PQOTHER2PF_11_RT_OFFSET 29979
#define QM_REG_PQOTHER2PF_12_RT_OFFSET 29980
#define QM_REG_PQOTHER2PF_13_RT_OFFSET 29981
#define QM_REG_PQOTHER2PF_14_RT_OFFSET 29982
#define QM_REG_PQOTHER2PF_15_RT_OFFSET 29983
#define QM_REG_RLGLBLPERIOD_0_RT_OFFSET 29984
#define QM_REG_RLGLBLPERIOD_1_RT_OFFSET 29985
#define QM_REG_RLGLBLPERIODTIMER_0_RT_OFFSET 29986
#define QM_REG_RLGLBLPERIODTIMER_1_RT_OFFSET 29987
#define QM_REG_RLGLBLPERIODSEL_0_RT_OFFSET 29988
#define QM_REG_RLGLBLPERIODSEL_1_RT_OFFSET 29989
#define QM_REG_RLGLBLPERIODSEL_2_RT_OFFSET 29990
#define QM_REG_RLGLBLPERIODSEL_3_RT_OFFSET 29991
#define QM_REG_RLGLBLPERIODSEL_4_RT_OFFSET 29992
#define QM_REG_RLGLBLPERIODSEL_5_RT_OFFSET 29993
#define QM_REG_RLGLBLPERIODSEL_6_RT_OFFSET 29994
#define QM_REG_RLGLBLPERIODSEL_7_RT_OFFSET 29995
#define QM_REG_RLGLBLINCVAL_RT_OFFSET 29996
#define QM_REG_RLGLBLINCVAL_RT_SIZE 256
#define QM_REG_RLGLBLUPPERBOUND_RT_OFFSET 30252
#define QM_REG_RLGLBLUPPERBOUND_RT_SIZE 256
#define QM_REG_RLGLBLCRD_RT_OFFSET 30508
#define QM_REG_RLGLBLCRD_RT_SIZE 256
#define QM_REG_RLGLBLENABLE_RT_OFFSET 30764
#define QM_REG_RLPFPERIOD_RT_OFFSET 30765
#define QM_REG_RLPFPERIODTIMER_RT_OFFSET 30766
#define QM_REG_RLPFINCVAL_RT_OFFSET 30767
#define QM_REG_RLPFINCVAL_RT_SIZE 16
#define QM_REG_RLPFUPPERBOUND_RT_OFFSET 30783
#define QM_REG_RLPFUPPERBOUND_RT_SIZE 16
#define QM_REG_RLPFCRD_RT_OFFSET 30799
#define QM_REG_RLPFCRD_RT_SIZE 16
#define QM_REG_RLPFENABLE_RT_OFFSET 30815
#define QM_REG_RLPFVOQENABLE_RT_OFFSET 30816
#define QM_REG_WFQPFWEIGHT_RT_OFFSET 30817
#define QM_REG_WFQPFWEIGHT_RT_SIZE 16
#define QM_REG_WFQPFUPPERBOUND_RT_OFFSET 30833
#define QM_REG_WFQPFUPPERBOUND_RT_SIZE 16
#define QM_REG_WFQPFCRD_RT_OFFSET 30849
#define QM_REG_WFQPFCRD_RT_SIZE 160
#define QM_REG_WFQPFENABLE_RT_OFFSET 31009
#define QM_REG_WFQVPENABLE_RT_OFFSET 31010
#define QM_REG_BASEADDRTXPQ_RT_OFFSET 31011
#define QM_REG_BASEADDRTXPQ_RT_SIZE 512
#define QM_REG_TXPQMAP_RT_OFFSET 31523
#define QM_REG_TXPQMAP_RT_SIZE 512
#define QM_REG_WFQVPWEIGHT_RT_OFFSET 32035
#define QM_REG_WFQVPWEIGHT_RT_SIZE 512
#define QM_REG_WFQVPCRD_RT_OFFSET 32547
#define QM_REG_WFQVPCRD_RT_SIZE 512
#define QM_REG_WFQVPMAP_RT_OFFSET 33059
#define QM_REG_WFQVPMAP_RT_SIZE 512
#define QM_REG_WFQPFCRD_MSB_RT_OFFSET 33571
#define QM_REG_WFQPFCRD_MSB_RT_SIZE 160
#define NIG_REG_TAG_ETHERTYPE_0_RT_OFFSET 33731
#define NIG_REG_OUTER_TAG_VALUE_LIST0_RT_OFFSET 33732
#define NIG_REG_OUTER_TAG_VALUE_LIST1_RT_OFFSET 33733
#define NIG_REG_OUTER_TAG_VALUE_LIST2_RT_OFFSET 33734
#define NIG_REG_OUTER_TAG_VALUE_LIST3_RT_OFFSET 33735
#define NIG_REG_OUTER_TAG_VALUE_MASK_RT_OFFSET 33736
#define NIG_REG_LLH_FUNC_TAGMAC_CLS_TYPE_RT_OFFSET 33737
#define NIG_REG_LLH_FUNC_TAG_EN_RT_OFFSET 33738
#define NIG_REG_LLH_FUNC_TAG_EN_RT_SIZE 4
#define NIG_REG_LLH_FUNC_TAG_HDR_SEL_RT_OFFSET 33742
#define NIG_REG_LLH_FUNC_TAG_HDR_SEL_RT_SIZE 4
#define NIG_REG_LLH_FUNC_TAG_VALUE_RT_OFFSET 33746
#define NIG_REG_LLH_FUNC_TAG_VALUE_RT_SIZE 4
#define NIG_REG_LLH_FUNC_NO_TAG_RT_OFFSET 33750
#define NIG_REG_LLH_FUNC_FILTER_VALUE_RT_OFFSET 33751
#define NIG_REG_LLH_FUNC_FILTER_VALUE_RT_SIZE 32
#define NIG_REG_LLH_FUNC_FILTER_EN_RT_OFFSET 33783
#define NIG_REG_LLH_FUNC_FILTER_EN_RT_SIZE 16
#define NIG_REG_LLH_FUNC_FILTER_MODE_RT_OFFSET 33799
#define NIG_REG_LLH_FUNC_FILTER_MODE_RT_SIZE 16
#define NIG_REG_LLH_FUNC_FILTER_PROTOCOL_TYPE_RT_OFFSET 33815
#define NIG_REG_LLH_FUNC_FILTER_PROTOCOL_TYPE_RT_SIZE 16
#define NIG_REG_LLH_FUNC_FILTER_HDR_SEL_RT_OFFSET 33831
#define NIG_REG_LLH_FUNC_FILTER_HDR_SEL_RT_SIZE 16
#define NIG_REG_TX_EDPM_CTRL_RT_OFFSET 33847
#define NIG_REG_ROCE_DUPLICATE_TO_HOST_RT_OFFSET 33848
#define CDU_REG_CID_ADDR_PARAMS_RT_OFFSET 33849
#define CDU_REG_SEGMENT0_PARAMS_RT_OFFSET 33850
#define CDU_REG_SEGMENT1_PARAMS_RT_OFFSET 33851
#define CDU_REG_PF_SEG0_TYPE_OFFSET_RT_OFFSET 33852
#define CDU_REG_PF_SEG1_TYPE_OFFSET_RT_OFFSET 33853
#define CDU_REG_PF_SEG2_TYPE_OFFSET_RT_OFFSET 33854
#define CDU_REG_PF_SEG3_TYPE_OFFSET_RT_OFFSET 33855
#define CDU_REG_PF_FL_SEG0_TYPE_OFFSET_RT_OFFSET 33856
#define CDU_REG_PF_FL_SEG1_TYPE_OFFSET_RT_OFFSET 33857
#define CDU_REG_PF_FL_SEG2_TYPE_OFFSET_RT_OFFSET 33858
#define CDU_REG_PF_FL_SEG3_TYPE_OFFSET_RT_OFFSET 33859
#define CDU_REG_VF_SEG_TYPE_OFFSET_RT_OFFSET 33860
#define CDU_REG_VF_FL_SEG_TYPE_OFFSET_RT_OFFSET 33861
#define PBF_REG_TAG_ETHERTYPE_0_RT_OFFSET 33862
#define PBF_REG_BTB_SHARED_AREA_SIZE_RT_OFFSET 33863
#define PBF_REG_YCMD_QS_NUM_LINES_VOQ0_RT_OFFSET 33864
#define PBF_REG_BTB_GUARANTEED_VOQ0_RT_OFFSET 33865
#define PBF_REG_BTB_SHARED_AREA_SETUP_VOQ0_RT_OFFSET 33866
#define PBF_REG_YCMD_QS_NUM_LINES_VOQ1_RT_OFFSET 33867
#define PBF_REG_BTB_GUARANTEED_VOQ1_RT_OFFSET 33868
#define PBF_REG_BTB_SHARED_AREA_SETUP_VOQ1_RT_OFFSET 33869
#define PBF_REG_YCMD_QS_NUM_LINES_VOQ2_RT_OFFSET 33870
#define PBF_REG_BTB_GUARANTEED_VOQ2_RT_OFFSET 33871
#define PBF_REG_BTB_SHARED_AREA_SETUP_VOQ2_RT_OFFSET 33872
#define PBF_REG_YCMD_QS_NUM_LINES_VOQ3_RT_OFFSET 33873
#define PBF_REG_BTB_GUARANTEED_VOQ3_RT_OFFSET 33874
#define PBF_REG_BTB_SHARED_AREA_SETUP_VOQ3_RT_OFFSET 33875
#define PBF_REG_YCMD_QS_NUM_LINES_VOQ4_RT_OFFSET 33876
#define PBF_REG_BTB_GUARANTEED_VOQ4_RT_OFFSET 33877
#define PBF_REG_BTB_SHARED_AREA_SETUP_VOQ4_RT_OFFSET 33878
#define PBF_REG_YCMD_QS_NUM_LINES_VOQ5_RT_OFFSET 33879
#define PBF_REG_BTB_GUARANTEED_VOQ5_RT_OFFSET 33880
#define PBF_REG_BTB_SHARED_AREA_SETUP_VOQ5_RT_OFFSET 33881
#define PBF_REG_YCMD_QS_NUM_LINES_VOQ6_RT_OFFSET 33882
#define PBF_REG_BTB_GUARANTEED_VOQ6_RT_OFFSET 33883
#define PBF_REG_BTB_SHARED_AREA_SETUP_VOQ6_RT_OFFSET 33884
#define PBF_REG_YCMD_QS_NUM_LINES_VOQ7_RT_OFFSET 33885
#define PBF_REG_BTB_GUARANTEED_VOQ7_RT_OFFSET 33886
#define PBF_REG_BTB_SHARED_AREA_SETUP_VOQ7_RT_OFFSET 33887
#define PBF_REG_YCMD_QS_NUM_LINES_VOQ8_RT_OFFSET 33888
#define PBF_REG_BTB_GUARANTEED_VOQ8_RT_OFFSET 33889
#define PBF_REG_BTB_SHARED_AREA_SETUP_VOQ8_RT_OFFSET 33890
#define PBF_REG_YCMD_QS_NUM_LINES_VOQ9_RT_OFFSET 33891
#define PBF_REG_BTB_GUARANTEED_VOQ9_RT_OFFSET 33892
#define PBF_REG_BTB_SHARED_AREA_SETUP_VOQ9_RT_OFFSET 33893
#define PBF_REG_YCMD_QS_NUM_LINES_VOQ10_RT_OFFSET 33894
#define PBF_REG_BTB_GUARANTEED_VOQ10_RT_OFFSET 33895
#define PBF_REG_BTB_SHARED_AREA_SETUP_VOQ10_RT_OFFSET 33896
#define PBF_REG_YCMD_QS_NUM_LINES_VOQ11_RT_OFFSET 33897
#define PBF_REG_BTB_GUARANTEED_VOQ11_RT_OFFSET 33898
#define PBF_REG_BTB_SHARED_AREA_SETUP_VOQ11_RT_OFFSET 33899
#define PBF_REG_YCMD_QS_NUM_LINES_VOQ12_RT_OFFSET 33900
#define PBF_REG_BTB_GUARANTEED_VOQ12_RT_OFFSET 33901
#define PBF_REG_BTB_SHARED_AREA_SETUP_VOQ12_RT_OFFSET 33902
#define PBF_REG_YCMD_QS_NUM_LINES_VOQ13_RT_OFFSET 33903
#define PBF_REG_BTB_GUARANTEED_VOQ13_RT_OFFSET 33904
#define PBF_REG_BTB_SHARED_AREA_SETUP_VOQ13_RT_OFFSET 33905
#define PBF_REG_YCMD_QS_NUM_LINES_VOQ14_RT_OFFSET 33906
#define PBF_REG_BTB_GUARANTEED_VOQ14_RT_OFFSET 33907
#define PBF_REG_BTB_SHARED_AREA_SETUP_VOQ14_RT_OFFSET 33908
#define PBF_REG_YCMD_QS_NUM_LINES_VOQ15_RT_OFFSET 33909
#define PBF_REG_BTB_GUARANTEED_VOQ15_RT_OFFSET 33910
#define PBF_REG_BTB_SHARED_AREA_SETUP_VOQ15_RT_OFFSET 33911
#define PBF_REG_YCMD_QS_NUM_LINES_VOQ16_RT_OFFSET 33912
#define PBF_REG_BTB_GUARANTEED_VOQ16_RT_OFFSET 33913
#define PBF_REG_BTB_SHARED_AREA_SETUP_VOQ16_RT_OFFSET 33914
#define PBF_REG_YCMD_QS_NUM_LINES_VOQ17_RT_OFFSET 33915
#define PBF_REG_BTB_GUARANTEED_VOQ17_RT_OFFSET 33916
#define PBF_REG_BTB_SHARED_AREA_SETUP_VOQ17_RT_OFFSET 33917
#define PBF_REG_YCMD_QS_NUM_LINES_VOQ18_RT_OFFSET 33918
#define PBF_REG_BTB_GUARANTEED_VOQ18_RT_OFFSET 33919
#define PBF_REG_BTB_SHARED_AREA_SETUP_VOQ18_RT_OFFSET 33920
#define PBF_REG_YCMD_QS_NUM_LINES_VOQ19_RT_OFFSET 33921
#define PBF_REG_BTB_GUARANTEED_VOQ19_RT_OFFSET 33922
#define PBF_REG_BTB_SHARED_AREA_SETUP_VOQ19_RT_OFFSET 33923
#define XCM_REG_CON_PHY_Q3_RT_OFFSET 33924

#define RUNTIME_ARRAY_SIZE 33925

/* The eth storm context for the Tstorm */
struct tstorm_eth_conn_st_ctx {
	__le32 reserved[4];
};

/* The eth storm context for the Pstorm */
struct pstorm_eth_conn_st_ctx {
	__le32 reserved[8];
};

/* The eth storm context for the Xstorm */
struct xstorm_eth_conn_st_ctx {
	__le32 reserved[60];
};

struct xstorm_eth_conn_ag_ctx {
	u8 reserved0;
	u8 eth_state;
	u8 flags0;
#define XSTORM_ETH_CONN_AG_CTX_EXIST_IN_QM0_MASK	0x1
#define XSTORM_ETH_CONN_AG_CTX_EXIST_IN_QM0_SHIFT	0
#define XSTORM_ETH_CONN_AG_CTX_RESERVED1_MASK		0x1
#define XSTORM_ETH_CONN_AG_CTX_RESERVED1_SHIFT		1
#define XSTORM_ETH_CONN_AG_CTX_RESERVED2_MASK		0x1
#define XSTORM_ETH_CONN_AG_CTX_RESERVED2_SHIFT		2
#define XSTORM_ETH_CONN_AG_CTX_EXIST_IN_QM3_MASK	0x1
#define XSTORM_ETH_CONN_AG_CTX_EXIST_IN_QM3_SHIFT	3
#define XSTORM_ETH_CONN_AG_CTX_RESERVED3_MASK		0x1
#define XSTORM_ETH_CONN_AG_CTX_RESERVED3_SHIFT		4
#define XSTORM_ETH_CONN_AG_CTX_RESERVED4_MASK		0x1
#define XSTORM_ETH_CONN_AG_CTX_RESERVED4_SHIFT		5
#define XSTORM_ETH_CONN_AG_CTX_RESERVED5_MASK		0x1
#define XSTORM_ETH_CONN_AG_CTX_RESERVED5_SHIFT		6
#define XSTORM_ETH_CONN_AG_CTX_RESERVED6_MASK		0x1
#define XSTORM_ETH_CONN_AG_CTX_RESERVED6_SHIFT		7
		u8 flags1;
#define XSTORM_ETH_CONN_AG_CTX_RESERVED7_MASK		0x1
#define XSTORM_ETH_CONN_AG_CTX_RESERVED7_SHIFT		0
#define XSTORM_ETH_CONN_AG_CTX_RESERVED8_MASK		0x1
#define XSTORM_ETH_CONN_AG_CTX_RESERVED8_SHIFT		1
#define XSTORM_ETH_CONN_AG_CTX_RESERVED9_MASK		0x1
#define XSTORM_ETH_CONN_AG_CTX_RESERVED9_SHIFT		2
#define XSTORM_ETH_CONN_AG_CTX_BIT11_MASK		0x1
#define XSTORM_ETH_CONN_AG_CTX_BIT11_SHIFT		3
#define XSTORM_ETH_CONN_AG_CTX_BIT12_MASK		0x1
#define XSTORM_ETH_CONN_AG_CTX_BIT12_SHIFT		4
#define XSTORM_ETH_CONN_AG_CTX_BIT13_MASK		0x1
#define XSTORM_ETH_CONN_AG_CTX_BIT13_SHIFT		5
#define XSTORM_ETH_CONN_AG_CTX_TX_RULE_ACTIVE_MASK	0x1
#define XSTORM_ETH_CONN_AG_CTX_TX_RULE_ACTIVE_SHIFT	6
#define XSTORM_ETH_CONN_AG_CTX_DQ_CF_ACTIVE_MASK	0x1
#define XSTORM_ETH_CONN_AG_CTX_DQ_CF_ACTIVE_SHIFT	7
	u8 flags2;
#define XSTORM_ETH_CONN_AG_CTX_CF0_MASK		0x3
#define XSTORM_ETH_CONN_AG_CTX_CF0_SHIFT		0
#define XSTORM_ETH_CONN_AG_CTX_CF1_MASK		0x3
#define XSTORM_ETH_CONN_AG_CTX_CF1_SHIFT		2
#define XSTORM_ETH_CONN_AG_CTX_CF2_MASK		0x3
#define XSTORM_ETH_CONN_AG_CTX_CF2_SHIFT		4
#define XSTORM_ETH_CONN_AG_CTX_CF3_MASK		0x3
#define XSTORM_ETH_CONN_AG_CTX_CF3_SHIFT		6
	u8 flags3;
#define XSTORM_ETH_CONN_AG_CTX_CF4_MASK		0x3
#define XSTORM_ETH_CONN_AG_CTX_CF4_SHIFT		0
#define XSTORM_ETH_CONN_AG_CTX_CF5_MASK		0x3
#define XSTORM_ETH_CONN_AG_CTX_CF5_SHIFT		2
#define XSTORM_ETH_CONN_AG_CTX_CF6_MASK		0x3
#define XSTORM_ETH_CONN_AG_CTX_CF6_SHIFT		4
#define XSTORM_ETH_CONN_AG_CTX_CF7_MASK		0x3
#define XSTORM_ETH_CONN_AG_CTX_CF7_SHIFT		6
		u8 flags4;
#define XSTORM_ETH_CONN_AG_CTX_CF8_MASK		0x3
#define XSTORM_ETH_CONN_AG_CTX_CF8_SHIFT		0
#define XSTORM_ETH_CONN_AG_CTX_CF9_MASK		0x3
#define XSTORM_ETH_CONN_AG_CTX_CF9_SHIFT		2
#define XSTORM_ETH_CONN_AG_CTX_CF10_MASK		0x3
#define XSTORM_ETH_CONN_AG_CTX_CF10_SHIFT		4
#define XSTORM_ETH_CONN_AG_CTX_CF11_MASK		0x3
#define XSTORM_ETH_CONN_AG_CTX_CF11_SHIFT		6
	u8 flags5;
#define XSTORM_ETH_CONN_AG_CTX_CF12_MASK		0x3
#define XSTORM_ETH_CONN_AG_CTX_CF12_SHIFT		0
#define XSTORM_ETH_CONN_AG_CTX_CF13_MASK		0x3
#define XSTORM_ETH_CONN_AG_CTX_CF13_SHIFT		2
#define XSTORM_ETH_CONN_AG_CTX_CF14_MASK		0x3
#define XSTORM_ETH_CONN_AG_CTX_CF14_SHIFT		4
#define XSTORM_ETH_CONN_AG_CTX_CF15_MASK		0x3
#define XSTORM_ETH_CONN_AG_CTX_CF15_SHIFT		6
	u8 flags6;
#define XSTORM_ETH_CONN_AG_CTX_GO_TO_BD_CONS_CF_MASK	0x3
#define XSTORM_ETH_CONN_AG_CTX_GO_TO_BD_CONS_CF_SHIFT	0
#define XSTORM_ETH_CONN_AG_CTX_MULTI_UNICAST_CF_MASK	0x3
#define XSTORM_ETH_CONN_AG_CTX_MULTI_UNICAST_CF_SHIFT	2
#define XSTORM_ETH_CONN_AG_CTX_DQ_CF_MASK		0x3
#define XSTORM_ETH_CONN_AG_CTX_DQ_CF_SHIFT		4
#define XSTORM_ETH_CONN_AG_CTX_TERMINATE_CF_MASK	0x3
#define XSTORM_ETH_CONN_AG_CTX_TERMINATE_CF_SHIFT	6
	u8 flags7;
#define XSTORM_ETH_CONN_AG_CTX_FLUSH_Q0_MASK		0x3
#define XSTORM_ETH_CONN_AG_CTX_FLUSH_Q0_SHIFT		0
#define XSTORM_ETH_CONN_AG_CTX_RESERVED10_MASK		0x3
#define XSTORM_ETH_CONN_AG_CTX_RESERVED10_SHIFT		2
#define XSTORM_ETH_CONN_AG_CTX_SLOW_PATH_MASK		0x3
#define XSTORM_ETH_CONN_AG_CTX_SLOW_PATH_SHIFT		4
#define XSTORM_ETH_CONN_AG_CTX_CF0EN_MASK		0x1
#define XSTORM_ETH_CONN_AG_CTX_CF0EN_SHIFT		6
#define XSTORM_ETH_CONN_AG_CTX_CF1EN_MASK		0x1
#define XSTORM_ETH_CONN_AG_CTX_CF1EN_SHIFT		7
	u8 flags8;
#define XSTORM_ETH_CONN_AG_CTX_CF2EN_MASK		0x1
#define XSTORM_ETH_CONN_AG_CTX_CF2EN_SHIFT		0
#define XSTORM_ETH_CONN_AG_CTX_CF3EN_MASK		0x1
#define XSTORM_ETH_CONN_AG_CTX_CF3EN_SHIFT		1
#define XSTORM_ETH_CONN_AG_CTX_CF4EN_MASK		0x1
#define XSTORM_ETH_CONN_AG_CTX_CF4EN_SHIFT		2
#define XSTORM_ETH_CONN_AG_CTX_CF5EN_MASK		0x1
#define XSTORM_ETH_CONN_AG_CTX_CF5EN_SHIFT		3
#define XSTORM_ETH_CONN_AG_CTX_CF6EN_MASK		0x1
#define XSTORM_ETH_CONN_AG_CTX_CF6EN_SHIFT		4
#define XSTORM_ETH_CONN_AG_CTX_CF7EN_MASK		0x1
#define XSTORM_ETH_CONN_AG_CTX_CF7EN_SHIFT		5
#define XSTORM_ETH_CONN_AG_CTX_CF8EN_MASK		0x1
#define XSTORM_ETH_CONN_AG_CTX_CF8EN_SHIFT		6
#define XSTORM_ETH_CONN_AG_CTX_CF9EN_MASK		0x1
#define XSTORM_ETH_CONN_AG_CTX_CF9EN_SHIFT		7
	u8 flags9;
#define XSTORM_ETH_CONN_AG_CTX_CF10EN_MASK		0x1
#define XSTORM_ETH_CONN_AG_CTX_CF10EN_SHIFT		0
#define XSTORM_ETH_CONN_AG_CTX_CF11EN_MASK		0x1
#define XSTORM_ETH_CONN_AG_CTX_CF11EN_SHIFT		1
#define XSTORM_ETH_CONN_AG_CTX_CF12EN_MASK		0x1
#define XSTORM_ETH_CONN_AG_CTX_CF12EN_SHIFT		2
#define XSTORM_ETH_CONN_AG_CTX_CF13EN_MASK		0x1
#define XSTORM_ETH_CONN_AG_CTX_CF13EN_SHIFT		3
#define XSTORM_ETH_CONN_AG_CTX_CF14EN_MASK		0x1
#define XSTORM_ETH_CONN_AG_CTX_CF14EN_SHIFT		4
#define XSTORM_ETH_CONN_AG_CTX_CF15EN_MASK		0x1
#define XSTORM_ETH_CONN_AG_CTX_CF15EN_SHIFT		5
#define XSTORM_ETH_CONN_AG_CTX_GO_TO_BD_CONS_CF_EN_MASK	0x1
#define XSTORM_ETH_CONN_AG_CTX_GO_TO_BD_CONS_CF_EN_SHIFT 6
#define XSTORM_ETH_CONN_AG_CTX_MULTI_UNICAST_CF_EN_MASK	0x1
#define XSTORM_ETH_CONN_AG_CTX_MULTI_UNICAST_CF_EN_SHIFT 7
	u8 flags10;
#define XSTORM_ETH_CONN_AG_CTX_DQ_CF_EN_MASK		0x1
#define XSTORM_ETH_CONN_AG_CTX_DQ_CF_EN_SHIFT		0
#define XSTORM_ETH_CONN_AG_CTX_TERMINATE_CF_EN_MASK	0x1
#define XSTORM_ETH_CONN_AG_CTX_TERMINATE_CF_EN_SHIFT	1
#define XSTORM_ETH_CONN_AG_CTX_FLUSH_Q0_EN_MASK		0x1
#define XSTORM_ETH_CONN_AG_CTX_FLUSH_Q0_EN_SHIFT	2
#define XSTORM_ETH_CONN_AG_CTX_RESERVED11_MASK		0x1
#define XSTORM_ETH_CONN_AG_CTX_RESERVED11_SHIFT		3
#define XSTORM_ETH_CONN_AG_CTX_SLOW_PATH_EN_MASK	0x1
#define XSTORM_ETH_CONN_AG_CTX_SLOW_PATH_EN_SHIFT	4
#define XSTORM_ETH_CONN_AG_CTX_TPH_ENABLE_EN_RESERVED_MASK 0x1
#define XSTORM_ETH_CONN_AG_CTX_TPH_ENABLE_EN_RESERVED_SHIFT 5
#define XSTORM_ETH_CONN_AG_CTX_RESERVED12_MASK		0x1
#define XSTORM_ETH_CONN_AG_CTX_RESERVED12_SHIFT		6
#define XSTORM_ETH_CONN_AG_CTX_RESERVED13_MASK		0x1
#define XSTORM_ETH_CONN_AG_CTX_RESERVED13_SHIFT		7
	u8 flags11;
#define XSTORM_ETH_CONN_AG_CTX_RESERVED14_MASK		0x1
#define XSTORM_ETH_CONN_AG_CTX_RESERVED14_SHIFT		0
#define XSTORM_ETH_CONN_AG_CTX_RESERVED15_MASK		0x1
#define XSTORM_ETH_CONN_AG_CTX_RESERVED15_SHIFT		1
#define XSTORM_ETH_CONN_AG_CTX_TX_DEC_RULE_EN_MASK	0x1
#define XSTORM_ETH_CONN_AG_CTX_TX_DEC_RULE_EN_SHIFT	2
#define XSTORM_ETH_CONN_AG_CTX_RULE5EN_MASK		0x1
#define XSTORM_ETH_CONN_AG_CTX_RULE5EN_SHIFT		3
#define XSTORM_ETH_CONN_AG_CTX_RULE6EN_MASK		0x1
#define XSTORM_ETH_CONN_AG_CTX_RULE6EN_SHIFT		4
#define XSTORM_ETH_CONN_AG_CTX_RULE7EN_MASK		0x1
#define XSTORM_ETH_CONN_AG_CTX_RULE7EN_SHIFT		5
#define XSTORM_ETH_CONN_AG_CTX_A0_RESERVED1_MASK	0x1
#define XSTORM_ETH_CONN_AG_CTX_A0_RESERVED1_SHIFT	6
#define XSTORM_ETH_CONN_AG_CTX_RULE9EN_MASK		0x1
#define XSTORM_ETH_CONN_AG_CTX_RULE9EN_SHIFT		7
	u8 flags12;
#define XSTORM_ETH_CONN_AG_CTX_RULE10EN_MASK		0x1
#define XSTORM_ETH_CONN_AG_CTX_RULE10EN_SHIFT		0
#define XSTORM_ETH_CONN_AG_CTX_RULE11EN_MASK		0x1
#define XSTORM_ETH_CONN_AG_CTX_RULE11EN_SHIFT		1
#define XSTORM_ETH_CONN_AG_CTX_A0_RESERVED2_MASK	0x1
#define XSTORM_ETH_CONN_AG_CTX_A0_RESERVED2_SHIFT	2
#define XSTORM_ETH_CONN_AG_CTX_A0_RESERVED3_MASK	0x1
#define XSTORM_ETH_CONN_AG_CTX_A0_RESERVED3_SHIFT	3
#define XSTORM_ETH_CONN_AG_CTX_RULE14EN_MASK		0x1
#define XSTORM_ETH_CONN_AG_CTX_RULE14EN_SHIFT		4
#define XSTORM_ETH_CONN_AG_CTX_RULE15EN_MASK		0x1
#define XSTORM_ETH_CONN_AG_CTX_RULE15EN_SHIFT		5
#define XSTORM_ETH_CONN_AG_CTX_RULE16EN_MASK		0x1
#define XSTORM_ETH_CONN_AG_CTX_RULE16EN_SHIFT		6
#define XSTORM_ETH_CONN_AG_CTX_RULE17EN_MASK		0x1
#define XSTORM_ETH_CONN_AG_CTX_RULE17EN_SHIFT		7
	u8 flags13;
#define XSTORM_ETH_CONN_AG_CTX_RULE18EN_MASK		0x1
#define XSTORM_ETH_CONN_AG_CTX_RULE18EN_SHIFT		0
#define XSTORM_ETH_CONN_AG_CTX_RULE19EN_MASK		0x1
#define XSTORM_ETH_CONN_AG_CTX_RULE19EN_SHIFT		1
#define XSTORM_ETH_CONN_AG_CTX_A0_RESERVED4_MASK	0x1
#define XSTORM_ETH_CONN_AG_CTX_A0_RESERVED4_SHIFT	2
#define XSTORM_ETH_CONN_AG_CTX_A0_RESERVED5_MASK	0x1
#define XSTORM_ETH_CONN_AG_CTX_A0_RESERVED5_SHIFT	3
#define XSTORM_ETH_CONN_AG_CTX_A0_RESERVED6_MASK	0x1
#define XSTORM_ETH_CONN_AG_CTX_A0_RESERVED6_SHIFT	4
#define XSTORM_ETH_CONN_AG_CTX_A0_RESERVED7_MASK	0x1
#define XSTORM_ETH_CONN_AG_CTX_A0_RESERVED7_SHIFT	5
#define XSTORM_ETH_CONN_AG_CTX_A0_RESERVED8_MASK	0x1
#define XSTORM_ETH_CONN_AG_CTX_A0_RESERVED8_SHIFT	6
#define XSTORM_ETH_CONN_AG_CTX_A0_RESERVED9_MASK	0x1
#define XSTORM_ETH_CONN_AG_CTX_A0_RESERVED9_SHIFT	7
	u8 flags14;
#define XSTORM_ETH_CONN_AG_CTX_EDPM_USE_EXT_HDR_MASK	0x1
#define XSTORM_ETH_CONN_AG_CTX_EDPM_USE_EXT_HDR_SHIFT	0
#define XSTORM_ETH_CONN_AG_CTX_EDPM_SEND_RAW_L3L4_MASK	0x1
#define XSTORM_ETH_CONN_AG_CTX_EDPM_SEND_RAW_L3L4_SHIFT	1
#define XSTORM_ETH_CONN_AG_CTX_EDPM_INBAND_PROP_HDR_MASK 0x1
#define XSTORM_ETH_CONN_AG_CTX_EDPM_INBAND_PROP_HDR_SHIFT 2
#define XSTORM_ETH_CONN_AG_CTX_EDPM_SEND_EXT_TUNNEL_MASK 0x1
#define XSTORM_ETH_CONN_AG_CTX_EDPM_SEND_EXT_TUNNEL_SHIFT 3
#define XSTORM_ETH_CONN_AG_CTX_L2_EDPM_ENABLE_MASK	0x1
#define XSTORM_ETH_CONN_AG_CTX_L2_EDPM_ENABLE_SHIFT	4
#define XSTORM_ETH_CONN_AG_CTX_ROCE_EDPM_ENABLE_MASK	0x1
#define XSTORM_ETH_CONN_AG_CTX_ROCE_EDPM_ENABLE_SHIFT	5
#define XSTORM_ETH_CONN_AG_CTX_TPH_ENABLE_MASK		0x3
#define XSTORM_ETH_CONN_AG_CTX_TPH_ENABLE_SHIFT		6
	u8 edpm_event_id;
	__le16 physical_q0;
	__le16 quota;
	__le16 edpm_num_bds;
	__le16 tx_bd_cons;
	__le16 tx_bd_prod;
	__le16 tx_class;
	__le16 conn_dpi;
	u8 byte3;
	u8 byte4;
	u8 byte5;
	u8 byte6;
	__le32 reg0;
	__le32 reg1;
	__le32 reg2;
	__le32 reg3;
	__le32 reg4;
	__le32 reg5;
	__le32 reg6;
	__le16 word7;
	__le16 word8;
	__le16 word9;
	__le16 word10;
	__le32 reg7;
	__le32 reg8;
	__le32 reg9;
	u8 byte7;
	u8 byte8;
	u8 byte9;
	u8 byte10;
	u8 byte11;
	u8 byte12;
	u8 byte13;
	u8 byte14;
	u8 byte15;
	u8 byte16;
	__le16 word11;
	__le32 reg10;
	__le32 reg11;
	__le32 reg12;
	__le32 reg13;
	__le32 reg14;
	__le32 reg15;
	__le32 reg16;
	__le32 reg17;
	__le32 reg18;
	__le32 reg19;
	__le16 word12;
	__le16 word13;
	__le16 word14;
	__le16 word15;
};

/* The eth storm context for the Ystorm */
struct ystorm_eth_conn_st_ctx {
	__le32 reserved[8];
};

struct ystorm_eth_conn_ag_ctx {
	u8 byte0;
	u8 state;
	u8 flags0;
#define YSTORM_ETH_CONN_AG_CTX_BIT0_MASK		0x1
#define YSTORM_ETH_CONN_AG_CTX_BIT0_SHIFT		0
#define YSTORM_ETH_CONN_AG_CTX_BIT1_MASK		0x1
#define YSTORM_ETH_CONN_AG_CTX_BIT1_SHIFT		1
#define YSTORM_ETH_CONN_AG_CTX_TX_BD_CONS_UPD_CF_MASK	0x3
#define YSTORM_ETH_CONN_AG_CTX_TX_BD_CONS_UPD_CF_SHIFT	2
#define YSTORM_ETH_CONN_AG_CTX_PMD_TERMINATE_CF_MASK	0x3
#define YSTORM_ETH_CONN_AG_CTX_PMD_TERMINATE_CF_SHIFT	4
#define YSTORM_ETH_CONN_AG_CTX_CF2_MASK			0x3
#define YSTORM_ETH_CONN_AG_CTX_CF2_SHIFT		6
	u8 flags1;
#define YSTORM_ETH_CONN_AG_CTX_TX_BD_CONS_UPD_CF_EN_MASK	0x1
#define YSTORM_ETH_CONN_AG_CTX_TX_BD_CONS_UPD_CF_EN_SHIFT	0
#define YSTORM_ETH_CONN_AG_CTX_PMD_TERMINATE_CF_EN_MASK		0x1
#define YSTORM_ETH_CONN_AG_CTX_PMD_TERMINATE_CF_EN_SHIFT	1
#define YSTORM_ETH_CONN_AG_CTX_CF2EN_MASK			0x1
#define YSTORM_ETH_CONN_AG_CTX_CF2EN_SHIFT			2
#define YSTORM_ETH_CONN_AG_CTX_RULE0EN_MASK			0x1
#define YSTORM_ETH_CONN_AG_CTX_RULE0EN_SHIFT			3
#define YSTORM_ETH_CONN_AG_CTX_RULE1EN_MASK			0x1
#define YSTORM_ETH_CONN_AG_CTX_RULE1EN_SHIFT			4
#define YSTORM_ETH_CONN_AG_CTX_RULE2EN_MASK			0x1
#define YSTORM_ETH_CONN_AG_CTX_RULE2EN_SHIFT			5
#define YSTORM_ETH_CONN_AG_CTX_RULE3EN_MASK			0x1
#define YSTORM_ETH_CONN_AG_CTX_RULE3EN_SHIFT			6
#define YSTORM_ETH_CONN_AG_CTX_RULE4EN_MASK			0x1
#define YSTORM_ETH_CONN_AG_CTX_RULE4EN_SHIFT			7
	u8 tx_q0_int_coallecing_timeset;
	u8 byte3;
	__le16 word0;
	__le32 terminate_spqe;
	__le32 reg1;
	__le16 tx_bd_cons_upd;
	__le16 word2;
	__le16 word3;
	__le16 word4;
	__le32 reg2;
	__le32 reg3;
};

struct tstorm_eth_conn_ag_ctx {
	u8 byte0;
	u8 byte1;
	u8 flags0;
#define TSTORM_ETH_CONN_AG_CTX_BIT0_MASK		0x1
#define TSTORM_ETH_CONN_AG_CTX_BIT0_SHIFT		0
#define TSTORM_ETH_CONN_AG_CTX_BIT1_MASK		0x1
#define TSTORM_ETH_CONN_AG_CTX_BIT1_SHIFT		1
#define TSTORM_ETH_CONN_AG_CTX_BIT2_MASK		0x1
#define TSTORM_ETH_CONN_AG_CTX_BIT2_SHIFT		2
#define TSTORM_ETH_CONN_AG_CTX_BIT3_MASK		0x1
#define TSTORM_ETH_CONN_AG_CTX_BIT3_SHIFT		3
#define TSTORM_ETH_CONN_AG_CTX_BIT4_MASK		0x1
#define TSTORM_ETH_CONN_AG_CTX_BIT4_SHIFT		4
#define TSTORM_ETH_CONN_AG_CTX_BIT5_MASK		0x1
#define TSTORM_ETH_CONN_AG_CTX_BIT5_SHIFT		5
#define TSTORM_ETH_CONN_AG_CTX_CF0_MASK			0x3
#define TSTORM_ETH_CONN_AG_CTX_CF0_SHIFT		6
	u8 flags1;
#define TSTORM_ETH_CONN_AG_CTX_CF1_MASK			0x3
#define TSTORM_ETH_CONN_AG_CTX_CF1_SHIFT		0
#define TSTORM_ETH_CONN_AG_CTX_CF2_MASK			0x3
#define TSTORM_ETH_CONN_AG_CTX_CF2_SHIFT		2
#define TSTORM_ETH_CONN_AG_CTX_CF3_MASK			0x3
#define TSTORM_ETH_CONN_AG_CTX_CF3_SHIFT		4
#define TSTORM_ETH_CONN_AG_CTX_CF4_MASK			0x3
#define TSTORM_ETH_CONN_AG_CTX_CF4_SHIFT		6
	u8 flags2;
#define TSTORM_ETH_CONN_AG_CTX_CF5_MASK			0x3
#define TSTORM_ETH_CONN_AG_CTX_CF5_SHIFT		0
#define TSTORM_ETH_CONN_AG_CTX_CF6_MASK			0x3
#define TSTORM_ETH_CONN_AG_CTX_CF6_SHIFT		2
#define TSTORM_ETH_CONN_AG_CTX_CF7_MASK			0x3
#define TSTORM_ETH_CONN_AG_CTX_CF7_SHIFT		4
#define TSTORM_ETH_CONN_AG_CTX_CF8_MASK			0x3
#define TSTORM_ETH_CONN_AG_CTX_CF8_SHIFT		6
	u8 flags3;
#define TSTORM_ETH_CONN_AG_CTX_CF9_MASK			0x3
#define TSTORM_ETH_CONN_AG_CTX_CF9_SHIFT		0
#define TSTORM_ETH_CONN_AG_CTX_CF10_MASK		0x3
#define TSTORM_ETH_CONN_AG_CTX_CF10_SHIFT		2
#define TSTORM_ETH_CONN_AG_CTX_CF0EN_MASK		0x1
#define TSTORM_ETH_CONN_AG_CTX_CF0EN_SHIFT		4
#define TSTORM_ETH_CONN_AG_CTX_CF1EN_MASK		0x1
#define TSTORM_ETH_CONN_AG_CTX_CF1EN_SHIFT		5
#define TSTORM_ETH_CONN_AG_CTX_CF2EN_MASK		0x1
#define TSTORM_ETH_CONN_AG_CTX_CF2EN_SHIFT		6
#define TSTORM_ETH_CONN_AG_CTX_CF3EN_MASK		0x1
#define TSTORM_ETH_CONN_AG_CTX_CF3EN_SHIFT		7
	u8 flags4;
#define TSTORM_ETH_CONN_AG_CTX_CF4EN_MASK		0x1
#define TSTORM_ETH_CONN_AG_CTX_CF4EN_SHIFT		0
#define TSTORM_ETH_CONN_AG_CTX_CF5EN_MASK		0x1
#define TSTORM_ETH_CONN_AG_CTX_CF5EN_SHIFT		1
#define TSTORM_ETH_CONN_AG_CTX_CF6EN_MASK		0x1
#define TSTORM_ETH_CONN_AG_CTX_CF6EN_SHIFT		2
#define TSTORM_ETH_CONN_AG_CTX_CF7EN_MASK		0x1
#define TSTORM_ETH_CONN_AG_CTX_CF7EN_SHIFT		3
#define TSTORM_ETH_CONN_AG_CTX_CF8EN_MASK		0x1
#define TSTORM_ETH_CONN_AG_CTX_CF8EN_SHIFT		4
#define TSTORM_ETH_CONN_AG_CTX_CF9EN_MASK		0x1
#define TSTORM_ETH_CONN_AG_CTX_CF9EN_SHIFT		5
#define TSTORM_ETH_CONN_AG_CTX_CF10EN_MASK		0x1
#define TSTORM_ETH_CONN_AG_CTX_CF10EN_SHIFT		6
#define TSTORM_ETH_CONN_AG_CTX_RULE0EN_MASK		0x1
#define TSTORM_ETH_CONN_AG_CTX_RULE0EN_SHIFT		7
	u8 flags5;
#define TSTORM_ETH_CONN_AG_CTX_RULE1EN_MASK		0x1
#define TSTORM_ETH_CONN_AG_CTX_RULE1EN_SHIFT		0
#define TSTORM_ETH_CONN_AG_CTX_RULE2EN_MASK		0x1
#define TSTORM_ETH_CONN_AG_CTX_RULE2EN_SHIFT		1
#define TSTORM_ETH_CONN_AG_CTX_RULE3EN_MASK		0x1
#define TSTORM_ETH_CONN_AG_CTX_RULE3EN_SHIFT		2
#define TSTORM_ETH_CONN_AG_CTX_RULE4EN_MASK		0x1
#define TSTORM_ETH_CONN_AG_CTX_RULE4EN_SHIFT		3
#define TSTORM_ETH_CONN_AG_CTX_RULE5EN_MASK		0x1
#define TSTORM_ETH_CONN_AG_CTX_RULE5EN_SHIFT		4
#define TSTORM_ETH_CONN_AG_CTX_RX_BD_EN_MASK		0x1
#define TSTORM_ETH_CONN_AG_CTX_RX_BD_EN_SHIFT		5
#define TSTORM_ETH_CONN_AG_CTX_RULE7EN_MASK		0x1
#define TSTORM_ETH_CONN_AG_CTX_RULE7EN_SHIFT		6
#define TSTORM_ETH_CONN_AG_CTX_RULE8EN_MASK		0x1
#define TSTORM_ETH_CONN_AG_CTX_RULE8EN_SHIFT		7
	__le32 reg0;
	__le32 reg1;
	__le32 reg2;
	__le32 reg3;
	__le32 reg4;
	__le32 reg5;
	__le32 reg6;
	__le32 reg7;
	__le32 reg8;
	u8 byte2;
	u8 byte3;
	__le16 rx_bd_cons;
	u8 byte4;
	u8 byte5;
	__le16 rx_bd_prod;
	__le16 word2;
	__le16 word3;
	__le32 reg9;
	__le32 reg10;
};

struct ustorm_eth_conn_ag_ctx {
	u8 byte0;
	u8 byte1;
	u8 flags0;
#define USTORM_ETH_CONN_AG_CTX_BIT0_MASK			0x1
#define USTORM_ETH_CONN_AG_CTX_BIT0_SHIFT			0
#define USTORM_ETH_CONN_AG_CTX_BIT1_MASK			0x1
#define USTORM_ETH_CONN_AG_CTX_BIT1_SHIFT			1
#define USTORM_ETH_CONN_AG_CTX_TX_PMD_TERMINATE_CF_MASK		0x3
#define USTORM_ETH_CONN_AG_CTX_TX_PMD_TERMINATE_CF_SHIFT	2
#define USTORM_ETH_CONN_AG_CTX_RX_PMD_TERMINATE_CF_MASK		0x3
#define USTORM_ETH_CONN_AG_CTX_RX_PMD_TERMINATE_CF_SHIFT	4
#define USTORM_ETH_CONN_AG_CTX_CF2_MASK				0x3
#define USTORM_ETH_CONN_AG_CTX_CF2_SHIFT			6
	u8 flags1;
#define USTORM_ETH_CONN_AG_CTX_CF3_MASK				0x3
#define USTORM_ETH_CONN_AG_CTX_CF3_SHIFT			0
#define USTORM_ETH_CONN_AG_CTX_TX_ARM_CF_MASK			0x3
#define USTORM_ETH_CONN_AG_CTX_TX_ARM_CF_SHIFT			2
#define USTORM_ETH_CONN_AG_CTX_RX_ARM_CF_MASK			0x3
#define USTORM_ETH_CONN_AG_CTX_RX_ARM_CF_SHIFT			4
#define USTORM_ETH_CONN_AG_CTX_TX_BD_CONS_UPD_CF_MASK		0x3
#define USTORM_ETH_CONN_AG_CTX_TX_BD_CONS_UPD_CF_SHIFT		6
	u8 flags2;
#define USTORM_ETH_CONN_AG_CTX_TX_PMD_TERMINATE_CF_EN_MASK	0x1
#define USTORM_ETH_CONN_AG_CTX_TX_PMD_TERMINATE_CF_EN_SHIFT	0
#define USTORM_ETH_CONN_AG_CTX_RX_PMD_TERMINATE_CF_EN_MASK	0x1
#define USTORM_ETH_CONN_AG_CTX_RX_PMD_TERMINATE_CF_EN_SHIFT	1
#define USTORM_ETH_CONN_AG_CTX_CF2EN_MASK			0x1
#define USTORM_ETH_CONN_AG_CTX_CF2EN_SHIFT			2
#define USTORM_ETH_CONN_AG_CTX_CF3EN_MASK			0x1
#define USTORM_ETH_CONN_AG_CTX_CF3EN_SHIFT			3
#define USTORM_ETH_CONN_AG_CTX_TX_ARM_CF_EN_MASK		0x1
#define USTORM_ETH_CONN_AG_CTX_TX_ARM_CF_EN_SHIFT		4
#define USTORM_ETH_CONN_AG_CTX_RX_ARM_CF_EN_MASK		0x1
#define USTORM_ETH_CONN_AG_CTX_RX_ARM_CF_EN_SHIFT		5
#define USTORM_ETH_CONN_AG_CTX_TX_BD_CONS_UPD_CF_EN_MASK	0x1
#define USTORM_ETH_CONN_AG_CTX_TX_BD_CONS_UPD_CF_EN_SHIFT	6
#define USTORM_ETH_CONN_AG_CTX_RULE0EN_MASK			0x1
#define USTORM_ETH_CONN_AG_CTX_RULE0EN_SHIFT			7
	u8 flags3;
#define USTORM_ETH_CONN_AG_CTX_RULE1EN_MASK			0x1
#define USTORM_ETH_CONN_AG_CTX_RULE1EN_SHIFT			0
#define USTORM_ETH_CONN_AG_CTX_RULE2EN_MASK			0x1
#define USTORM_ETH_CONN_AG_CTX_RULE2EN_SHIFT			1
#define USTORM_ETH_CONN_AG_CTX_RULE3EN_MASK			0x1
#define USTORM_ETH_CONN_AG_CTX_RULE3EN_SHIFT			2
#define USTORM_ETH_CONN_AG_CTX_RULE4EN_MASK			0x1
#define USTORM_ETH_CONN_AG_CTX_RULE4EN_SHIFT			3
#define USTORM_ETH_CONN_AG_CTX_RULE5EN_MASK			0x1
#define USTORM_ETH_CONN_AG_CTX_RULE5EN_SHIFT			4
#define USTORM_ETH_CONN_AG_CTX_RULE6EN_MASK			0x1
#define USTORM_ETH_CONN_AG_CTX_RULE6EN_SHIFT			5
#define USTORM_ETH_CONN_AG_CTX_RULE7EN_MASK			0x1
#define USTORM_ETH_CONN_AG_CTX_RULE7EN_SHIFT			6
#define USTORM_ETH_CONN_AG_CTX_RULE8EN_MASK			0x1
#define USTORM_ETH_CONN_AG_CTX_RULE8EN_SHIFT			7
	u8 byte2;
	u8 byte3;
	__le16 word0;
	__le16 tx_bd_cons;
	__le32 reg0;
	__le32 reg1;
	__le32 reg2;
	__le32 tx_int_coallecing_timeset;
	__le16 tx_drv_bd_cons;
	__le16 rx_drv_cqe_cons;
};

/* The eth storm context for the Ustorm */
struct ustorm_eth_conn_st_ctx {
	__le32 reserved[40];
};

/* The eth storm context for the Mstorm */
struct mstorm_eth_conn_st_ctx {
	__le32 reserved[8];
};

/* eth connection context */
struct eth_conn_context {
	struct tstorm_eth_conn_st_ctx tstorm_st_context;
	struct regpair tstorm_st_padding[2];
	struct pstorm_eth_conn_st_ctx pstorm_st_context;
	struct xstorm_eth_conn_st_ctx xstorm_st_context;
	struct xstorm_eth_conn_ag_ctx xstorm_ag_context;
	struct ystorm_eth_conn_st_ctx ystorm_st_context;
	struct ystorm_eth_conn_ag_ctx ystorm_ag_context;
	struct tstorm_eth_conn_ag_ctx tstorm_ag_context;
	struct ustorm_eth_conn_ag_ctx ustorm_ag_context;
	struct ustorm_eth_conn_st_ctx ustorm_st_context;
	struct mstorm_eth_conn_st_ctx mstorm_st_context;
};

/* opcodes for the event ring */
enum eth_event_opcode {
	ETH_EVENT_UNUSED,
	ETH_EVENT_VPORT_START,
	ETH_EVENT_VPORT_UPDATE,
	ETH_EVENT_VPORT_STOP,
	ETH_EVENT_TX_QUEUE_START,
	ETH_EVENT_TX_QUEUE_STOP,
	ETH_EVENT_RX_QUEUE_START,
	ETH_EVENT_RX_QUEUE_UPDATE,
	ETH_EVENT_RX_QUEUE_STOP,
	ETH_EVENT_FILTERS_UPDATE,
	ETH_EVENT_RESERVED,
	ETH_EVENT_RESERVED2,
	ETH_EVENT_RESERVED3,
	ETH_EVENT_RX_ADD_UDP_FILTER,
	ETH_EVENT_RX_DELETE_UDP_FILTER,
	ETH_EVENT_RESERVED4,
	ETH_EVENT_RESERVED5,
	MAX_ETH_EVENT_OPCODE
};

/* Classify rule types in E2/E3 */
enum eth_filter_action {
	ETH_FILTER_ACTION_UNUSED,
	ETH_FILTER_ACTION_REMOVE,
	ETH_FILTER_ACTION_ADD,
	ETH_FILTER_ACTION_REMOVE_ALL,
	MAX_ETH_FILTER_ACTION
};

/* Command for adding/removing a classification rule $$KEEP_ENDIANNESS$$ */
struct eth_filter_cmd {
	u8 type;
	u8 vport_id;
	u8 action;
	u8 reserved0;
	__le32 vni;
	__le16 mac_lsb;
	__le16 mac_mid;
	__le16 mac_msb;
	__le16 vlan_id;
};

/*	$$KEEP_ENDIANNESS$$ */
struct eth_filter_cmd_header {
	u8 rx;
	u8 tx;
	u8 cmd_cnt;
	u8 assert_on_error;
	u8 reserved1[4];
};

/* Ethernet filter types: mac/vlan/pair */
enum eth_filter_type {
	ETH_FILTER_TYPE_UNUSED,
	ETH_FILTER_TYPE_MAC,
	ETH_FILTER_TYPE_VLAN,
	ETH_FILTER_TYPE_PAIR,
	ETH_FILTER_TYPE_INNER_MAC,
	ETH_FILTER_TYPE_INNER_VLAN,
	ETH_FILTER_TYPE_INNER_PAIR,
	ETH_FILTER_TYPE_INNER_MAC_VNI_PAIR,
	ETH_FILTER_TYPE_MAC_VNI_PAIR,
	ETH_FILTER_TYPE_VNI,
	MAX_ETH_FILTER_TYPE
};

/* Ethernet Ramrod Command IDs */
enum eth_ramrod_cmd_id {
	ETH_RAMROD_UNUSED,
	ETH_RAMROD_VPORT_START,
	ETH_RAMROD_VPORT_UPDATE,
	ETH_RAMROD_VPORT_STOP,
	ETH_RAMROD_RX_QUEUE_START,
	ETH_RAMROD_RX_QUEUE_STOP,
	ETH_RAMROD_TX_QUEUE_START,
	ETH_RAMROD_TX_QUEUE_STOP,
	ETH_RAMROD_FILTERS_UPDATE,
	ETH_RAMROD_RX_QUEUE_UPDATE,
	ETH_RAMROD_RX_CREATE_OPENFLOW_ACTION,
	ETH_RAMROD_RX_ADD_OPENFLOW_FILTER,
	ETH_RAMROD_RX_DELETE_OPENFLOW_FILTER,
	ETH_RAMROD_RX_ADD_UDP_FILTER,
	ETH_RAMROD_RX_DELETE_UDP_FILTER,
	ETH_RAMROD_RX_CREATE_GFT_ACTION,
	ETH_RAMROD_GFT_UPDATE_FILTER,
	MAX_ETH_RAMROD_CMD_ID
};

/* return code from eth sp ramrods */
struct eth_return_code {
	u8 value;
#define ETH_RETURN_CODE_ERR_CODE_MASK	0x1F
#define ETH_RETURN_CODE_ERR_CODE_SHIFT	0
#define ETH_RETURN_CODE_RESERVED_MASK	0x3
#define ETH_RETURN_CODE_RESERVED_SHIFT	5
#define ETH_RETURN_CODE_RX_TX_MASK	0x1
#define ETH_RETURN_CODE_RX_TX_SHIFT	7
};

/* What to do in case an error occurs */
enum eth_tx_err {
	ETH_TX_ERR_DROP,
	ETH_TX_ERR_ASSERT_MALICIOUS,
	MAX_ETH_TX_ERR
};

/* Array of the different error type behaviors */
struct eth_tx_err_vals {
	__le16 values;
#define ETH_TX_ERR_VALS_ILLEGAL_VLAN_MODE_MASK			0x1
#define ETH_TX_ERR_VALS_ILLEGAL_VLAN_MODE_SHIFT			0
#define ETH_TX_ERR_VALS_PACKET_TOO_SMALL_MASK			0x1
#define ETH_TX_ERR_VALS_PACKET_TOO_SMALL_SHIFT			1
#define ETH_TX_ERR_VALS_ANTI_SPOOFING_ERR_MASK			0x1
#define ETH_TX_ERR_VALS_ANTI_SPOOFING_ERR_SHIFT			2
#define ETH_TX_ERR_VALS_ILLEGAL_INBAND_TAGS_MASK		0x1
#define ETH_TX_ERR_VALS_ILLEGAL_INBAND_TAGS_SHIFT		3
#define ETH_TX_ERR_VALS_VLAN_INSERTION_W_INBAND_TAG_MASK	0x1
#define ETH_TX_ERR_VALS_VLAN_INSERTION_W_INBAND_TAG_SHIFT	4
#define ETH_TX_ERR_VALS_MTU_VIOLATION_MASK			0x1
#define ETH_TX_ERR_VALS_MTU_VIOLATION_SHIFT			5
#define ETH_TX_ERR_VALS_ILLEGAL_CONTROL_FRAME_MASK		0x1
#define ETH_TX_ERR_VALS_ILLEGAL_CONTROL_FRAME_SHIFT		6
#define ETH_TX_ERR_VALS_RESERVED_MASK				0x1FF
#define ETH_TX_ERR_VALS_RESERVED_SHIFT				7
};

/* vport rss configuration data */
struct eth_vport_rss_config {
	__le16 capabilities;
#define ETH_VPORT_RSS_CONFIG_IPV4_CAPABILITY_MASK		0x1
#define ETH_VPORT_RSS_CONFIG_IPV4_CAPABILITY_SHIFT		0
#define ETH_VPORT_RSS_CONFIG_IPV6_CAPABILITY_MASK		0x1
#define ETH_VPORT_RSS_CONFIG_IPV6_CAPABILITY_SHIFT		1
#define ETH_VPORT_RSS_CONFIG_IPV4_TCP_CAPABILITY_MASK		0x1
#define ETH_VPORT_RSS_CONFIG_IPV4_TCP_CAPABILITY_SHIFT		2
#define ETH_VPORT_RSS_CONFIG_IPV6_TCP_CAPABILITY_MASK		0x1
#define ETH_VPORT_RSS_CONFIG_IPV6_TCP_CAPABILITY_SHIFT		3
#define ETH_VPORT_RSS_CONFIG_IPV4_UDP_CAPABILITY_MASK		0x1
#define ETH_VPORT_RSS_CONFIG_IPV4_UDP_CAPABILITY_SHIFT		4
#define ETH_VPORT_RSS_CONFIG_IPV6_UDP_CAPABILITY_MASK		0x1
#define ETH_VPORT_RSS_CONFIG_IPV6_UDP_CAPABILITY_SHIFT		5
#define ETH_VPORT_RSS_CONFIG_EN_5_TUPLE_CAPABILITY_MASK		0x1
#define ETH_VPORT_RSS_CONFIG_EN_5_TUPLE_CAPABILITY_SHIFT	6
#define ETH_VPORT_RSS_CONFIG_RESERVED0_MASK			0x1FF
#define ETH_VPORT_RSS_CONFIG_RESERVED0_SHIFT			7
	u8 rss_id;
	u8 rss_mode;
	u8 update_rss_key;
	u8 update_rss_ind_table;
	u8 update_rss_capabilities;
	u8 tbl_size;
	__le32 reserved2[2];
	__le16 indirection_table[ETH_RSS_IND_TABLE_ENTRIES_NUM];

	__le32 rss_key[ETH_RSS_KEY_SIZE_REGS];
	__le32 reserved3[2];
};

/* eth vport RSS mode */
enum eth_vport_rss_mode {
	ETH_VPORT_RSS_MODE_DISABLED,
	ETH_VPORT_RSS_MODE_REGULAR,
	MAX_ETH_VPORT_RSS_MODE
};

/* Command for setting classification flags for a vport $$KEEP_ENDIANNESS$$ */
struct eth_vport_rx_mode {
	__le16 state;
#define ETH_VPORT_RX_MODE_UCAST_DROP_ALL_MASK		0x1
#define ETH_VPORT_RX_MODE_UCAST_DROP_ALL_SHIFT		0
#define ETH_VPORT_RX_MODE_UCAST_ACCEPT_ALL_MASK		0x1
#define ETH_VPORT_RX_MODE_UCAST_ACCEPT_ALL_SHIFT	1
#define ETH_VPORT_RX_MODE_UCAST_ACCEPT_UNMATCHED_MASK	0x1
#define ETH_VPORT_RX_MODE_UCAST_ACCEPT_UNMATCHED_SHIFT	2
#define ETH_VPORT_RX_MODE_MCAST_DROP_ALL_MASK		0x1
#define ETH_VPORT_RX_MODE_MCAST_DROP_ALL_SHIFT		3
#define ETH_VPORT_RX_MODE_MCAST_ACCEPT_ALL_MASK		0x1
#define ETH_VPORT_RX_MODE_MCAST_ACCEPT_ALL_SHIFT	4
#define ETH_VPORT_RX_MODE_BCAST_ACCEPT_ALL_MASK		0x1
#define ETH_VPORT_RX_MODE_BCAST_ACCEPT_ALL_SHIFT	5
#define ETH_VPORT_RX_MODE_RESERVED1_MASK		0x3FF
#define ETH_VPORT_RX_MODE_RESERVED1_SHIFT		6
	__le16 reserved2[3];
};

/* Command for setting tpa parameters */
struct eth_vport_tpa_param {
	u8 tpa_ipv4_en_flg;
	u8 tpa_ipv6_en_flg;
	u8 tpa_ipv4_tunn_en_flg;
	u8 tpa_ipv6_tunn_en_flg;
	u8 tpa_pkt_split_flg;
	u8 tpa_hdr_data_split_flg;
	u8 tpa_gro_consistent_flg;

	u8 tpa_max_aggs_num;

	__le16 tpa_max_size;
	__le16 tpa_min_size_to_start;

	__le16 tpa_min_size_to_cont;
	u8 max_buff_num;
	u8 reserved;
};

/* Command for setting classification flags for a vport $$KEEP_ENDIANNESS$$ */
struct eth_vport_tx_mode {
	__le16 state;
#define ETH_VPORT_TX_MODE_UCAST_DROP_ALL_MASK		0x1
#define ETH_VPORT_TX_MODE_UCAST_DROP_ALL_SHIFT		0
#define ETH_VPORT_TX_MODE_UCAST_ACCEPT_ALL_MASK		0x1
#define ETH_VPORT_TX_MODE_UCAST_ACCEPT_ALL_SHIFT	1
#define ETH_VPORT_TX_MODE_MCAST_DROP_ALL_MASK		0x1
#define ETH_VPORT_TX_MODE_MCAST_DROP_ALL_SHIFT		2
#define ETH_VPORT_TX_MODE_MCAST_ACCEPT_ALL_MASK		0x1
#define ETH_VPORT_TX_MODE_MCAST_ACCEPT_ALL_SHIFT	3
#define ETH_VPORT_TX_MODE_BCAST_ACCEPT_ALL_MASK		0x1
#define ETH_VPORT_TX_MODE_BCAST_ACCEPT_ALL_SHIFT	4
#define ETH_VPORT_TX_MODE_RESERVED1_MASK		0x7FF
#define ETH_VPORT_TX_MODE_RESERVED1_SHIFT		5
	__le16 reserved2[3];
};

/* Ramrod data for rx queue start ramrod */
struct rx_queue_start_ramrod_data {
	__le16 rx_queue_id;
	__le16 num_of_pbl_pages;
	__le16 bd_max_bytes;
	__le16 sb_id;
	u8 sb_index;
	u8 vport_id;
	u8 default_rss_queue_flg;
	u8 complete_cqe_flg;
	u8 complete_event_flg;
	u8 stats_counter_id;
	u8 pin_context;
	u8 pxp_tph_valid_bd;
	u8 pxp_tph_valid_pkt;
	u8 pxp_st_hint;

	__le16 pxp_st_index;
	u8 pmd_mode;

	u8 notify_en;
	u8 toggle_val;

	u8 vf_rx_prod_index;

	u8 reserved[6];
	__le16 reserved1;
	struct regpair cqe_pbl_addr;
	struct regpair bd_base;
	struct regpair reserved2;
};

/* Ramrod data for rx queue start ramrod */
struct rx_queue_stop_ramrod_data {
	__le16 rx_queue_id;
	u8 complete_cqe_flg;
	u8 complete_event_flg;
	u8 vport_id;
	u8 reserved[3];
};

/* Ramrod data for rx queue update ramrod */
struct rx_queue_update_ramrod_data {
	__le16 rx_queue_id;
	u8 complete_cqe_flg;
	u8 complete_event_flg;
	u8 vport_id;
	u8 reserved[4];
	u8 reserved1;
	u8 reserved2;
	u8 reserved3;
	__le16 reserved4;
	__le16 reserved5;
	struct regpair reserved6;
};

/* Ramrod data for rx Add UDP Filter */
struct rx_udp_filter_data {
	__le16 action_icid;
	__le16 vlan_id;
	u8 ip_type;
	u8 tenant_id_exists;
	__le16 reserved1;
	__le32 ip_dst_addr[4];
	__le32 ip_src_addr[4];
	__le16 udp_dst_port;
	__le16 udp_src_port;
	__le32 tenant_id;
};

/* Ramrod data for rx queue start ramrod */
struct tx_queue_start_ramrod_data {
	__le16 sb_id;
	u8 sb_index;
	u8 vport_id;
	u8 reserved0;
	u8 stats_counter_id;
	__le16 qm_pq_id;
	u8 flags;
#define TX_QUEUE_START_RAMROD_DATA_DISABLE_OPPORTUNISTIC_MASK	0x1
#define TX_QUEUE_START_RAMROD_DATA_DISABLE_OPPORTUNISTIC_SHIFT	0
#define TX_QUEUE_START_RAMROD_DATA_TEST_MODE_PKT_DUP_MASK	0x1
#define TX_QUEUE_START_RAMROD_DATA_TEST_MODE_PKT_DUP_SHIFT	1
#define TX_QUEUE_START_RAMROD_DATA_TEST_MODE_TX_DEST_MASK	0x1
#define TX_QUEUE_START_RAMROD_DATA_TEST_MODE_TX_DEST_SHIFT	2
#define TX_QUEUE_START_RAMROD_DATA_PMD_MODE_MASK		0x1
#define TX_QUEUE_START_RAMROD_DATA_PMD_MODE_SHIFT		3
#define TX_QUEUE_START_RAMROD_DATA_NOTIFY_EN_MASK		0x1
#define TX_QUEUE_START_RAMROD_DATA_NOTIFY_EN_SHIFT		4
#define TX_QUEUE_START_RAMROD_DATA_PIN_CONTEXT_MASK		0x1
#define TX_QUEUE_START_RAMROD_DATA_PIN_CONTEXT_SHIFT		5
#define TX_QUEUE_START_RAMROD_DATA_RESERVED1_MASK		0x3
#define TX_QUEUE_START_RAMROD_DATA_RESERVED1_SHIFT		6
	u8 pxp_st_hint;
	u8 pxp_tph_valid_bd;
	u8 pxp_tph_valid_pkt;
	__le16 pxp_st_index;
	__le16 comp_agg_size;
	__le16 queue_zone_id;
	__le16 test_dup_count;
	__le16 pbl_size;
	__le16 tx_queue_id;

	struct regpair pbl_base_addr;
	struct regpair bd_cons_address;
};

/* Ramrod data for tx queue stop ramrod */
struct tx_queue_stop_ramrod_data {
	__le16 reserved[4];
};

/* Ramrod data for vport update ramrod */
struct vport_filter_update_ramrod_data {
	struct eth_filter_cmd_header filter_cmd_hdr;
	struct eth_filter_cmd filter_cmds[ETH_FILTER_RULES_COUNT];
};

/* Ramrod data for vport start ramrod */
struct vport_start_ramrod_data {
	u8 vport_id;
	u8 sw_fid;
	__le16 mtu;
	u8 drop_ttl0_en;
	u8 inner_vlan_removal_en;
	struct eth_vport_rx_mode rx_mode;
	struct eth_vport_tx_mode tx_mode;
	struct eth_vport_tpa_param tpa_param;
	__le16 default_vlan;
	u8 tx_switching_en;
	u8 anti_spoofing_en;

	u8 default_vlan_en;

	u8 handle_ptp_pkts;
	u8 silent_vlan_removal_en;
	u8 untagged;
	struct eth_tx_err_vals tx_err_behav;

	u8 zero_placement_offset;
	u8 ctl_frame_mac_check_en;
	u8 ctl_frame_ethtype_check_en;
	u8 reserved[5];
};

/* Ramrod data for vport stop ramrod */
struct vport_stop_ramrod_data {
	u8 vport_id;
	u8 reserved[7];
};

/* Ramrod data for vport update ramrod */
struct vport_update_ramrod_data_cmn {
	u8 vport_id;
	u8 update_rx_active_flg;
	u8 rx_active_flg;
	u8 update_tx_active_flg;
	u8 tx_active_flg;
	u8 update_rx_mode_flg;
	u8 update_tx_mode_flg;
	u8 update_approx_mcast_flg;

	u8 update_rss_flg;
	u8 update_inner_vlan_removal_en_flg;

	u8 inner_vlan_removal_en;
	u8 update_tpa_param_flg;
	u8 update_tpa_en_flg;
	u8 update_tx_switching_en_flg;

	u8 tx_switching_en;
	u8 update_anti_spoofing_en_flg;

	u8 anti_spoofing_en;
	u8 update_handle_ptp_pkts;

	u8 handle_ptp_pkts;
	u8 update_default_vlan_en_flg;

	u8 default_vlan_en;

	u8 update_default_vlan_flg;

	__le16 default_vlan;
	u8 update_accept_any_vlan_flg;

	u8 accept_any_vlan;
	u8 silent_vlan_removal_en;
	u8 update_mtu_flg;

	__le16 mtu;
	u8 reserved[2];
};

struct vport_update_ramrod_mcast {
	__le32 bins[ETH_MULTICAST_MAC_BINS_IN_REGS];
};

/* Ramrod data for vport update ramrod */
struct vport_update_ramrod_data {
	struct vport_update_ramrod_data_cmn common;

	struct eth_vport_rx_mode rx_mode;
	struct eth_vport_tx_mode tx_mode;
	struct eth_vport_tpa_param tpa_param;
	struct vport_update_ramrod_mcast approx_mcast;
	struct eth_vport_rss_config rss_config;
};

#define VF_MAX_STATIC 192

#define MCP_GLOB_PATH_MAX	2
#define MCP_PORT_MAX		2
#define MCP_GLOB_PORT_MAX	4
#define MCP_GLOB_FUNC_MAX	16

/* Offset from the beginning of the MCP scratchpad */
#define OFFSIZE_OFFSET_SHIFT	0
#define OFFSIZE_OFFSET_MASK	0x0000ffff
/* Size of specific element (not the whole array if any) */
#define OFFSIZE_SIZE_SHIFT	16
#define OFFSIZE_SIZE_MASK	0xffff0000

#define SECTION_OFFSET(_offsize) ((((_offsize &			\
				     OFFSIZE_OFFSET_MASK) >>	\
				    OFFSIZE_OFFSET_SHIFT) << 2))

#define QED_SECTION_SIZE(_offsize) (((_offsize &		\
				      OFFSIZE_SIZE_MASK) >>	\
				     OFFSIZE_SIZE_SHIFT) << 2)

#define SECTION_ADDR(_offsize, idx) (MCP_REG_SCRATCH +			\
				     SECTION_OFFSET(_offsize) +		\
				     (QED_SECTION_SIZE(_offsize) * idx))

#define SECTION_OFFSIZE_ADDR(_pub_base, _section)	\
	(_pub_base + offsetof(struct mcp_public_data, sections[_section]))

/* PHY configuration */
struct eth_phy_cfg {
	u32 speed;
#define ETH_SPEED_AUTONEG	0
#define ETH_SPEED_SMARTLINQ	0x8

	u32 pause;
#define ETH_PAUSE_NONE		0x0
#define ETH_PAUSE_AUTONEG	0x1
#define ETH_PAUSE_RX		0x2
#define ETH_PAUSE_TX		0x4

	u32 adv_speed;
	u32 loopback_mode;
#define ETH_LOOPBACK_NONE		(0)
#define ETH_LOOPBACK_INT_PHY		(1)
#define ETH_LOOPBACK_EXT_PHY		(2)
#define ETH_LOOPBACK_EXT		(3)
#define ETH_LOOPBACK_MAC		(4)

	u32 feature_config_flags;
#define ETH_EEE_MODE_ADV_LPI		(1 << 0)
};

struct port_mf_cfg {
	u32 dynamic_cfg;
#define PORT_MF_CFG_OV_TAG_MASK		0x0000ffff
#define PORT_MF_CFG_OV_TAG_SHIFT	0
#define PORT_MF_CFG_OV_TAG_DEFAULT	PORT_MF_CFG_OV_TAG_MASK

	u32 reserved[1];
};

struct eth_stats {
	u64 r64;
	u64 r127;
	u64 r255;
	u64 r511;
	u64 r1023;
	u64 r1518;
	u64 r1522;
	u64 r2047;
	u64 r4095;
	u64 r9216;
	u64 r16383;
	u64 rfcs;
	u64 rxcf;
	u64 rxpf;
	u64 rxpp;
	u64 raln;
	u64 rfcr;
	u64 rovr;
	u64 rjbr;
	u64 rund;
	u64 rfrg;
	u64 t64;
	u64 t127;
	u64 t255;
	u64 t511;
	u64 t1023;
	u64 t1518;
	u64 t2047;
	u64 t4095;
	u64 t9216;
	u64 t16383;
	u64 txpf;
	u64 txpp;
	u64 tlpiec;
	u64 tncl;
	u64 rbyte;
	u64 rxuca;
	u64 rxmca;
	u64 rxbca;
	u64 rxpok;
	u64 tbyte;
	u64 txuca;
	u64 txmca;
	u64 txbca;
	u64 txcf;
};

struct brb_stats {
	u64 brb_truncate[8];
	u64 brb_discard[8];
};

struct port_stats {
	struct brb_stats brb;
	struct eth_stats eth;
};

struct couple_mode_teaming {
	u8 port_cmt[MCP_GLOB_PORT_MAX];
#define PORT_CMT_IN_TEAM	(1 << 0)

#define PORT_CMT_PORT_ROLE	(1 << 1)
#define PORT_CMT_PORT_INACTIVE	(0 << 1)
#define PORT_CMT_PORT_ACTIVE	(1 << 1)

#define PORT_CMT_TEAM_MASK	(1 << 2)
#define PORT_CMT_TEAM0		(0 << 2)
#define PORT_CMT_TEAM1		(1 << 2)
};

#define LLDP_CHASSIS_ID_STAT_LEN	4
#define LLDP_PORT_ID_STAT_LEN		4
#define DCBX_MAX_APP_PROTOCOL		32
#define MAX_SYSTEM_LLDP_TLV_DATA	32

enum _lldp_agent {
	LLDP_NEAREST_BRIDGE = 0,
	LLDP_NEAREST_NON_TPMR_BRIDGE,
	LLDP_NEAREST_CUSTOMER_BRIDGE,
	LLDP_MAX_LLDP_AGENTS
};

struct lldp_config_params_s {
	u32 config;
#define LLDP_CONFIG_TX_INTERVAL_MASK	0x000000ff
#define LLDP_CONFIG_TX_INTERVAL_SHIFT	0
#define LLDP_CONFIG_HOLD_MASK		0x00000f00
#define LLDP_CONFIG_HOLD_SHIFT		8
#define LLDP_CONFIG_MAX_CREDIT_MASK	0x0000f000
#define LLDP_CONFIG_MAX_CREDIT_SHIFT	12
#define LLDP_CONFIG_ENABLE_RX_MASK	0x40000000
#define LLDP_CONFIG_ENABLE_RX_SHIFT	30
#define LLDP_CONFIG_ENABLE_TX_MASK	0x80000000
#define LLDP_CONFIG_ENABLE_TX_SHIFT	31
	u32 local_chassis_id[LLDP_CHASSIS_ID_STAT_LEN];
	u32 local_port_id[LLDP_PORT_ID_STAT_LEN];
};

struct lldp_status_params_s {
	u32 prefix_seq_num;
	u32 status;
	u32 peer_chassis_id[LLDP_CHASSIS_ID_STAT_LEN];
	u32 peer_port_id[LLDP_PORT_ID_STAT_LEN];
	u32 suffix_seq_num;
};

struct dcbx_ets_feature {
	u32 flags;
#define DCBX_ETS_ENABLED_MASK	0x00000001
#define DCBX_ETS_ENABLED_SHIFT	0
#define DCBX_ETS_WILLING_MASK	0x00000002
#define DCBX_ETS_WILLING_SHIFT	1
#define DCBX_ETS_ERROR_MASK	0x00000004
#define DCBX_ETS_ERROR_SHIFT	2
#define DCBX_ETS_CBS_MASK	0x00000008
#define DCBX_ETS_CBS_SHIFT	3
#define DCBX_ETS_MAX_TCS_MASK	0x000000f0
#define DCBX_ETS_MAX_TCS_SHIFT	4
#define DCBX_ISCSI_OOO_TC_MASK	0x00000f00
#define DCBX_ISCSI_OOO_TC_SHIFT	8
	u32 pri_tc_tbl[1];
#define DCBX_ISCSI_OOO_TC	(4)

#define NIG_ETS_ISCSI_OOO_CLIENT_OFFSET	(DCBX_ISCSI_OOO_TC + 1)
#define DCBX_CEE_STRICT_PRIORITY	0xf
	u32 tc_bw_tbl[2];
	u32 tc_tsa_tbl[2];
#define DCBX_ETS_TSA_STRICT	0
#define DCBX_ETS_TSA_CBS	1
#define DCBX_ETS_TSA_ETS	2
};

struct dcbx_app_priority_entry {
	u32 entry;
#define DCBX_APP_PRI_MAP_MASK		0x000000ff
#define DCBX_APP_PRI_MAP_SHIFT		0
#define DCBX_APP_PRI_0			0x01
#define DCBX_APP_PRI_1			0x02
#define DCBX_APP_PRI_2			0x04
#define DCBX_APP_PRI_3			0x08
#define DCBX_APP_PRI_4			0x10
#define DCBX_APP_PRI_5			0x20
#define DCBX_APP_PRI_6			0x40
#define DCBX_APP_PRI_7			0x80
#define DCBX_APP_SF_MASK		0x00000300
#define DCBX_APP_SF_SHIFT		8
#define DCBX_APP_SF_ETHTYPE		0
#define DCBX_APP_SF_PORT		1
#define DCBX_APP_PROTOCOL_ID_MASK	0xffff0000
#define DCBX_APP_PROTOCOL_ID_SHIFT	16
};

struct dcbx_app_priority_feature {
	u32 flags;
#define DCBX_APP_ENABLED_MASK		0x00000001
#define DCBX_APP_ENABLED_SHIFT		0
#define DCBX_APP_WILLING_MASK		0x00000002
#define DCBX_APP_WILLING_SHIFT		1
#define DCBX_APP_ERROR_MASK		0x00000004
#define DCBX_APP_ERROR_SHIFT		2
#define DCBX_APP_MAX_TCS_MASK		0x0000f000
#define DCBX_APP_MAX_TCS_SHIFT		12
#define DCBX_APP_NUM_ENTRIES_MASK	0x00ff0000
#define DCBX_APP_NUM_ENTRIES_SHIFT	16
	struct dcbx_app_priority_entry app_pri_tbl[DCBX_MAX_APP_PROTOCOL];
};

struct dcbx_features {
	struct dcbx_ets_feature ets;
	u32 pfc;
#define DCBX_PFC_PRI_EN_BITMAP_MASK	0x000000ff
#define DCBX_PFC_PRI_EN_BITMAP_SHIFT	0
#define DCBX_PFC_PRI_EN_BITMAP_PRI_0	0x01
#define DCBX_PFC_PRI_EN_BITMAP_PRI_1	0x02
#define DCBX_PFC_PRI_EN_BITMAP_PRI_2	0x04
#define DCBX_PFC_PRI_EN_BITMAP_PRI_3	0x08
#define DCBX_PFC_PRI_EN_BITMAP_PRI_4	0x10
#define DCBX_PFC_PRI_EN_BITMAP_PRI_5	0x20
#define DCBX_PFC_PRI_EN_BITMAP_PRI_6	0x40
#define DCBX_PFC_PRI_EN_BITMAP_PRI_7	0x80

#define DCBX_PFC_FLAGS_MASK		0x0000ff00
#define DCBX_PFC_FLAGS_SHIFT		8
#define DCBX_PFC_CAPS_MASK		0x00000f00
#define DCBX_PFC_CAPS_SHIFT		8
#define DCBX_PFC_MBC_MASK		0x00004000
#define DCBX_PFC_MBC_SHIFT		14
#define DCBX_PFC_WILLING_MASK		0x00008000
#define DCBX_PFC_WILLING_SHIFT		15
#define DCBX_PFC_ENABLED_MASK		0x00010000
#define DCBX_PFC_ENABLED_SHIFT		16
#define DCBX_PFC_ERROR_MASK		0x00020000
#define DCBX_PFC_ERROR_SHIFT		17
	struct dcbx_app_priority_feature app;
};

struct dcbx_local_params {
	u32 config;
#define DCBX_CONFIG_VERSION_MASK	0x00000007
#define DCBX_CONFIG_VERSION_SHIFT	0
#define DCBX_CONFIG_VERSION_DISABLED	0
#define DCBX_CONFIG_VERSION_IEEE	1
#define DCBX_CONFIG_VERSION_CEE		2
#define DCBX_CONFIG_VERSION_STATIC	4

	u32 flags;
	struct dcbx_features features;
};

struct dcbx_mib {
	u32 prefix_seq_num;
	u32 flags;
	struct dcbx_features features;
	u32 suffix_seq_num;
};

struct lldp_system_tlvs_buffer_s {
	u16 valid;
	u16 length;
	u32 data[MAX_SYSTEM_LLDP_TLV_DATA];
};

struct dcb_dscp_map {
	u32 flags;
#define DCB_DSCP_ENABLE_MASK	0x1
#define DCB_DSCP_ENABLE_SHIFT	0
#define DCB_DSCP_ENABLE	1
	u32 dscp_pri_map[8];
};

struct public_global {
	u32 max_path;
	u32 max_ports;
	u32 debug_mb_offset;
	u32 phymod_dbg_mb_offset;
	struct couple_mode_teaming cmt;
	s32 internal_temperature;
	u32 mfw_ver;
	u32 running_bundle_id;
	s32 external_temperature;
	u32 mdump_reason;
};
 
struct fw_flr_mb {
	u32 aggint;
	u32 opgen_addr;
	u32 accum_ack;
};

struct public_path {
	struct fw_flr_mb flr_mb;
	u32 mcp_vf_disabled[VF_MAX_STATIC / 32];

	u32 process_kill;
#define PROCESS_KILL_COUNTER_MASK	0x0000ffff
#define PROCESS_KILL_COUNTER_SHIFT	0
#define PROCESS_KILL_GLOB_AEU_BIT_MASK	0xffff0000
#define PROCESS_KILL_GLOB_AEU_BIT_SHIFT	16
#define GLOBAL_AEU_BIT(aeu_reg_id, aeu_bit) (aeu_reg_id * 32 + aeu_bit)
};

struct public_port {
	u32 validity_map;
	u32 link_status;
#define LINK_STATUS_LINK_UP			0x00000001
#define LINK_STATUS_SPEED_AND_DUPLEX_MASK	0x0000001e
#define LINK_STATUS_SPEED_AND_DUPLEX_1000THD	(1 << 1)
#define LINK_STATUS_SPEED_AND_DUPLEX_1000TFD	(2 << 1)
#define LINK_STATUS_SPEED_AND_DUPLEX_10G	(3 << 1)
#define LINK_STATUS_SPEED_AND_DUPLEX_20G	(4 << 1)
#define LINK_STATUS_SPEED_AND_DUPLEX_40G	(5 << 1)
#define LINK_STATUS_SPEED_AND_DUPLEX_50G	(6 << 1)
#define LINK_STATUS_SPEED_AND_DUPLEX_100G	(7 << 1)
#define LINK_STATUS_SPEED_AND_DUPLEX_25G	(8 << 1)

#define LINK_STATUS_AUTO_NEGOTIATE_ENABLED	0x00000020

#define LINK_STATUS_AUTO_NEGOTIATE_COMPLETE	0x00000040
#define LINK_STATUS_PARALLEL_DETECTION_USED	0x00000080

#define LINK_STATUS_PFC_ENABLED				0x00000100
#define LINK_STATUS_LINK_PARTNER_1000TFD_CAPABLE 0x00000200
#define LINK_STATUS_LINK_PARTNER_1000THD_CAPABLE 0x00000400
#define LINK_STATUS_LINK_PARTNER_10G_CAPABLE		0x00000800
#define LINK_STATUS_LINK_PARTNER_20G_CAPABLE		0x00001000
#define LINK_STATUS_LINK_PARTNER_40G_CAPABLE		0x00002000
#define LINK_STATUS_LINK_PARTNER_50G_CAPABLE		0x00004000
#define LINK_STATUS_LINK_PARTNER_100G_CAPABLE		0x00008000
#define LINK_STATUS_LINK_PARTNER_25G_CAPABLE		0x00010000

#define LINK_STATUS_LINK_PARTNER_FLOW_CONTROL_MASK	0x000C0000
#define LINK_STATUS_LINK_PARTNER_NOT_PAUSE_CAPABLE	(0 << 18)
#define LINK_STATUS_LINK_PARTNER_SYMMETRIC_PAUSE	(1 << 18)
#define LINK_STATUS_LINK_PARTNER_ASYMMETRIC_PAUSE	(2 << 18)
#define LINK_STATUS_LINK_PARTNER_BOTH_PAUSE		(3 << 18)

#define LINK_STATUS_SFP_TX_FAULT			0x00100000
#define LINK_STATUS_TX_FLOW_CONTROL_ENABLED		0x00200000
#define LINK_STATUS_RX_FLOW_CONTROL_ENABLED		0x00400000
#define LINK_STATUS_RX_SIGNAL_PRESENT			0x00800000
#define LINK_STATUS_MAC_LOCAL_FAULT			0x01000000
#define LINK_STATUS_MAC_REMOTE_FAULT			0x02000000
#define LINK_STATUS_UNSUPPORTED_SPD_REQ			0x04000000

	u32 link_status1;
	u32 ext_phy_fw_version;
	u32 drv_phy_cfg_addr;

	u32 port_stx;

	u32 stat_nig_timer;

	struct port_mf_cfg port_mf_config;
	struct port_stats stats;

	u32 media_type;
#define MEDIA_UNSPECIFIED	0x0
#define MEDIA_SFPP_10G_FIBER	0x1
#define MEDIA_XFP_FIBER		0x2
#define MEDIA_DA_TWINAX		0x3
#define MEDIA_BASE_T		0x4
#define MEDIA_SFP_1G_FIBER	0x5
#define MEDIA_MODULE_FIBER	0x6
#define MEDIA_KR		0xf0
#define MEDIA_NOT_PRESENT	0xff

	u32 lfa_status;
	u32 link_change_count;

	struct lldp_config_params_s lldp_config_params[LLDP_MAX_LLDP_AGENTS];
	struct lldp_status_params_s lldp_status_params[LLDP_MAX_LLDP_AGENTS];
	struct lldp_system_tlvs_buffer_s system_lldp_tlvs_buf;

	/* DCBX related MIB */
	struct dcbx_local_params local_admin_dcbx_mib;
	struct dcbx_mib remote_dcbx_mib;
	struct dcbx_mib operational_dcbx_mib;
	u32 reserved[2];
	u32 transceiver_data;
#define ETH_TRANSCEIVER_STATE_MASK	0x000000FF
#define ETH_TRANSCEIVER_STATE_SHIFT	0x00000000
#define ETH_TRANSCEIVER_STATE_UNPLUGGED	0x00000000
#define ETH_TRANSCEIVER_STATE_PRESENT	0x00000001
#define ETH_TRANSCEIVER_STATE_VALID	0x00000003
#define ETH_TRANSCEIVER_STATE_UPDATING	0x00000008
	u32 wol_info;
	u32 wol_pkt_len;
	u32 wol_pkt_details;
	struct dcb_dscp_map dcb_dscp_map;
};

struct public_func {
	u32 reserved0[2];
	u32 mtu_size;

	u32 reserved[7];

	u32 config;
#define FUNC_MF_CFG_FUNC_HIDE			0x00000001
#define FUNC_MF_CFG_PAUSE_ON_HOST_RING		0x00000002
#define FUNC_MF_CFG_PAUSE_ON_HOST_RING_SHIFT	0x00000001

#define FUNC_MF_CFG_PROTOCOL_MASK	0x000000f0
#define FUNC_MF_CFG_PROTOCOL_SHIFT	4
#define FUNC_MF_CFG_PROTOCOL_ETHERNET	0x00000000
#define FUNC_MF_CFG_PROTOCOL_MAX	0x00000030

#define FUNC_MF_CFG_MIN_BW_MASK		0x0000ff00
#define FUNC_MF_CFG_MIN_BW_SHIFT	8
#define FUNC_MF_CFG_MIN_BW_DEFAULT	0x00000000
#define FUNC_MF_CFG_MAX_BW_MASK		0x00ff0000
#define FUNC_MF_CFG_MAX_BW_SHIFT	16
#define FUNC_MF_CFG_MAX_BW_DEFAULT	0x00640000

	u32 status;
#define FUNC_STATUS_VLINK_DOWN		0x00000001

	u32 mac_upper;
#define FUNC_MF_CFG_UPPERMAC_MASK	0x0000ffff
#define FUNC_MF_CFG_UPPERMAC_SHIFT	0
#define FUNC_MF_CFG_UPPERMAC_DEFAULT	FUNC_MF_CFG_UPPERMAC_MASK
	u32 mac_lower;
#define FUNC_MF_CFG_LOWERMAC_DEFAULT	0xffffffff

	u32 fcoe_wwn_port_name_upper;
	u32 fcoe_wwn_port_name_lower;

	u32 fcoe_wwn_node_name_upper;
	u32 fcoe_wwn_node_name_lower;

	u32 ovlan_stag;
#define FUNC_MF_CFG_OV_STAG_MASK	0x0000ffff
#define FUNC_MF_CFG_OV_STAG_SHIFT	0
#define FUNC_MF_CFG_OV_STAG_DEFAULT	FUNC_MF_CFG_OV_STAG_MASK

	u32 pf_allocation;

	u32 preserve_data;

	u32 driver_last_activity_ts;

	u32 drv_ack_vf_disabled[VF_MAX_STATIC / 32];

	u32 drv_id;
#define DRV_ID_PDA_COMP_VER_MASK	0x0000ffff
#define DRV_ID_PDA_COMP_VER_SHIFT	0

#define DRV_ID_MCP_HSI_VER_MASK		0x00ff0000
#define DRV_ID_MCP_HSI_VER_SHIFT	16
#define DRV_ID_MCP_HSI_VER_CURRENT	(1 << DRV_ID_MCP_HSI_VER_SHIFT)

#define DRV_ID_DRV_TYPE_MASK		0x7f000000
#define DRV_ID_DRV_TYPE_SHIFT		24
#define DRV_ID_DRV_TYPE_UNKNOWN		(0 << DRV_ID_DRV_TYPE_SHIFT)
#define DRV_ID_DRV_TYPE_LINUX		(1 << DRV_ID_DRV_TYPE_SHIFT)

#define DRV_ID_DRV_INIT_HW_MASK		0x80000000
#define DRV_ID_DRV_INIT_HW_SHIFT	31
#define DRV_ID_DRV_INIT_HW_FLAG		(1 << DRV_ID_DRV_INIT_HW_SHIFT)
};
 
struct mcp_mac {
	u32 mac_upper;
	u32 mac_lower;
};

struct mcp_val64 {
	u32 lo;
	u32 hi;
};

struct mcp_file_att {
	u32 nvm_start_addr;
	u32 len;
};

struct bist_nvm_image_att {
	u32 return_code;
	u32 image_type;
	u32 nvm_start_addr;
	u32 len;
};

#define MCP_DRV_VER_STR_SIZE 16
#define MCP_DRV_VER_STR_SIZE_DWORD (MCP_DRV_VER_STR_SIZE / sizeof(u32))
#define MCP_DRV_NVM_BUF_LEN 32
struct drv_version_stc {
	u32 version;
	u8 name[MCP_DRV_VER_STR_SIZE - 4];
};

struct lan_stats_stc {
	u64 ucast_rx_pkts;
	u64 ucast_tx_pkts;
	u32 fcs_err;
	u32 rserved;
};

struct ocbb_data_stc {
	u32 ocbb_host_addr;
	u32 ocsd_host_addr;
	u32 ocsd_req_update_interval;
};

#define MAX_NUM_OF_SENSORS 7
struct temperature_status_stc {
	u32 num_of_sensors;
	u32 sensor[MAX_NUM_OF_SENSORS];
};

/* crash dump configuration header */
struct mdump_config_stc {
	u32 version;
	u32 config;
	u32 epoc;
	u32 num_of_logs;
	u32 valid_logs;
};

union drv_union_data {
	u32 ver_str[MCP_DRV_VER_STR_SIZE_DWORD];
	struct mcp_mac wol_mac;

	struct eth_phy_cfg drv_phy_cfg;

	struct mcp_val64 val64;

	u8 raw_data[MCP_DRV_NVM_BUF_LEN];

	struct mcp_file_att file_att;

	u32 ack_vf_disabled[VF_MAX_STATIC / 32];

	struct drv_version_stc drv_version;

	struct lan_stats_stc lan_stats;
	u64 reserved_stats[11];
	struct ocbb_data_stc ocbb_info;
	struct temperature_status_stc temp_info;
	struct bist_nvm_image_att nvm_image_att;
	struct mdump_config_stc mdump_config;
};

struct public_drv_mb {
	u32 drv_mb_header;
#define DRV_MSG_CODE_MASK			0xffff0000
#define DRV_MSG_CODE_LOAD_REQ			0x10000000
#define DRV_MSG_CODE_LOAD_DONE			0x11000000
#define DRV_MSG_CODE_INIT_HW			0x12000000
#define DRV_MSG_CODE_UNLOAD_REQ			0x20000000
#define DRV_MSG_CODE_UNLOAD_DONE		0x21000000
#define DRV_MSG_CODE_INIT_PHY			0x22000000
#define DRV_MSG_CODE_LINK_RESET			0x23000000
#define DRV_MSG_CODE_SET_DCBX			0x25000000

#define DRV_MSG_CODE_BW_UPDATE_ACK		0x32000000
#define DRV_MSG_CODE_NIG_DRAIN			0x30000000
#define DRV_MSG_CODE_VF_DISABLED_DONE		0xc0000000
#define DRV_MSG_CODE_CFG_VF_MSIX		0xc0010000
#define DRV_MSG_CODE_MCP_RESET			0x00090000
#define DRV_MSG_CODE_SET_VERSION		0x000f0000

#define DRV_MSG_CODE_BIST_TEST			0x001e0000
#define DRV_MSG_CODE_SET_LED_MODE		0x00200000

#define DRV_MSG_SEQ_NUMBER_MASK			0x0000ffff

	u32 drv_mb_param;
#define DRV_MB_PARAM_UNLOAD_WOL_MCP		0x00000001
#define DRV_MB_PARAM_DCBX_NOTIFY_MASK		0x000000FF
#define DRV_MB_PARAM_DCBX_NOTIFY_SHIFT		3
#define DRV_MB_PARAM_CFG_VF_MSIX_VF_ID_SHIFT	0
#define DRV_MB_PARAM_CFG_VF_MSIX_VF_ID_MASK	0x000000FF
#define DRV_MB_PARAM_CFG_VF_MSIX_SB_NUM_SHIFT	8
#define DRV_MB_PARAM_CFG_VF_MSIX_SB_NUM_MASK	0x0000FF00

#define DRV_MB_PARAM_SET_LED_MODE_OPER		0x0
#define DRV_MB_PARAM_SET_LED_MODE_ON		0x1
#define DRV_MB_PARAM_SET_LED_MODE_OFF		0x2
#define DRV_MB_PARAM_BIST_REGISTER_TEST		1
#define DRV_MB_PARAM_BIST_CLOCK_TEST		2

#define DRV_MB_PARAM_BIST_RC_UNKNOWN		0
#define DRV_MB_PARAM_BIST_RC_PASSED		1
#define DRV_MB_PARAM_BIST_RC_FAILED		2
#define DRV_MB_PARAM_BIST_RC_INVALID_PARAMETER	3

#define DRV_MB_PARAM_BIST_TEST_INDEX_SHIFT	0
#define DRV_MB_PARAM_BIST_TEST_INDEX_MASK	0x000000FF

	u32 fw_mb_header;
#define FW_MSG_CODE_MASK			0xffff0000
#define FW_MSG_CODE_DRV_LOAD_ENGINE		0x10100000
#define FW_MSG_CODE_DRV_LOAD_PORT		0x10110000
#define FW_MSG_CODE_DRV_LOAD_FUNCTION		0x10120000
#define FW_MSG_CODE_DRV_LOAD_REFUSED_PDA	0x10200000
#define FW_MSG_CODE_DRV_LOAD_REFUSED_HSI	0x10210000
#define FW_MSG_CODE_DRV_LOAD_REFUSED_DIAG	0x10220000
#define FW_MSG_CODE_DRV_LOAD_DONE		0x11100000
#define FW_MSG_CODE_DRV_UNLOAD_ENGINE		0x20110000
#define FW_MSG_CODE_DRV_UNLOAD_PORT		0x20120000
#define FW_MSG_CODE_DRV_UNLOAD_FUNCTION		0x20130000
#define FW_MSG_CODE_DRV_UNLOAD_DONE		0x21100000
#define FW_MSG_CODE_DRV_CFG_VF_MSIX_DONE	0xb0010000
#define FW_MSG_CODE_OK				0x00160000

#define FW_MSG_SEQ_NUMBER_MASK			0x0000ffff

	u32 fw_mb_param;

	u32 drv_pulse_mb;
#define DRV_PULSE_SEQ_MASK			0x00007fff
#define DRV_PULSE_SYSTEM_TIME_MASK		0xffff0000
#define DRV_PULSE_ALWAYS_ALIVE			0x00008000

 	u32 mcp_pulse_mb;
#define MCP_PULSE_SEQ_MASK			0x00007fff
#define MCP_PULSE_ALWAYS_ALIVE			0x00008000
#define MCP_EVENT_MASK				0xffff0000
#define MCP_EVENT_OTHER_DRIVER_RESET_REQ	0x00010000

	union drv_union_data union_data;
};

enum MFW_DRV_MSG_TYPE {
	MFW_DRV_MSG_LINK_CHANGE,
	MFW_DRV_MSG_FLR_FW_ACK_FAILED,
	MFW_DRV_MSG_VF_DISABLED,
	MFW_DRV_MSG_LLDP_DATA_UPDATED,
	MFW_DRV_MSG_DCBX_REMOTE_MIB_UPDATED,
	MFW_DRV_MSG_DCBX_OPERATIONAL_MIB_UPDATED,
	MFW_DRV_MSG_RESERVED4,
	MFW_DRV_MSG_BW_UPDATE,
	MFW_DRV_MSG_BW_UPDATE5,
	MFW_DRV_MSG_BW_UPDATE6,
	MFW_DRV_MSG_BW_UPDATE7,
	MFW_DRV_MSG_BW_UPDATE8,
	MFW_DRV_MSG_BW_UPDATE9,
	MFW_DRV_MSG_BW_UPDATE10,
	MFW_DRV_MSG_TRANSCEIVER_STATE_CHANGE,
	MFW_DRV_MSG_BW_UPDATE11,
	MFW_DRV_MSG_MAX
};

#define MFW_DRV_MSG_MAX_DWORDS(msgs)	(((msgs - 1) >> 2) + 1)
#define MFW_DRV_MSG_DWORD(msg_id)	(msg_id >> 2)
#define MFW_DRV_MSG_OFFSET(msg_id)	((msg_id & 0x3) << 3)
#define MFW_DRV_MSG_MASK(msg_id)	(0xff << MFW_DRV_MSG_OFFSET(msg_id))

struct public_mfw_mb {
	u32 sup_msgs;
	u32 msg[MFW_DRV_MSG_MAX_DWORDS(MFW_DRV_MSG_MAX)];
	u32 ack[MFW_DRV_MSG_MAX_DWORDS(MFW_DRV_MSG_MAX)];
};

enum public_sections {
	PUBLIC_DRV_MB,
	PUBLIC_MFW_MB,
	PUBLIC_GLOBAL,
	PUBLIC_PATH,
	PUBLIC_PORT,
	PUBLIC_FUNC,
	PUBLIC_MAX_SECTIONS
};

struct mcp_public_data {
	u32 num_sections;
	u32 sections[PUBLIC_MAX_SECTIONS];
	struct public_drv_mb drv_mb[MCP_GLOB_FUNC_MAX];
	struct public_mfw_mb mfw_mb[MCP_GLOB_FUNC_MAX];
	struct public_global global;
	struct public_path path[MCP_GLOB_PATH_MAX];
	struct public_port port[MCP_GLOB_PORT_MAX];
	struct public_func func[MCP_GLOB_FUNC_MAX];
};

struct nvm_cfg_mac_address {
	u32 mac_addr_hi;
#define NVM_CFG_MAC_ADDRESS_HI_MASK	0x0000FFFF
#define NVM_CFG_MAC_ADDRESS_HI_OFFSET	0
	u32 mac_addr_lo;
};

struct nvm_cfg1_glob {
	u32 generic_cont0;
#define NVM_CFG1_GLOB_MF_MODE_MASK		0x00000FF0
#define NVM_CFG1_GLOB_MF_MODE_OFFSET		4
#define NVM_CFG1_GLOB_MF_MODE_MF_ALLOWED	0x0
#define NVM_CFG1_GLOB_MF_MODE_DEFAULT		0x1
#define NVM_CFG1_GLOB_MF_MODE_SPIO4		0x2
#define NVM_CFG1_GLOB_MF_MODE_NPAR1_0		0x3
#define NVM_CFG1_GLOB_MF_MODE_NPAR1_5		0x4
#define NVM_CFG1_GLOB_MF_MODE_NPAR2_0		0x5
#define NVM_CFG1_GLOB_MF_MODE_BD		0x6
#define NVM_CFG1_GLOB_MF_MODE_UFP		0x7
	u32 engineering_change[3];
	u32 manufacturing_id;
	u32 serial_number[4];
	u32 pcie_cfg;
	u32 mgmt_traffic;
	u32 core_cfg;
#define NVM_CFG1_GLOB_NETWORK_PORT_MODE_MASK		0x000000FF
#define NVM_CFG1_GLOB_NETWORK_PORT_MODE_OFFSET		0
#define NVM_CFG1_GLOB_NETWORK_PORT_MODE_BB_2X40G	0x0
#define NVM_CFG1_GLOB_NETWORK_PORT_MODE_2X50G		0x1
#define NVM_CFG1_GLOB_NETWORK_PORT_MODE_BB_1X100G	0x2
#define NVM_CFG1_GLOB_NETWORK_PORT_MODE_4X10G_F		0x3
#define NVM_CFG1_GLOB_NETWORK_PORT_MODE_BB_4X10G_E	0x4
#define NVM_CFG1_GLOB_NETWORK_PORT_MODE_BB_4X20G	0x5
#define NVM_CFG1_GLOB_NETWORK_PORT_MODE_1X40G		0xB
#define NVM_CFG1_GLOB_NETWORK_PORT_MODE_2X25G		0xC
#define NVM_CFG1_GLOB_NETWORK_PORT_MODE_1X25G		0xD
#define NVM_CFG1_GLOB_NETWORK_PORT_MODE_4X25G		0xE
	u32 e_lane_cfg1;
	u32 e_lane_cfg2;
	u32 f_lane_cfg1;
	u32 f_lane_cfg2;
	u32 mps10_preemphasis;
	u32 mps10_driver_current;
	u32 mps25_preemphasis;
	u32 mps25_driver_current;
	u32 pci_id;
	u32 pci_subsys_id;
	u32 bar;
	u32 mps10_txfir_main;
	u32 mps10_txfir_post;
	u32 mps25_txfir_main;
	u32 mps25_txfir_post;
	u32 manufacture_ver;
	u32 manufacture_time;
	u32 led_global_settings;
	u32 generic_cont1;
	u32 mbi_version;
	u32 mbi_date;
	u32 misc_sig;
	u32 device_capabilities;
#define NVM_CFG1_GLOB_DEVICE_CAPABILITIES_ETHERNET	0x1
	u32 power_dissipated;
	u32 power_consumed;
	u32 efi_version;
	u32 multi_network_modes_capability;
	u32 reserved[41];
};

struct nvm_cfg1_path {
	u32 reserved[30];
};

struct nvm_cfg1_port {
	u32 reserved__m_relocated_to_option_123;
	u32 reserved__m_relocated_to_option_124;
	u32 generic_cont0;
#define NVM_CFG1_PORT_DCBX_MODE_MASK				0x000F0000
#define NVM_CFG1_PORT_DCBX_MODE_OFFSET				16
#define NVM_CFG1_PORT_DCBX_MODE_DISABLED			0x0
#define NVM_CFG1_PORT_DCBX_MODE_IEEE				0x1
#define NVM_CFG1_PORT_DCBX_MODE_CEE				0x2
#define NVM_CFG1_PORT_DCBX_MODE_DYNAMIC				0x3
#define NVM_CFG1_PORT_DEFAULT_ENABLED_PROTOCOLS_MASK		0x00F00000
#define NVM_CFG1_PORT_DEFAULT_ENABLED_PROTOCOLS_OFFSET		20
#define NVM_CFG1_PORT_DEFAULT_ENABLED_PROTOCOLS_ETHERNET	0x1
#define NVM_CFG1_PORT_DEFAULT_ENABLED_PROTOCOLS_FCOE		0x2
#define NVM_CFG1_PORT_DEFAULT_ENABLED_PROTOCOLS_ISCSI		0x4
	u32 pcie_cfg;
	u32 features;
	u32 speed_cap_mask;
#define NVM_CFG1_PORT_DRV_SPEED_CAPABILITY_MASK_MASK		0x0000FFFF
#define NVM_CFG1_PORT_DRV_SPEED_CAPABILITY_MASK_OFFSET		0
#define NVM_CFG1_PORT_DRV_SPEED_CAPABILITY_MASK_1G		0x1
#define NVM_CFG1_PORT_DRV_SPEED_CAPABILITY_MASK_10G		0x2
#define NVM_CFG1_PORT_DRV_SPEED_CAPABILITY_MASK_25G		0x8
#define NVM_CFG1_PORT_DRV_SPEED_CAPABILITY_MASK_40G		0x10
#define NVM_CFG1_PORT_DRV_SPEED_CAPABILITY_MASK_50G		0x20
#define NVM_CFG1_PORT_DRV_SPEED_CAPABILITY_MASK_BB_100G		0x40
	u32 link_settings;
#define NVM_CFG1_PORT_DRV_LINK_SPEED_MASK			0x0000000F
#define NVM_CFG1_PORT_DRV_LINK_SPEED_OFFSET			0
#define NVM_CFG1_PORT_DRV_LINK_SPEED_AUTONEG			0x0
#define NVM_CFG1_PORT_DRV_LINK_SPEED_1G				0x1
#define NVM_CFG1_PORT_DRV_LINK_SPEED_10G			0x2
#define NVM_CFG1_PORT_DRV_LINK_SPEED_25G			0x4
#define NVM_CFG1_PORT_DRV_LINK_SPEED_40G			0x5
#define NVM_CFG1_PORT_DRV_LINK_SPEED_50G			0x6
#define NVM_CFG1_PORT_DRV_LINK_SPEED_BB_100G			0x7
#define NVM_CFG1_PORT_DRV_LINK_SPEED_SMARTLINQ			0x8
#define NVM_CFG1_PORT_DRV_FLOW_CONTROL_MASK			0x00000070
#define NVM_CFG1_PORT_DRV_FLOW_CONTROL_OFFSET			4
#define NVM_CFG1_PORT_DRV_FLOW_CONTROL_AUTONEG			0x1
#define NVM_CFG1_PORT_DRV_FLOW_CONTROL_RX			0x2
#define NVM_CFG1_PORT_DRV_FLOW_CONTROL_TX			0x4
	u32 phy_cfg;
	u32 mgmt_traffic;
	u32 ext_phy;
	u32 mba_cfg1;
	u32 mba_cfg2;
	u32 vf_cfg;
	struct nvm_cfg_mac_address lldp_mac_address;
	u32 led_port_settings;
	u32 transceiver_00;
	u32 device_ids;
	u32 board_cfg;
	u32 mnm_10g_cap;
	u32 mnm_10g_ctrl;
	u32 mnm_10g_misc;
	u32 mnm_25g_cap;
	u32 mnm_25g_ctrl;
	u32 mnm_25g_misc;
	u32 mnm_40g_cap;
	u32 mnm_40g_ctrl;
	u32 mnm_40g_misc;
	u32 mnm_50g_cap;
	u32 mnm_50g_ctrl;
	u32 mnm_50g_misc;
	u32 mnm_100g_cap;
	u32 mnm_100g_ctrl;
	u32 mnm_100g_misc;
	u32 reserved[116];
};

struct nvm_cfg1_func {
	struct nvm_cfg_mac_address mac_address;
	u32 rsrv1;
	u32 rsrv2;
	u32 device_id;
	u32 cmn_cfg;
	u32 pci_cfg;
	struct nvm_cfg_mac_address fcoe_node_wwn_mac_addr;
	struct nvm_cfg_mac_address fcoe_port_wwn_mac_addr;
	u32 preboot_generic_cfg;
	u32 reserved[8];
};

struct nvm_cfg1 {
	struct nvm_cfg1_glob glob;
	struct nvm_cfg1_path path[MCP_GLOB_PATH_MAX];
	struct nvm_cfg1_port port[MCP_GLOB_PORT_MAX];
	struct nvm_cfg1_func func[MCP_GLOB_FUNC_MAX];
};
#endif
