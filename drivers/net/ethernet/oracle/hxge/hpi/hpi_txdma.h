/*****************************************************************************
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
*
* Copyright 2009, 2011 Oracle America, Inc. All rights reserved.
*
* This program is free software; you can redistribute it and/or modify it under
* the terms of the GNU General Public License version 2 only, as published by
* the Free Software Foundation.
*
* This program is distributed in the hope that it will be useful, but WITHOUT
* ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
* FOR A PARTICULAR PURPOSE.  See the GNU General Public License version 2 for
* more details (a copy is included in the LICENSE file that accompanied this
* code).
*
* You should have received a copy of the GNU General Public License version 2
* along with this program; If not,
* see http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt
*
* Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 or
* visit www.oracle.com if you need additional information or have any
* questions.
*
******************************************************************************/

#ifndef _HPI_TXDMA_H
#define	_HPI_TXDMA_H

#include "hpi.h"
#include "../hxge_defs.h"
#include "../hxge_txdma_hw.h"
#include "../hxge_tdc_hw.h"

typedef	enum _txdma_cs_cntl_e {
	TXDMA_INIT_RESET	= 0x1,
	TXDMA_INIT_START	= 0x2,
	TXDMA_START		= 0x3,
	TXDMA_RESET		= 0x4,
	TXDMA_STOP		= 0x5,
	TXDMA_MBOX_ENABLE	= 0x6
} txdma_cs_cntl_t;

#define	HXGE_TXDMA_OFFSET(x, v, channel) (x + \
		(!v ? DMC_OFFSET(channel) : TDMC_PIOVADDR_OFFSET(channel)))
/*
 * PIO macros to read and write the transmit registers.
 */
#define	TXDMA_REG_READ64(handle, reg, channel, val_p)	\
		HXGE_REG_RD64(handle, \
		(HXGE_TXDMA_OFFSET(reg, 0, channel)), val_p)

#define	TXDMA_REG_WRITE64(handle, reg, channel, data)	\
		HXGE_REG_WR64(handle, \
		HXGE_TXDMA_OFFSET(reg, 0, channel), data)

#define	HPI_TXDMA_GATHER_INDEX(index)	\
		((index <= TX_MAX_GATHER_POINTERS)) ? HPI_SUCCESS : \
		(HPI_TXDMA_GATHER_INVALID)

/*
 * Transmit HPI error codes
 */
#define	TXDMA_ER_ST			(TXDMA_BLK_ID << HPI_BLOCK_ID_SHIFT)
#define	TXDMA_ID_SHIFT(n)		(n << HPI_PORT_CHAN_SHIFT)

#define	TXDMA_HW_STOP_FAILED		(HPI_BK_HW_ER_START | 0x1)
#define	TXDMA_HW_RESUME_FAILED		(HPI_BK_HW_ER_START | 0x2)

#define	TXDMA_GATHER_INVALID		(HPI_BK_ERROR_START | 0x1)
#define	TXDMA_XFER_LEN_INVALID		(HPI_BK_ERROR_START | 0x2)

#define	HPI_TXDMA_OPCODE_INVALID(n)	(TXDMA_ID_SHIFT(n) |	\
					TXDMA_ER_ST | OPCODE_INVALID)

#define	HPI_TXDMA_FUNC_INVALID(n)	(TXDMA_ID_SHIFT(n) |	\
					TXDMA_ER_ST | PORT_INVALID)
#define	HPI_TXDMA_CHANNEL_INVALID(n)	(TXDMA_ID_SHIFT(n) |	\
					TXDMA_ER_ST | CHANNEL_INVALID)

#define	HPI_TXDMA_PAGE_INVALID(n)	(TXDMA_ID_SHIFT(n) |	\
					TXDMA_ER_ST | LOGICAL_PAGE_INVALID)

#define	HPI_TXDMA_REGISTER_INVALID	(TXDMA_ER_ST | REGISTER_INVALID)
#define	HPI_TXDMA_COUNTER_INVALID	(TXDMA_ER_ST | COUNTER_INVALID)
#define	HPI_TXDMA_CONFIG_INVALID	(TXDMA_ER_ST | CONFIG_INVALID)


#define	HPI_TXDMA_GATHER_INVALID	(TXDMA_ER_ST | TXDMA_GATHER_INVALID)
#define	HPI_TXDMA_XFER_LEN_INVALID	(TXDMA_ER_ST | TXDMA_XFER_LEN_INVALID)

#define	HPI_TXDMA_RESET_FAILED		(TXDMA_ER_ST | RESET_FAILED)
#define	HPI_TXDMA_STOP_FAILED		(TXDMA_ER_ST | TXDMA_HW_STOP_FAILED)
#define	HPI_TXDMA_RESUME_FAILED		(TXDMA_ER_ST | TXDMA_HW_RESUME_FAILED)

/*
 * Transmit DMA Channel HPI Prototypes.
 */
hpi_status_t hpi_txdma_log_page_handle_set(hpi_handle_t handle,
	uint8_t channel, tdc_page_handle_t *hdl_p);
hpi_status_t hpi_txdma_channel_reset(hpi_handle_t handle, uint8_t channel);
hpi_status_t hpi_txdma_channel_init_enable(hpi_handle_t handle,
		uint8_t channel);
hpi_status_t hpi_txdma_channel_enable(hpi_handle_t handle, uint8_t channel);
hpi_status_t hpi_txdma_channel_disable(hpi_handle_t handle, uint8_t channel);
hpi_status_t hpi_txdma_channel_mbox_enable(hpi_handle_t handle,
		uint8_t channel);
hpi_status_t hpi_txdma_channel_control(hpi_handle_t handle,
		txdma_cs_cntl_t control, uint8_t channel);
hpi_status_t hpi_txdma_control_status(hpi_handle_t handle, io_op_t op_mode,
		uint8_t channel, tdc_stat_t *cs_p);

hpi_status_t hpi_txdma_event_mask(hpi_handle_t handle, io_op_t op_mode,
		uint8_t channel, tdc_int_mask_t *mask_p);
hpi_status_t hpi_tx_fifo_status(hpi_handle_t handle, io_op_t op_mode,
		      tdc_fifo_err_stat_t *cs_p);
hpi_status_t hpi_tx_fifo_mask(hpi_handle_t handle, io_op_t op_mode, 
		    tdc_fifo_err_mask_t *mask_p);

hpi_status_t hpi_txdma_event_mask_mk_out(hpi_handle_t handle, uint8_t channel);
hpi_status_t hpi_txdma_event_mask_mk_in(hpi_handle_t handle, uint8_t channel);

hpi_status_t hpi_txdma_ring_addr_set(hpi_handle_t handle, uint8_t channel,
		uint64_t start_addr, uint32_t len);
hpi_status_t hpi_txdma_ring_config(hpi_handle_t handle, io_op_t op_mode,
		uint8_t channel, uint64_t *reg_data);
hpi_status_t hpi_txdma_mbox_config(hpi_handle_t handle, io_op_t op_mode,
		uint8_t channel, uint64_t *mbox_addr);
hpi_status_t hpi_txdma_desc_gather_set(hpi_handle_t handle,
		p_tx_desc_t desc_p, uint8_t gather_index,
		boolean_t mark, uint8_t ngathers,
		uint64_t dma_ioaddr, uint32_t transfer_len);

hpi_status_t hpi_txdma_desc_gather_sop_set(hpi_handle_t handle,
		p_tx_desc_t desc_p, boolean_t mark_mode, uint8_t ngathers);

hpi_status_t hpi_txdma_desc_gather_sop_set_1(hpi_handle_t handle,
		p_tx_desc_t desc_p, boolean_t mark_mode, uint8_t ngathers,
		uint32_t transfer_len);

hpi_status_t hpi_txdma_desc_set_xfer_len(hpi_handle_t handle,
		p_tx_desc_t desc_p, uint32_t transfer_len);

hpi_status_t hpi_txdma_desc_set_zero(hpi_handle_t handle, uint16_t entries);
hpi_status_t hpi_txdma_desc_mem_get(hpi_handle_t handle, uint16_t index,
		p_tx_desc_t desc_p);
hpi_status_t hpi_txdma_desc_kick_reg_set(hpi_handle_t handle, uint8_t channel,
		uint16_t tail_index, boolean_t wrap);
hpi_status_t hpi_txdma_desc_kick_reg_get(hpi_handle_t handle, uint8_t channel,
		tdc_tdr_kick_t *kick_p);
hpi_status_t hpi_txdma_ring_head_get(hpi_handle_t handle, uint8_t channel,
		tdc_tdr_head_t *hdl_p);
hpi_status_t hpi_txdma_channel_mbox_get(hpi_handle_t handle, uint8_t channel,
		p_txdma_mailbox_t mbox_p);
hpi_status_t hpi_txdma_channel_pre_state_get(hpi_handle_t handle,
		uint8_t channel, tdc_tdr_pre_head_t *prep);
void hpi_txdma_dump_desc_one(hpi_handle_t handle, p_tx_desc_t desc_p,
	int desc_index);
hpi_status_t hpi_txdma_dump_tdc_regs(hpi_handle_t handle, uint8_t tdc);
hpi_status_t hpi_txdma_dump_tdc_common_regs(hpi_handle_t handle);
hpi_status_t hpi_txdma_control_reset_wait(hpi_handle_t handle,
        uint8_t channel);
hpi_status_t hpi_txdma_control_stop_wait(hpi_handle_t handle,
	uint8_t channel);


#endif	/* _HPI_TXDMA_H */
