/**
 * Userspace side of communications with Tse kernel module.
 *
 * Copyright (C) 2008 International Business Machines Corp.
 *   Author(s): Michael A. Halcrow <mhalcrow@us.ibm.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#include <errno.h>
#include <syslog.h>
#include <string.h>
#include <sys/types.h>
#include "config.h"
#include "../include/tse.h"

/**
 * tse_write_packet_length
 * @dest: The byte array target into which to write the
 *       length. Must have at least 5 bytes allocated.
 * @size: The length to write.
 * @packet_size_length: The number of bytes used to encode the
 *                      packet length is written to this address.
 *
 * Returns zero on success; non-zero on error.
 */
int tse_write_packet_length(char *dest, size_t size,
				 size_t *packet_size_length)
{
	int rc = 0;

	if (size < 192) {
		dest[0] = size;
		(*packet_size_length) = 1;
	} else if (size < 65536) {
		dest[0] = (((size - 192) / 256) + 192);
		dest[1] = ((size - 192) % 256);
		(*packet_size_length) = 2;
	} else {
		rc = -EINVAL;
		syslog(LOG_ERR, "Unsupported packet size: [%zu]\n",
		       size);
	}
	return rc;
}

/**
 * tse_parse_packet_length
 * @data: Pointer to memory containing length at offset
 * @size: This function writes the decoded size to this memory
 *        address; zero on error
 * @length_size: The number of bytes occupied by the encoded length
 *
 * Returns zero on success
 */
int tse_parse_packet_length(unsigned char *data, size_t *size,
				 size_t *length_size)
{
	int rc = 0;

	(*length_size) = 0;
	(*size) = 0;
	if (data[0] < 192) {
		/* One-byte length */
		(*size) = data[0];
		(*length_size) = 1;
	} else if (data[0] < 224) {
		/* Two-byte length */
		(*size) = ((data[0] - 192) * 256);
		(*size) += (data[1] + 192);
		(*length_size) = 2;
	} else if (data[0] == 255) {
		/* Five-byte length; we're not supposed to see this */
		rc = -EINVAL;
		syslog(LOG_ERR, "Five-byte packet length not "
		       "supported\n");
		goto out;
	} else {
		rc = -EINVAL;
		syslog(LOG_ERR, "Error parsing packet length\n");
		goto out;
	}
out:
	return rc;
}

/**
 * Called with mctx_mux held
 */
int tse_init_messaging(struct tse_messaging_ctx *mctx, uint32_t type)
{
	int rc = 0;

	memset(mctx, 0, sizeof(*mctx));
	switch (type) {
	case TSE_MESSAGING_TYPE_NETLINK:
		mctx->type = TSE_MESSAGING_TYPE_NETLINK;
		rc = tse_init_netlink(&mctx->ctx.nl_ctx);
		break;
	case TSE_MESSAGING_TYPE_MISCDEV:
		mctx->type = TSE_MESSAGING_TYPE_MISCDEV;
		rc = tse_init_miscdev(&mctx->ctx.miscdev_ctx);
		break;
	default:
		rc = -EINVAL;
		goto out;
	};
out:
	return rc;
}

int tse_messaging_exit(struct tse_messaging_ctx *mctx)
{
	int rc = 0;

	switch (mctx->type) {
	case TSE_MESSAGING_TYPE_NETLINK:
		tse_release_netlink(&mctx->ctx.nl_ctx);
		break;
	case TSE_MESSAGING_TYPE_MISCDEV:
		tse_release_miscdev(&mctx->ctx.miscdev_ctx);
		break;
	default:
		rc = -EINVAL;
		goto out;
	};
out:
	return rc;
}

/**
 * tse_send_message
 * @mctx: Parent context for Tse messaging with the kernel
 * @msg: Message to send (struct tse_message with data appended)
 * @msg_type: Message type to send
 * @msg_flags: Flags for sending message
 * @msg_seq: Message sequence number
 * 
 */
int tse_send_message(struct tse_messaging_ctx *mctx,
			  struct tse_message *msg,
			  unsigned char msg_type, uint16_t msg_flags,
			  uint32_t msg_seq)
{
	int rc = 0;

	switch (mctx->type) {
	case TSE_MESSAGING_TYPE_NETLINK:
		rc = tse_send_netlink(&mctx->ctx.nl_ctx, msg, msg_type,
					   msg_flags, msg_seq);
		if (rc) {
			syslog(LOG_ERR, "%s: Failed to register netlink daemon "
			       "with the Tse kernel module; rc = [%d]\n",
			       __FUNCTION__, rc);

		}
		break;
	case TSE_MESSAGING_TYPE_MISCDEV:
		rc = tse_send_miscdev(&mctx->ctx.miscdev_ctx, msg,
					   msg_type, msg_flags, msg_seq);
		if (rc) {
			syslog(LOG_ERR, "%s: Failed to register miscdev daemon "
			       "with the Tse kernel module; rc = [%d]\n",
			       __FUNCTION__, rc);
		}
		break;
	default:
		rc = -EINVAL;
		goto out;
	};
out:
	return rc;
}

int tse_run_daemon(struct tse_messaging_ctx *mctx)
{
	int rc;

	switch (mctx->type) {
	case TSE_MESSAGING_TYPE_NETLINK:
		rc = tse_run_netlink_daemon(&mctx->ctx.nl_ctx);
		if (rc)
			goto out;
		break;
	case TSE_MESSAGING_TYPE_MISCDEV:
		rc = tse_run_miscdev_daemon(&mctx->ctx.miscdev_ctx);
		if (rc)
			goto out;
		break;
	default:
		rc = -EINVAL;
		goto out;
	}
out:
	return rc;
}
