/* -*- mode: c; c-basic-offset: 8; -*-
 * vim: noexpandtab sw=8 ts=8 sts=0:
 *
 * acl.c
 *
 * Copyright (C) 2004, 2008 Oracle.  All rights reserved.
 *
 * CREDITS:
 * Lots of code in this file is copy from linux/fs/ext3/acl.c.
 * Copyright (C) 2001-2003 Andreas Gruenbacher, <agruen@suse.de>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>

#include <cluster/masklog.h>

#include "ocfs2.h"
#include "alloc.h"
#include "dlmglue.h"
#include "file.h"
#include "inode.h"
#include "journal.h"
#include "ocfs2_fs.h"

#include "xattr.h"
#include "acl.h"


/*
 * Convert from xattr value to acl struct.
 */
static struct posix_acl *ocfs2_acl_from_xattr(const void *value, size_t size)
{
	int n, count;
	struct posix_acl *acl;

	if (!value)
		return NULL;
	if (size < sizeof(struct posix_acl_entry))
		return ERR_PTR(-EINVAL);

	count = size / sizeof(struct posix_acl_entry);

	acl = posix_acl_alloc(count, GFP_NOFS);
	if (!acl)
		return ERR_PTR(-ENOMEM);
	for (n = 0; n < count; n++) {
		struct ocfs2_acl_entry *entry =
			(struct ocfs2_acl_entry *)value;

		acl->a_entries[n].e_tag  = le16_to_cpu(entry->e_tag);
		acl->a_entries[n].e_perm = le16_to_cpu(entry->e_perm);
		switch(acl->a_entries[n].e_tag) {
		case ACL_USER:
			acl->a_entries[n].e_uid =
				make_kuid(&init_user_ns,
					  le32_to_cpu(entry->e_id));
			break;
		case ACL_GROUP:
			acl->a_entries[n].e_gid =
				make_kgid(&init_user_ns,
					  le32_to_cpu(entry->e_id));
			break;
		default:
			break;
		}
		value += sizeof(struct posix_acl_entry);

	}
	return acl;
}

/*
 * Convert acl struct to xattr value.
 */
static void *ocfs2_acl_to_xattr(const struct posix_acl *acl, size_t *size)
{
	struct ocfs2_acl_entry *entry = NULL;
	char *ocfs2_acl;
	size_t n;

	*size = acl->a_count * sizeof(struct posix_acl_entry);

	ocfs2_acl = kmalloc(*size, GFP_NOFS);
	if (!ocfs2_acl)
		return ERR_PTR(-ENOMEM);

	entry = (struct ocfs2_acl_entry *)ocfs2_acl;
	for (n = 0; n < acl->a_count; n++, entry++) {
		entry->e_tag  = cpu_to_le16(acl->a_entries[n].e_tag);
		entry->e_perm = cpu_to_le16(acl->a_entries[n].e_perm);
		switch(acl->a_entries[n].e_tag) {
		case ACL_USER:
			entry->e_id = cpu_to_le32(
				from_kuid(&init_user_ns,
					  acl->a_entries[n].e_uid));
			break;
		case ACL_GROUP:
			entry->e_id = cpu_to_le32(
				from_kgid(&init_user_ns,
					  acl->a_entries[n].e_gid));
			break;
		default:
			entry->e_id = cpu_to_le32(ACL_UNDEFINED_ID);
			break;
		}
	}
	return ocfs2_acl;
}

static struct posix_acl *ocfs2_get_acl_nolock(struct inode *inode,
					      int type,
					      struct buffer_head *di_bh)
{
	int name_index;
	char *value = NULL;
	struct posix_acl *acl;
	int retval;

	switch (type) {
	case ACL_TYPE_ACCESS:
		name_index = OCFS2_XATTR_INDEX_POSIX_ACL_ACCESS;
		break;
	case ACL_TYPE_DEFAULT:
		name_index = OCFS2_XATTR_INDEX_POSIX_ACL_DEFAULT;
		break;
	default:
		return ERR_PTR(-EINVAL);
	}

	retval = ocfs2_xattr_get_nolock(inode, di_bh, name_index, "", NULL, 0);
	if (retval > 0) {
		value = kmalloc(retval, GFP_NOFS);
		if (!value)
			return ERR_PTR(-ENOMEM);
		retval = ocfs2_xattr_get_nolock(inode, di_bh, name_index,
						"", value, retval);
	}

	if (retval > 0)
		acl = ocfs2_acl_from_xattr(value, retval);
	else if (retval == -ENODATA || retval == 0)
		acl = NULL;
	else
		acl = ERR_PTR(retval);

	kfree(value);

	return acl;
}

/*
 * Helper function to set i_mode in memory and disk. Some call paths
 * will not have di_bh or a journal handle to pass, in which case it
 * will create it's own.
 */
static int ocfs2_acl_set_mode(struct inode *inode, struct buffer_head *di_bh,
			      handle_t *handle, umode_t new_mode)
{
	int ret, commit_handle = 0;
	struct ocfs2_dinode *di;

	if (di_bh == NULL) {
		ret = ocfs2_read_inode_block(inode, &di_bh);
		if (ret) {
			mlog_errno(ret);
			goto out;
		}
	} else
		get_bh(di_bh);

	if (handle == NULL) {
		handle = ocfs2_start_trans(OCFS2_SB(inode->i_sb),
					   OCFS2_INODE_UPDATE_CREDITS);
		if (IS_ERR(handle)) {
			ret = PTR_ERR(handle);
			mlog_errno(ret);
			goto out_brelse;
		}

		commit_handle = 1;
	}

	di = (struct ocfs2_dinode *)di_bh->b_data;
	ret = ocfs2_journal_access_di(handle, INODE_CACHE(inode), di_bh,
				      OCFS2_JOURNAL_ACCESS_WRITE);
	if (ret) {
		mlog_errno(ret);
		goto out_commit;
	}

	inode->i_mode = new_mode;
	inode->i_ctime = CURRENT_TIME;
	di->i_mode = cpu_to_le16(inode->i_mode);
	di->i_ctime = cpu_to_le64(inode->i_ctime.tv_sec);
	di->i_ctime_nsec = cpu_to_le32(inode->i_ctime.tv_nsec);
	ocfs2_update_inode_fsync_trans(handle, inode, 0);

	ocfs2_journal_dirty(handle, di_bh);

out_commit:
	if (commit_handle)
		ocfs2_commit_trans(OCFS2_SB(inode->i_sb), handle);
out_brelse:
	brelse(di_bh);
out:
	return ret;
}

/*
 * Set the access or default ACL of an inode.
 */
int ocfs2_set_acl(handle_t *handle,
			 struct inode *inode,
			 struct buffer_head *di_bh,
			 int type,
			 struct posix_acl *acl,
			 struct ocfs2_alloc_context *meta_ac,
			 struct ocfs2_alloc_context *data_ac)
{
	int name_index;
	void *value = NULL;
	size_t size = 0;
	int ret;

	if (S_ISLNK(inode->i_mode))
		return -EOPNOTSUPP;

	switch (type) {
	case ACL_TYPE_ACCESS:
		name_index = OCFS2_XATTR_INDEX_POSIX_ACL_ACCESS;
		if (acl) {
			umode_t mode = inode->i_mode;
			ret = posix_acl_equiv_mode(acl, &mode);
			if (ret < 0)
				return ret;

			if (ret == 0)
				acl = NULL;

			ret = ocfs2_acl_set_mode(inode, di_bh,
						 handle, mode);
			if (ret)
				return ret;
		}
		break;
	case ACL_TYPE_DEFAULT:
		name_index = OCFS2_XATTR_INDEX_POSIX_ACL_DEFAULT;
		if (!S_ISDIR(inode->i_mode))
			return acl ? -EACCES : 0;
		break;
	default:
		return -EINVAL;
	}

	if (acl) {
		value = ocfs2_acl_to_xattr(acl, &size);
		if (IS_ERR(value))
			return (int)PTR_ERR(value);
	}

	if (handle)
		ret = ocfs2_xattr_set_handle(handle, inode, di_bh, name_index,
					     "", value, size, 0,
					     meta_ac, data_ac);
	else
		ret = ocfs2_xattr_set(inode, name_index, "", value, size, 0);

	kfree(value);

	return ret;
}

int ocfs2_iop_set_acl(struct inode *inode, struct posix_acl *acl, int type)
{
	struct buffer_head *bh = NULL;
	int status = 0;

	status = ocfs2_inode_lock_full(inode, &bh, 1, OCFS2_LOCK_RECURSIVE);
	if (status < 0) {
		if (status != -ENOENT)
			mlog_errno(status);
		return status;
	}
	status = ocfs2_set_acl(NULL, inode, bh, type, acl, NULL, NULL);
	ocfs2_inode_unlock(inode, 1);
	brelse(bh);
	return status;
}

struct posix_acl *ocfs2_iop_get_acl(struct inode *inode, int type)
{
	struct ocfs2_super *osb;
	struct buffer_head *di_bh = NULL;
	struct posix_acl *acl;
	int ret;

	osb = OCFS2_SB(inode->i_sb);
	if (!(osb->s_mount_opt & OCFS2_MOUNT_POSIX_ACL))
		return NULL;
	ret = ocfs2_inode_lock_full(inode, &di_bh, 0, OCFS2_LOCK_RECURSIVE);
	if (ret < 0) {
		if (ret != -ENOENT)
			mlog_errno(ret);
		return ERR_PTR(ret);
	}

	acl = ocfs2_get_acl_nolock(inode, type, di_bh);

	ocfs2_inode_unlock(inode, 0);
	brelse(di_bh);
	return acl;
}
