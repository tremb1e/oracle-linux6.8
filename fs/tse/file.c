/**
 * Tse: Linux filesystem encryption layer
 *
 * Copyright (C) 1997-2004 Erez Zadok
 * Copyright (C) 2001-2004 Stony Brook University
 * Copyright (C) 2004-2007 International Business Machines Corp.
 *   Author(s): Michael A. Halcrow <mhalcrow@us.ibm.com>
 *   		Michael C. Thompson <mcthomps@us.ibm.com>
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

#include <linux/file.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/mount.h>
#include <linux/pagemap.h>
#include <linux/security.h>
#include <linux/compat.h>
#include <linux/fs_stack.h>
#include "tse_kernel.h"

/**
 * tse_read_update_atime
 *
 * generic_file_read updates the atime of upper layer inode.  But, it
 * doesn't give us a chance to update the atime of the lower layer
 * inode.  This function is a wrapper to generic_file_read.  It
 * updates the atime of the lower level inode if generic_file_read
 * returns without any errors. This is to be used only for file reads.
 * The function to be used for directory reads is tse_read.
 */
static ssize_t tse_read_update_atime(struct kiocb *iocb,
				struct iov_iter *to)
{
	ssize_t rc;
	struct path *path;
	struct file *file = iocb->ki_filp;

	rc = generic_file_read_iter(iocb, to);
	if (rc >= 0) {
		path = tse_dentry_to_lower_path(file->f_path.dentry);
		touch_atime(path);
	}
	return rc;
}

struct tse_getdents_callback {
	struct dir_context ctx;
	struct dir_context *caller;
	struct super_block *sb;
	int filldir_called;
	int entries_written;
};

/* Inspired by generic filldir in fs/readdir.c */
static int
tse_filldir(struct dir_context *ctx, const char *lower_name,
		 int lower_namelen, loff_t offset, u64 ino, unsigned int d_type)
{
	struct tse_getdents_callback *buf =
		container_of(ctx, struct tse_getdents_callback, ctx);
	size_t name_size;
	char *name;
	int rc;

	buf->filldir_called++;
	rc = tse_decode_and_decrypt_filename(&name, &name_size,
						  buf->sb, lower_name,
						  lower_namelen);
	if (rc) {
		printk(KERN_ERR "%s: Error attempting to decode and decrypt "
		       "filename [%s]; rc = [%d]\n", __func__, lower_name,
		       rc);
		goto out;
	}
	buf->caller->pos = buf->ctx.pos;
	rc = !dir_emit(buf->caller, name, name_size, ino, d_type);
	kfree(name);
	if (!rc)
		buf->entries_written++;
out:
	return rc;
}

/**
 * tse_readdir
 * @file: The Tse directory file
 * @ctx: The actor to feed the entries to
 */
static int tse_readdir(struct file *file, struct dir_context *ctx)
{
	int rc;
	struct file *lower_file;
	struct inode *inode = file_inode(file);
	struct tse_getdents_callback buf = {
		.ctx.actor = tse_filldir,
		.caller = ctx,
		.sb = inode->i_sb,
	};
	lower_file = tse_file_to_lower(file);
	lower_file->f_pos = ctx->pos;
	rc = iterate_dir(lower_file, &buf.ctx);
	ctx->pos = buf.ctx.pos;
	if (rc < 0)
		goto out;
	if (buf.filldir_called && !buf.entries_written)
		goto out;
	if (rc >= 0)
		fsstack_copy_attr_atime(inode,
					file_inode(lower_file));
out:
	return rc;
}

struct kmem_cache *tse_file_info_cache;

static int read_or_initialize_metadata(struct dentry *dentry)
{
	struct inode *inode = d_inode(dentry);
	struct tse_mount_crypt_stat *mount_crypt_stat;
	struct tse_crypt_stat *crypt_stat;
	int rc;

	crypt_stat = &tse_inode_to_private(inode)->crypt_stat;
	mount_crypt_stat = &tse_superblock_to_private(
						inode->i_sb)->mount_crypt_stat;
	mutex_lock(&crypt_stat->cs_mutex);

	if (crypt_stat->flags & TSE_POLICY_APPLIED &&
	    crypt_stat->flags & TSE_KEY_VALID) {
		rc = 0;
		goto out;
	}

	rc = tse_read_metadata(dentry);
	if (!rc)
		goto out;

	if (mount_crypt_stat->flags & TSE_PLAINTEXT_PASSTHROUGH_ENABLED) {
		crypt_stat->flags &= ~(TSE_I_SIZE_INITIALIZED
				       | TSE_ENCRYPTED);
		rc = 0;
		goto out;
	}

	if (!(mount_crypt_stat->flags & TSE_XATTR_METADATA_ENABLED) &&
	    !i_size_read(tse_inode_to_lower(inode))) {
		rc = tse_initialize_file(dentry, inode);
		if (!rc)
			goto out;
	}

	rc = -EIO;
out:
	mutex_unlock(&crypt_stat->cs_mutex);
	return rc;
}

/**
 * tse_open
 * @inode: inode speciying file to open
 * @file: Structure to return filled in
 *
 * Opens the file specified by inode.
 *
 * Returns zero on success; non-zero otherwise
 */
static int tse_open(struct inode *inode, struct file *file)
{
	int rc = 0;
	struct tse_crypt_stat *crypt_stat = NULL;
	struct dentry *tse_dentry = file->f_path.dentry;
	/* Private value of tse_dentry allocated in
	 * tse_lookup() */
	struct tse_file_info *file_info;

	/* Released in tse_release or end of function if failure */
	file_info = kmem_cache_zalloc(tse_file_info_cache, GFP_KERNEL);
	tse_set_file_private(file, file_info);
	if (!file_info) {
		tse_printk(KERN_ERR,
				"Error attempting to allocate memory\n");
		rc = -ENOMEM;
		goto out;
	}
	crypt_stat = &tse_inode_to_private(inode)->crypt_stat;
	mutex_lock(&crypt_stat->cs_mutex);
	if (!(crypt_stat->flags & TSE_POLICY_APPLIED)) {
		tse_printk(KERN_DEBUG, "Setting flags for stat...\n");
		/* Policy code enabled in future release */
		crypt_stat->flags |= (TSE_POLICY_APPLIED
				      | TSE_ENCRYPTED);
	}
	mutex_unlock(&crypt_stat->cs_mutex);
	rc = tse_get_lower_file(tse_dentry, inode);
	if (rc) {
		printk(KERN_ERR "%s: Error attempting to initialize "
			"the lower file for the dentry with name "
			"[%pd]; rc = [%d]\n", __func__,
			tse_dentry, rc);
		goto out_free;
	}
	if ((tse_inode_to_private(inode)->lower_file->f_flags & O_ACCMODE)
	    == O_RDONLY && (file->f_flags & O_ACCMODE) != O_RDONLY) {
		rc = -EPERM;
		printk(KERN_WARNING "%s: Lower file is RO; Tse "
		       "file must hence be opened RO\n", __func__);
		goto out_put;
	}
	tse_set_file_lower(
		file, tse_inode_to_private(inode)->lower_file);
	if (d_is_dir(tse_dentry)) {
		tse_printk(KERN_DEBUG, "This is a directory\n");
		mutex_lock(&crypt_stat->cs_mutex);
		crypt_stat->flags &= ~(TSE_ENCRYPTED);
		mutex_unlock(&crypt_stat->cs_mutex);
		rc = 0;
		goto out;
	}
	rc = read_or_initialize_metadata(tse_dentry);
	if (rc)
		goto out_put;
	tse_printk(KERN_DEBUG, "inode w/ addr = [0x%p], i_ino = "
			"[0x%.16lx] size: [0x%.16llx]\n", inode, inode->i_ino,
			(unsigned long long)i_size_read(inode));
	goto out;
out_put:
	tse_put_lower_file(inode);
out_free:
	kmem_cache_free(tse_file_info_cache,
			tse_file_to_private(file));
out:
	return rc;
}

static int tse_flush(struct file *file, fl_owner_t td)
{
	struct file *lower_file = tse_file_to_lower(file);

	if (lower_file->f_op->flush) {
		filemap_write_and_wait(file->f_mapping);
		return lower_file->f_op->flush(lower_file, td);
	}

	return 0;
}

static int tse_release(struct inode *inode, struct file *file)
{
	tse_put_lower_file(inode);
	kmem_cache_free(tse_file_info_cache,
			tse_file_to_private(file));
	return 0;
}

static int
tse_fsync(struct file *file, loff_t start, loff_t end, int datasync)
{
	int rc;

	rc = filemap_write_and_wait(file->f_mapping);
	if (rc)
		return rc;

	return vfs_fsync(tse_file_to_lower(file), datasync);
}

static int tse_fasync(int fd, struct file *file, int flag)
{
	int rc = 0;
	struct file *lower_file = NULL;

	lower_file = tse_file_to_lower(file);
	if (lower_file->f_op->fasync)
		rc = lower_file->f_op->fasync(fd, lower_file, flag);
	return rc;
}

static long
tse_unlocked_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct file *lower_file = tse_file_to_lower(file);
	long rc = -ENOTTY;

	if (!lower_file->f_op->unlocked_ioctl)
		return rc;

	switch (cmd) {
	case FITRIM:
	case FS_IOC_GETFLAGS:
	case FS_IOC_SETFLAGS:
	case FS_IOC_GETVERSION:
	case FS_IOC_SETVERSION:
		rc = lower_file->f_op->unlocked_ioctl(lower_file, cmd, arg);
		fsstack_copy_attr_all(file_inode(file), file_inode(lower_file));

		return rc;
	default:
		return rc;
	}
}

#ifdef CONFIG_COMPAT
static long
tse_compat_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct file *lower_file = tse_file_to_lower(file);
	long rc = -ENOIOCTLCMD;

	if (!lower_file->f_op->compat_ioctl)
		return rc;

	switch (cmd) {
	case FITRIM:
	case FS_IOC32_GETFLAGS:
	case FS_IOC32_SETFLAGS:
	case FS_IOC32_GETVERSION:
	case FS_IOC32_SETVERSION:
		rc = lower_file->f_op->compat_ioctl(lower_file, cmd, arg);
		fsstack_copy_attr_all(file_inode(file), file_inode(lower_file));

		return rc;
	default:
		return rc;
	}
}
#endif

const struct file_operations tse_dir_fops = {
	.iterate = tse_readdir,
	.read = generic_read_dir,
	.unlocked_ioctl = tse_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = tse_compat_ioctl,
#endif
	.open = tse_open,
	.flush = tse_flush,
	.release = tse_release,
	.fsync = tse_fsync,
	.fasync = tse_fasync,
	.splice_read = generic_file_splice_read,
	.llseek = default_llseek,
};

const struct file_operations tse_main_fops = {
	.llseek = generic_file_llseek,
	.read_iter = tse_read_update_atime,
	.write_iter = generic_file_write_iter,
	.iterate = tse_readdir,
	.unlocked_ioctl = tse_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = tse_compat_ioctl,
#endif
	.mmap = generic_file_mmap,
	.open = tse_open,
	.flush = tse_flush,
	.release = tse_release,
	.fsync = tse_fsync,
	.fasync = tse_fasync,
	.splice_read = generic_file_splice_read,
};
