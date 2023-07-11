/**
 * Copyright (C) 2006-2007 International Business Machines Corp.
 * Author(s): Mike Halcrow <mhalcrow@us.ibm.com>
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

#include "config.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "../include/tse.h"
#include "../include/decision_graph.h"

static int tf_passwd(struct tse_ctx *ctx, struct param_node *node,
		     struct val_node **head, void **foo)
{
	int rc;
	if (!node->val)
		return -EINVAL;
	if ((rc = stack_push(head, node->val)))
		return rc;
	node->val = NULL;
	return DEFAULT_TOK;
}

static int tf_pass_file(struct tse_ctx *ctx, struct param_node *node,
			struct val_node **head, void **foo)
{
	char *tmp_val = NULL;
	int fd;
	struct tse_name_val_pair *file_head;
	struct tse_name_val_pair *walker;
	int rc = 0;

	file_head = malloc(sizeof(struct tse_name_val_pair));
	if (!file_head) {
		rc = -ENOMEM;
		goto out;
	}
	memset(file_head, 0, sizeof(struct tse_name_val_pair));
	if (strcmp(node->mnt_opt_names[0], "passphrase_passwd_file") == 0) {
		fd = open(node->val, O_RDONLY);
		if (fd == -1) {
			rc = -errno;
			syslog(LOG_ERR, "%s: Error whilst attempting to open "
			       "[%s]; errno = [%m]\n", __FUNCTION__, node->val);
			goto out;
		}
	} else if (strcmp(node->mnt_opt_names[0], "passphrase_passwd_fd") == 0) {
		fd = strtol(node->val, NULL, 0);
	} else {
		syslog(LOG_ERR, "%s: Invalid file descriptor qualifier\n",
			__FUNCTION__);
		rc = MOUNT_ERROR;
		goto out;
	}
	rc = parse_options_file(fd, file_head);
	close(fd);
	if (rc) {
		syslog(LOG_ERR, "%s: Error parsing file for passwd; "
		       "rc = [%d]\n", __FUNCTION__, rc);
		goto out;
	}
	walker = file_head->next;
	while (walker) {
		if (strcmp(walker->name, "passphrase_passwd") == 0
		    || strcmp(walker->name, "passwd") == 0) {
			if (asprintf(&tmp_val, "%s", walker->value) < 0) {
				rc = -ENOMEM;
				goto out;
			}
			stack_push(head, tmp_val);
			break;
		}
		walker = walker->next;
	}
	if (!walker) {
		syslog(LOG_ERR, "%s: Cannot find [passwd] directive\n",
		       __FUNCTION__);
		rc = MOUNT_ERROR;
		goto out;
	}
	free_name_val_pairs(file_head);
	file_head = NULL;
	walker = NULL;
out:
	free(node->val);
	node->val = NULL;
	return rc;
}

static int tf_salt(struct tse_ctx *ctx, struct param_node *node,
		   struct val_node **head, void **foo)
{
	char *passwd;
	char salt[TSE_SALT_SIZE];
	char *salt_hex;
	char *auth_tok_sig;
	char *param;
	int rc = 0;

	if (!node->val)
		rc = asprintf(&node->val, "%s", node->default_val);
	if (rc == -1)
		return -ENOMEM;
	stack_push(head, node->val);
	node->val = NULL;
	stack_pop_val(head, (void *)&salt_hex);
	stack_pop_val(head, (void *)&passwd);
	auth_tok_sig = malloc(TSE_SIG_SIZE_HEX + 1);
	if (!auth_tok_sig) {
		rc = -ENOMEM;
		goto out;
	}
	from_hex(salt, salt_hex, TSE_SIG_SIZE);
	rc = tse_add_passphrase_key_to_keyring(auth_tok_sig, passwd, salt);
	if (rc < 0) {
		free(auth_tok_sig);
		goto out;
	}
	rc = asprintf(&param, "tse_sig=%s", auth_tok_sig);
	if (rc == -1) {
		free(auth_tok_sig);
		rc = -ENOMEM;
		goto out;
	}
	free(auth_tok_sig);
	rc = stack_push(head, param);
out:
	free(salt_hex);
	free(passwd);
	if (rc)
		return rc;
	return DEFAULT_TOK;
}

#define TSE_PASSPHRASE_TOK 0
#define TSE_PASSWD_TOK 1
#define TSE_PASS_FILE_TOK 2
#define TSE_PASS_FD_TOK 3
#define TSE_SALT_TOK 4
struct param_node passphrase_param_nodes[] = {
	/* TSE_PASSPHRASE_TOK = 0 */
	{.num_mnt_opt_names = 1,
	 .mnt_opt_names = {"passphrase_type"},
	 .prompt = "Method for providing the passphrase",
	 .val_type = VAL_STR,
	 .val = NULL,
	 .display_opts = NULL,
	 .default_val = "passphrase_passwd",
	 .flags = (TSE_PARAM_FLAG_NO_VALUE
		   | TSE_ALLOW_IMPLICIT_TRANSITION
		   | TSE_IMPLICIT_OVERRIDE_DEFAULT),
	 .num_transitions = 3,
	 .tl = {{.val = "passphrase_passwd",
		 .pretty_val = "Provide passphrase directly",
		 .next_token = &passphrase_param_nodes[TSE_PASSWD_TOK],
		 .trans_func = NULL},
		{.val = "passphrase_passwd_file",
		 .pretty_val = "File containing passphrase (only use secure "
		 "media)",
		 .next_token = &passphrase_param_nodes[TSE_PASS_FILE_TOK],
		 .trans_func = NULL},
		{.val = "passphrase_passwd_fd",
		 .pretty_val = "File descriptor for file containing passphrase",
		 .next_token = &passphrase_param_nodes[TSE_PASS_FD_TOK],
		 .trans_func = NULL}}},

	/* TSE_PASSWD_TOK = 1 */
	{.num_mnt_opt_names = 2,
	 .mnt_opt_names = {"passphrase_passwd", "passwd"},
	 .prompt = "Passphrase",
	 .val_type = VAL_STR,
	 .val = NULL,
	 .display_opts = NULL,
	 .default_val = NULL,
	 .flags = (TSE_PARAM_FLAG_MASK_OUTPUT
		   | TSE_NONEMPTY_VALUE_REQUIRED),
	 .num_transitions = 2,
	 .tl = {{.val = "passphrase_salt",
		 .pretty_val = "salt",
		 .next_token = &passphrase_param_nodes[TSE_SALT_TOK],
		 .trans_func = tf_passwd},
		{.val = "default",
		 .pretty_val = "default",
		 .next_token = &passphrase_param_nodes[TSE_SALT_TOK],
		 .trans_func = tf_passwd}}},

	/* TSE_PASS_FILE_TOK = 2 */
	{.num_mnt_opt_names = 2,
	 .mnt_opt_names = {"passphrase_passwd_file", "passfile"},
	 .prompt = "Passphrase File",
	 .val_type = VAL_STR,
	 .val = NULL,
	 .display_opts = NULL,
	 .default_val = NULL,
	 .flags = TSE_PARAM_FLAG_ECHO_INPUT
		  | TSE_NONEMPTY_VALUE_REQUIRED,
	 .num_transitions = 2,
	 .tl = {{.val = "passphrase_salt",
		 .pretty_val = "salt",
		 .next_token = &passphrase_param_nodes[TSE_SALT_TOK],
		 .trans_func = tf_pass_file},
		{.val = "default",
		 .pretty_val = "default",
		 .next_token = &passphrase_param_nodes[TSE_SALT_TOK],
		 .trans_func = tf_pass_file}}},

	/* TSE_PASS_FD_TOK = 3 */
	{.num_mnt_opt_names = 2,
	 .mnt_opt_names = {"passphrase_passwd_fd", "passfd"},
	 .prompt = "Passphrase File Discriptor",
	 .val_type = VAL_STR,
	 .val = NULL,
	 .display_opts = NULL,
	 .default_val = NULL,
	 .flags = TSE_PARAM_FLAG_ECHO_INPUT
		  | TSE_NONEMPTY_VALUE_REQUIRED,
	 .num_transitions = 2,
	 .tl = {{.val = "salt",
		 .pretty_val = "salt",
		 .next_token = &passphrase_param_nodes[TSE_SALT_TOK],
		 .trans_func = tf_pass_file},
		{.val = "default",
		 .pretty_val = "default",
		 .next_token = &passphrase_param_nodes[TSE_SALT_TOK],
		 .trans_func = tf_pass_file}}},

	/* TSE_SALT_TOK = 4 */
	{.num_mnt_opt_names = 2,
	 .mnt_opt_names = {"passphrase_salt", "salt"},
	 .prompt = "Salt (hexadecimal representation)",
	 .val_type = VAL_HEX,
	 .val = NULL,
	 .display_opts = NULL,
	 .default_val = TSE_DEFAULT_SALT_HEX,
	 .flags = 0,
	 .num_transitions = 1,
	 .tl = {{.val = NULL,
		 .pretty_val = NULL,
		 .next_token = NULL,
		 .trans_func = tf_salt}}},
};

struct transition_node passphrase_transition = {
	.val = "passphrase",
	.pretty_val = "Passphrase",
	.next_token = &(passphrase_param_nodes[0]),
	.trans_func = NULL
};

static int tse_passphrase_get_param_subgraph_trans_node(
	struct transition_node **trans, uint32_t version)
{
	if ((version & TSE_VERSIONING_PASSPHRASE) == 0)
		return -1;
	*trans = &passphrase_transition;
	return 0;
}

static int tse_passphrase_init(char **alias)
{
	int rc = 0;

	if (asprintf(alias, "passphrase") == -1) {
		syslog(LOG_ERR, "Out of memory\n");
		rc = -ENOMEM;
		goto out;
	}
out:
	return rc;
}

static int tse_passphrase_destroy(unsigned char *blob)
{
	return 0;
}

static int tse_passphrase_finalize(void)
{
	return 0;
}

struct tse_key_mod_ops tse_passphrase_ops = {
	&tse_passphrase_init,
	NULL,
	NULL,
	NULL,
	&tse_passphrase_get_param_subgraph_trans_node,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	&tse_passphrase_destroy,
	&tse_passphrase_finalize
};

struct tse_key_mod_ops *get_key_mod_ops(void)
{
	return &tse_passphrase_ops;
}

/**
 * Builtin handle
 */
struct tse_key_mod_ops *passphrase_get_key_mod_ops(void)
{
	return get_key_mod_ops();
}
