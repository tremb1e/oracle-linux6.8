/**
 * Copyright (C) 2006 International Business Machines
 * Author(s): Michael A. Halcrow <mhalcrow@us.ibm.com>
 *            Stephan Mueller <smueller@chronox.de>
 *            Tyler Hicks <tyhicks@ou.edu>
 *            Michael C. Thompson <mcthomps@us.ibm.com>
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
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <keyutils.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pwd.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "config.h"
#include "tse.h"
#include "decision_graph.h"
#include "io.h"

#define NUM_REQUIRED_ARGS 3

static void usage()
{
	fprintf(stderr, "\tTse mount helper\n\tusage: "
		"mount -t tse [lower directory] [tse mount point]\n"
		"\n"
		"See the README file in the tse-utils package for "
		"complete usage guidelines.\n"
		);
	exit(-EINVAL);
}

/**
 * This function will malloc any argument that is passed in as non-NULL.
 * In the event of a failure, all returned pointers are invalid and no
 * memory is left allocated.
 *
 * returns 0 on success
 */
static int parse_arguments(int argc, char **argv, char **src, char **target,
			   char **options)
{
	int rc = 0;
	char *ptr;
	size_t len;

	if (src)
		*src = NULL;
	if (target)
		*target = NULL;
	if (options)
		*options = NULL;

	if (src) {
		ptr = argv[1];
		len = strlen(ptr) + 1; /* + NULL terminator */
		*src = malloc(len);
		if (!*src) {
			fprintf(stderr, "Unable to allocate source buffer\n");
			rc = -ENOMEM;
			goto out;
		}
		memcpy(*src, ptr, len);
		if ((*src)[len - 1] == '/')
			(*src)[len - 1] = '\0';
	}
	if (target) {
		ptr = argv[2];
		len = strlen(ptr) + 1; /* + NULL-terminator */
		*target = malloc(len);
		if (!*target) {
			fprintf(stderr, "Unable to allocate target buffer\n");
			rc = -ENOMEM;
			goto out;
		}
		memcpy(*target, ptr, len);
		if ((*target)[len - 1] == '/')
			(*target)[len - 1] = '\0';
	}
	if ((options) && (argc >= NUM_REQUIRED_ARGS)) {
		int i;

		ptr = NULL;
		for (i = 3; i < (argc-1); i++)
			if (!strcmp("-o", argv[i])) {
				ptr = argv[i+1];
				break;
			}
		if (!ptr) {
			fprintf(stderr, "Unable to find a list of options to "
					"parse, defaulting to interactive "
					"mount\n");
			return 0;
		}
		len = strlen(ptr) + 1; /* + NULL-terminator */
		*options = malloc(len);
		if (!*options){
			fprintf(stderr, "Unable to allocate memory for options "
					"buffer\n");
			rc = -ENOMEM;
			goto out;
		}
		memcpy(*options, ptr, len);
	}
	return 0;
out:
	if (src && *src)
		free(*src);
	if (target && *target)
		free(*target);
	if (options && *options)
		free(*options);
	return rc;
}

static int tse_generate_mount_flags(char *options, int *flags)
{
	char *opt;
	char *next_opt;
	char *end;
	int num_options = 0;

	if (!options)
		return 0;

	end = strchr(options, '\0');
	opt = options;
	while (opt) {
		if ((next_opt = strchr(opt, ',')))
			next_opt++;
		/* the following mount options should be
		 * stripped out from what is passed into the
		 * kernel since these eight options are best
		 * passed as the mount flags rather than
		 * redundantly to the kernel and could
		 * generate spurious warnings depending on the
		 * level of the corresponding cifs vfs kernel
		 * code */
		if (!strncmp(opt, "nosuid", 6))
			*flags |= MS_NOSUID;
		else if (!strncmp(opt, "suid", 4))
			*flags &= ~MS_NOSUID;
		else if (!strncmp(opt, "nodev", 5))
			*flags |= MS_NODEV;
		else if (!strncmp(opt, "dev", 3))
			*flags &= ~MS_NODEV;
		else if (!strncmp(opt, "noexec", 6))
			*flags |= MS_NOEXEC;
		else if (!strncmp(opt, "exec", 4))
			*flags &= ~MS_NOEXEC;
		else if (!strncmp(opt, "ro", 2))
			*flags |= MS_RDONLY;
		else if (!strncmp(opt, "rw", 2))
			*flags &= ~MS_RDONLY;
		else if (!strncmp(opt, "remount", 7))
			*flags |= MS_REMOUNT;
		else {
			opt = next_opt;
			num_options++;
			continue;
		}
		if (!next_opt) {
			if (opt != options)
				end = --opt;
			else
				end = options;
			*end = '\0';
			break;
		}
		memcpy(opt, next_opt, end - next_opt);
		end = end - (next_opt - opt);
		*end = '\0';
	}
	return num_options;
}

char *parameters_to_scrub[] = {
	"key=",
	"cipher=",
	"passthrough",
	"tse_passthrough",
	"hmac",
	"tse_hmac",
	"xattr",
	"tse_xattr",
	"encrypted_view",
	"tse_encrypted_view",
	"user",
	"sig",
	"no_sig_cache",
	"verbose",
	"verbosity",
	"tse_enable_filename_crypto",
	NULL
};

char *parameters_to_not_scrub[] = {
	"xattr_user",
	NULL
};

static int parameter_should_not_be_scrubbed(char *str) {
	int i;

	for (i = 0; parameters_to_not_scrub[i]; i++)
		if (strstr(str, parameters_to_not_scrub[i]) == str)
			return 1;
	return 0;
}

static int parameter_should_be_scrubbed(char *str)
{
	int i;

	for (i = 0; parameters_to_scrub[i]; i++)
		if (strstr(str, parameters_to_scrub[i]) == str
		    && !parameter_should_not_be_scrubbed(str))
			return 1;
	return 0;
}

/**
 * Remove from the options string known options which should not be passed
 * into the kernel. Any options that are unknown will be passed in.
 * This is to account for options like "rw".
 *
 * Returns zero on success, non-zero otherwise
 */
static int strip_userland_opts(char *options)
{
	char *cur = NULL, *next = NULL;
	char *temp, *temp_end;
	size_t len;
	int used = 0, first = 1;

	if (!options)
		return 0;

	len = (strlen(options) + 1);
	if ((temp = (char*)malloc(len)) == NULL) {
		fprintf(stderr, "Out of memory\n");
		return -1;
	}
	temp_end = temp;
	memset(temp, 0, len);
	cur = options;
	while (cur) {
		int opt_len;

		next = strstr(cur, ",");
		if (next) {
			*next='\0';
			next++;
		}
		if (!parameter_should_be_scrubbed(cur)) {
			if (!first) {
				memcpy(temp_end, ",", 1);
				temp_end++;
			}
			opt_len = strlen(cur);
			memcpy(temp_end, cur, opt_len);
			temp_end = temp_end + opt_len;
			used += opt_len;
			first = 0;
		}
		cur = next;
	}
	memcpy(options,temp,len);
	free(temp);
	return 0;
}

static int process_sig(char *auth_tok_sig, struct passwd *pw)
{
	char *home;
	char *sig_cache_filename = NULL;
	char *dot_tse_dir;
	int flags;
	char *yesno = NULL;
	int rc;
	int tries;

	home = pw->pw_dir;
	rc = asprintf(&dot_tse_dir, "%s/.tse", home);
	if (rc == -1) {
		rc = -ENOMEM;
		goto out;
	}
	mkdir(dot_tse_dir, S_IRWXU);
	if (chown(dot_tse_dir, getuid(), getgid()) == -1)
		printf("Can't change ownership of sig file; "
		       "errno = [%d]; [%m]\n", errno);
	free(dot_tse_dir);
	rc = asprintf(&sig_cache_filename, "%s/.tse/sig-cache.txt",
		      home);
	if (rc == -1) {
		rc = -ENOMEM;
		goto out;
	}
	flags = 0;
	if ((rc = tse_check_sig(auth_tok_sig, sig_cache_filename,
				     &flags)))
		goto out;
	if (flags & TSE_SIG_FLAG_NOENT) {
		printf("WARNING: Based on the contents of [%s],\n"
		       "it looks like you have never mounted with this key \n"
		       "before. This could mean that you have typed your \n"
		       "passphrase wrong.\n\n", sig_cache_filename);
		tries = 0;
		yesno = NULL;
		do {
			free(yesno);
			if ((rc = get_string_stdin(&yesno,
			       "Would you like to proceed with "
			       "the mount (yes/no)? ",TSE_ECHO_ON)))
				goto out;
		} while ((rc = strcmp(yesno, "yes")) && strcmp(yesno, "no")
			 && (++tries < 5));
		if (rc == 0) {
			tries = 0;
			do {
				free(yesno);
				printf("Would you like to append sig [%s] to\n"
				       "[%s] \nin order to avoid this warning "
				       "in the future", auth_tok_sig,
				       sig_cache_filename);
				if ((rc = get_string_stdin(&yesno," (yes/no)? ",
					TSE_ECHO_ON)))
					goto out;
			} while ((rc = strcmp(yesno, "yes")) 
				 && strcmp(yesno, "no") && (++tries < 5));
			if (rc == 0) {
				if ((rc = tse_append_sig(
					    auth_tok_sig,
					    sig_cache_filename))) {
					printf("Error appending to [%s]; rc = "
					"[%d]. Aborting mount.\n",
					sig_cache_filename, rc);
					goto out;
				}
				printf("Successfully appended new sig to user "
					"sig cache file\n");
			} else {
				if (strcmp(yesno,"no"))
					rc = -EINVAL;
				else {
					printf("Not adding sig to user sig "
					       "cache file; continuing with "
					       "mount.\n");
					rc = 0;
				}
			}
		} else {
			if (strcmp(yesno,"no"))
				rc = -EINVAL;
			printf("Aborting mount.\n");
			rc = ECANCELED;
			goto out;
		}
	}
out:
	free(yesno);
	free(sig_cache_filename);
	return rc;
}

static int opts_str_contains_option(char *options, char *option)
{
	char *opt;
	char *next_opt;
	char *end;

	if (!options || !option)
		return 0;

	int option_len = strlen(option);

	end = strchr(options, '\0');
	opt = options;
	while (opt) {
		if ((next_opt = strchr(opt, ',')))
			next_opt++;
		if (!strncmp(opt, option, option_len))
			return 1;
		else {
			opt = next_opt;
			continue;
		}
		if (!next_opt) {
			if (opt != options)
				end = --opt;
			else
				end = options;
			*end = '\0';
			break;
		}
		memcpy(opt, next_opt, end - next_opt);
		end = end - (next_opt - opt);
		*end = '\0';
	}
	return 0;
}

char *required_mount_opts[] = {
	"tse_key_bytes=",
	NULL
};

static int tse_validate_mount_opts(char *opts)
{
	int i = 0;
	int rc = 0;

	while (required_mount_opts[i]) {
		if (!opts_str_contains_option(opts, required_mount_opts[i])) {
			printf("Required mount option not provided: [%s]\n",
			       required_mount_opts[i]);
			rc = -EINVAL;
			goto out;
		}
		i++;
	}
out:
	return rc;
}

/**
 * tse_do_mount
 * @params:
 *
 * The mount options actually sent to the kernel are in the @params
 * linked list of struct val_node objects. params <-
 * tse_process_decision_graph(head) -> decision_graph_mount(head)
 * -> eval_param_tree(val_stack_head) -> do_transition(val_stack_head)
 * -> trans_func(head). 
 */
static int tse_do_mount(int argc, char **argv, struct val_node *mnt_params,
			     int sig_cache, struct passwd *pw)
{
	int rc;
	int flags = 0;
	int num_opts = 0;
	char *src = NULL, *targ = NULL, *opts = NULL, *new_opts = NULL, *temp;
	char *val;

	if ((rc = parse_arguments(argc, argv, &src, &targ, &opts))) {
		fprintf(stderr, "Unable to understand the mount options\n");
		goto out;
	}
	rc = strip_userland_opts(opts);
	if (rc)
		goto out;
	num_opts = tse_generate_mount_flags(opts, &flags);
	if (!(temp = strdup("tse_unlink_sigs"))) {
		rc = -ENOMEM;
		goto out;
	}
	if ((rc = stack_push(&mnt_params, (void *)temp)))
		goto out;
	printf("Attempting to mount with the following options:\n");
	new_opts = opts;
	opts = NULL;
	while (!stack_pop_val(&mnt_params, (void *)&val)) {
		if(!val)
			break;
		temp = new_opts;
		printf("  %s\n", val);
		if (sig_cache && memcmp(val, "tse_sig=", 13) == 0) {
			if ((rc = process_sig(&val[13], pw))) {
				if (rc != ECANCELED)
					printf("Error processing sig; "
					       "rc = [%d]\n", rc);
				goto out;
			}
		}
		if (!temp || !strstr(temp, val)) {
			rc = asprintf(&new_opts, "%s%c%s", val,
				      ((temp && *temp) ? ',' : '\0'), temp);
			if (rc == -1) {
				new_opts = NULL;
				rc = -ENOMEM;
				goto out;
			}
			free(temp);
		}
		rc = 0;
	}
	if ((rc = tse_validate_mount_opts(new_opts)) != 0) {
		printf("Invalid mount options; aborting. rc = [%d]\n",
		       rc);
		goto out;
	}
	rc = tse_mount(src, targ, flags, new_opts);
out:
	free(src);
	free(targ);
	free(opts);
	free(new_opts);
	return rc;
}

static int dump_args = 0;

int main(int argc, char **argv)
{
	uint32_t version;
	char *opts_str;
	struct val_node *mnt_params;
	struct tse_ctx ctx;
	int sig_cache = 1;
	int rc;
	struct passwd *pw;

	/* Nasty hack;  On some systems, this need to run before we mlock.
	 * See:
	 *     https://bugs.launchpad.net/ubuntu/+source/glibc/+bug/329264
	 */
	pw = getpwuid(getuid());
	if (!pw) {
		fprintf(stderr, "Exiting. Unable to obtain passwd info\n");
		rc = -EIO;
		goto out;
	}

	rc = mlockall(MCL_FUTURE);
	if (rc) {
		fprintf(stderr, "Exiting. Unable to mlockall address space: %m\n");
		return -1;
	}
	if (dump_args) {
		int i;

		for (i = 0; i < argc; i++)
			printf("argv[%d] = [%s]\n", i, argv[i]);
	}
	if (argc < NUM_REQUIRED_ARGS) {
		fprintf(stderr, "Insufficient number of arguments\n");
		usage();
		rc = -EINVAL;
		goto out;
	}
	rc = tse_get_version(&version);
	if (rc) {
		printf("\nUnable to get the version number of the kernel\n");
		printf("module. Please make sure that you have the Tse\n");
		printf("kernel module loaded, you have sysfs mounted, and\n");
		printf("the sysfs mount point is in /etc/mtab. This is\n");
		printf("necessary so that the mount helper knows which \n");
		printf("kernel options are supported.\n\n");
		printf("Make sure that your system is set up to auto-load\n"
		       "your filesystem kernel module on mount.\n\n");
		printf("Enabling passphrase-mode only for now.\n\n");
		version = TSE_VERSIONING_PASSPHRASE;
	}
	if ((rc = tse_validate_keyring())) {
		printf("Unable to link the KEY_SPEC_USER_KEYRING into the "
		       "KEY_SPEC_SESSION_KEYRING; there is something wrong "
		       "with your kernel keyring. Did you build key retention "
		       "support into your kernel?\n");
		goto out;
	}
	mnt_params = malloc(sizeof(struct val_node));
	memset(mnt_params, 0, sizeof(struct val_node));
	memset(&ctx, 0, sizeof(struct tse_ctx));
	ctx.get_string = &get_string_stdin;
	if ((rc = parse_arguments(argc, argv, NULL, NULL, &opts_str)))
		goto out;
	if (opts_str_contains_option(opts_str, "verbose"))
		tse_verbosity = 1;
	if (!opts_str_contains_option(opts_str, "remount")) {
		if (opts_str_contains_option(opts_str, "no_sig_cache"))
			sig_cache = 0;
		if (opts_str_contains_option(opts_str, "no_prompt")
		    || opts_str_contains_option(opts_str, "wild_ass_guess")) {
			if (!opts_str_contains_option(opts_str,
						      "verbosity=0")) {
				char *tmp;

				rc = asprintf(&tmp, "%s,verbosity=0", opts_str);
				if (rc == -1) {
					rc = -ENOMEM;
					goto out;
				}
				rc = 0;
				opts_str = tmp;
			}
		}
		if (opts_str_contains_option(opts_str, "verbosity=0"))
			sig_cache = 0;
		rc = tse_process_decision_graph(
			&ctx, &mnt_params, version, opts_str,
			TSE_ASK_FOR_ALL_MOUNT_OPTIONS);
		if (rc) {
			if (rc > 0) 
				rc = -EINVAL;
			printf("Error attempting to evaluate mount options: "
			       "[%d] %s\nCheck your system logs for details "
			       "on why this happened.\nTry updating your "
			       "tse-utils package, and/or\nsubmit a bug "
			       "report on https://launchpad.net/tse\n",
				rc, strerror(-rc));
			goto out;
		}
		rc = tse_do_mount(argc, argv, mnt_params, sig_cache, pw);
		if (rc == ECANCELED) {
		    rc = 0;
		    goto out;
		}
		if (rc) {
			if (rc > 0)
				rc = -rc;
			printf("Error mounting Tse: [%d] %s\n"
			       "Check your system logs; visit "
			       "<http://launchpad.net/tse>\n",
			       rc, strerror(-rc));
			if (rc == -ENODEV)
				printf("Try ``modprobe tse''\n");
		} else
			printf("Mounted Tse\n");
	} else {
		fprintf(stderr, "When are remounting Tse, you need "
			"to pass the mount utility the -i parameter to avoid "
			"calling the mount helper\n");
		rc = -EINVAL;
	}

out:
	munlockall();
	return rc;
}
