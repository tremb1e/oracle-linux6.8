/**
 * pam_tse.c: PAM module that sends the user's authentication
 * tokens into the kernel keyring.
 *
 * Copyright (C) 2007 International Business Machines
 * Author(s): Michael Halcrow <mhalcrow@us.ibm.com>
 *            Dustin Kirkland <kirkland@canonical.com>
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
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <syslog.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <security/pam_modules.h>
#include "../include/tse.h"

#define PRIVATE_DIR "Private"

static void error(const char *msg)
{
	syslog(LOG_ERR, "errno = [%i]; strerror = [%m]\n", errno);
	switch (errno) {
	case ENOKEY:
		syslog(LOG_ERR, "%s: Requested key not available\n", msg);
		return;

	case EKEYEXPIRED:
		syslog(LOG_ERR, "%s: Key has expired\n", msg);
		return;

	case EKEYREVOKED:
		syslog(LOG_ERR, "%s: Key has been revoked\n", msg);
		return;

	case EKEYREJECTED:
		syslog(LOG_ERR, "%s: Key was rejected by service\n", msg);
		return;
	default:
		syslog(LOG_ERR, "%s: Unknown key error\n", msg);
		return;
	}
}

/* returns: 0 for pam automounting not set, 1 for set, <0 for error */
static int tse_pam_automount_set(const char *homedir)
{
	char *file_path;
	int rc = 0;
	struct stat s;
	if (asprintf(
		&file_path, "%s/.tse/%s",
		homedir,
		TSE_DEFAULT_WRAPPED_PASSPHRASE_FILENAME) == -1)
		return -ENOMEM;
	if (stat(file_path, &s) != 0) {
		if (errno != ENOENT)
			rc = -errno;
		goto out;
	}
	free(file_path);
	if (asprintf(&file_path, "%s/.tse/auto-mount", homedir) == -1)
		return -ENOMEM;
	if (stat(file_path, &s) != 0) {
		if (errno != ENOENT)
			rc = -errno;
		goto out;
	}
	rc = 1;
out:
	free(file_path);
	return rc;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
				   const char **argv)
{
	uid_t uid = 0;
	char *homedir = NULL;
	uid_t saved_uid = 0;
	const char *username;
	char *passphrase = NULL;
	char salt[TSE_SALT_SIZE];
	char salt_hex[TSE_SALT_SIZE_HEX];
	char *auth_tok_sig;
	char *private_mnt = NULL;
	pid_t child_pid, tmp_pid;
	long rc;
	uint32_t version;

	syslog(LOG_INFO, "%s: Called\n", __FUNCTION__);
	rc = pam_get_user(pamh, &username, NULL);
	if (rc == PAM_SUCCESS) {
		struct passwd *pwd;

		syslog(LOG_INFO, "%s: username = [%s]\n", __FUNCTION__,
		       username);
		pwd = getpwnam(username);
		if (pwd) {
			uid = pwd->pw_uid;
			homedir = pwd->pw_dir;
		}
	} else {
		syslog(LOG_ERR, "Error getting passwd info for user [%s]; "
		       "rc = [%ld]\n", username, rc);
		goto out;
	}
	if (!tse_pam_automount_set(homedir))
		goto out;
	private_mnt = tse_fetch_private_mnt(homedir);
	if (tse_private_is_mounted(NULL, private_mnt, NULL, 1))
		/* If private/home is already mounted, then we can skip
		   costly loading of keys */
		goto out;
	/* we need side effect of this check:
	   load tse module if not loaded already */
	if (tse_get_version(&version) != 0)
		syslog(LOG_WARNING, "Can't check if kernel supports tse\n");
	saved_uid = geteuid();
	seteuid(uid);
	rc = pam_get_item(pamh, PAM_AUTHTOK, (const void **)&passphrase);
	seteuid(saved_uid);
	if (rc != PAM_SUCCESS) {
		syslog(LOG_ERR, "Error retrieving passphrase; rc = [%ld]\n",
		       rc);
		goto out;
	}
	auth_tok_sig = malloc(TSE_SIG_SIZE_HEX + 1);
	if (!auth_tok_sig) {
		rc = -ENOMEM;
		syslog(LOG_ERR, "Out of memory\n");
		goto out;
	}
	rc = tse_read_salt_hex_from_rc(salt_hex);
	if (rc) {
		from_hex(salt, TSE_DEFAULT_SALT_HEX, TSE_SALT_SIZE);
	} else
		from_hex(salt, salt_hex, TSE_SALT_SIZE);
	if ((child_pid = fork()) == 0) {
		setuid(uid);
		if (passphrase == NULL) {
			syslog(LOG_ERR, "NULL passphrase; aborting\n");
			rc = -EINVAL;
			goto out_child;
		}
		if ((rc = tse_validate_keyring())) {
			syslog(LOG_WARNING,
			       "Cannot validate keyring integrity\n");
		}
		rc = 0;
		if ((argc == 1)
		    && (memcmp(argv[0], "unwrap\0", 7) == 0)) {
			char *wrapped_pw_filename;

			rc = asprintf(
				&wrapped_pw_filename, "%s/.tse/%s",
				homedir,
				TSE_DEFAULT_WRAPPED_PASSPHRASE_FILENAME);
			if (rc == -1) {
				syslog(LOG_ERR, "Unable to allocate memory\n");
				rc = -ENOMEM;
				goto out_child;
			}
			rc = tse_insert_wrapped_passphrase_into_keyring(
				auth_tok_sig, wrapped_pw_filename, passphrase,
				salt);
			free(wrapped_pw_filename);
		} else {
			rc = tse_add_passphrase_key_to_keyring(
				auth_tok_sig, passphrase, salt);
		}
		if (rc == 1) {
			goto out_child;
		}
		if (rc) {
			syslog(LOG_ERR, "Error adding passphrase key token to "
			       "user session keyring; rc = [%ld]\n", rc);
			goto out_child;
		}
		if (fork() == 0) {
			if ((rc = tse_set_zombie_session_placeholder())) {
				syslog(LOG_ERR, "Error attempting to create "
						"and register zombie process; "
						"rc = [%ld]\n", rc);
			}
		}
out_child:
		free(auth_tok_sig);
		exit(0);
	}
	tmp_pid = waitpid(child_pid, NULL, 0);
	if (tmp_pid == -1)
		syslog(LOG_WARNING,
		       "waitpid() returned with error condition\n");
out:
	if (private_mnt != NULL)
		free(private_mnt);
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc,
			      const char **argv)
{
	return PAM_SUCCESS;
}

static struct passwd *fetch_pwd(pam_handle_t *pamh)
{
	long rc;
	const char *username = NULL;
	struct passwd *pwd = NULL;

	rc = pam_get_user(pamh, &username, NULL);
	if (rc != PAM_SUCCESS || username == NULL) {
		syslog(LOG_ERR, "Error getting passwd info for user [%s]; "
				"rc = [%ld]\n", username, rc);
		return NULL;
	}
	pwd = getpwnam(username);
	if (pwd == NULL) {
		syslog(LOG_ERR, "Error getting passwd info for user [%s]; "
				"rc = [%ld]\n", username, rc);
		return NULL;
	}
	return pwd;
}

static int private_dir(pam_handle_t *pamh, int mount)
{
	int rc, fd;
	struct passwd *pwd = NULL;
	char *sigfile = NULL;
	char *autofile = NULL;
	char *recorded = NULL;
	char *a;
	char *automount = "auto-mount";
	char *autoumount = "auto-umount";
	struct stat s;
	pid_t pid;
	struct utmp *u;
	int count = 0;

	if ((pwd = fetch_pwd(pamh)) == NULL) {
		/* fetch_pwd() logged a message */
		return 1;
	}
	if (mount == 1) {
		a = automount;
	} else {
		a = autoumount;
	}
	if (
	    (asprintf(&autofile, "%s/.tse/%s", pwd->pw_dir, a) < 0)
	     || autofile == NULL) {
		syslog(LOG_ERR, "Error allocating memory for autofile name");
		return 1;
        }
        if (
	    (asprintf(&sigfile, "%s/.tse/%s.sig", pwd->pw_dir,
	     PRIVATE_DIR) < 0) || sigfile == NULL) {
		syslog(LOG_ERR, "Error allocating memory for sigfile name");
		return 1;
        }
	if (stat(sigfile, &s) != 0) {
		/* No sigfile, no need to mount private dir */
		goto out;
	}
	if (!S_ISREG(s.st_mode)) {
		/* No sigfile, no need to mount private dir */
		goto out;
	}
	if ((pid = fork()) < 0) {
		syslog(LOG_ERR, "Error setting up private mount");
		return 1;
	}
	if (pid == 0) {
		if (mount == 1) {
		        if ((asprintf(&recorded,
			    "%s/.tse/.wrapped-passphrase.recorded",
			    pwd->pw_dir) < 0) || recorded == NULL) {
				syslog(LOG_ERR,
				   "Error allocating memory for recorded name");
				return 1;
			}
			if (stat(recorded, &s) != 0 && stat("/usr/share/tse-utils/tse-record-passphrase", &s) == 0) {
				/* User has not recorded their passphrase */
				unlink("/var/lib/update-notifier/user.d/tse-record-passphrase");
				symlink("/usr/share/tse-utils/tse-record-passphrase", "/var/lib/update-notifier/user.d/tse-record-passphrase");
				fd = open("/var/lib/update-notifier/dpkg-run-stamp", O_WRONLY|O_CREAT|O_NONBLOCK, 0666);
				close(fd);
			}
			if (stat(autofile, &s) != 0) {
				/* User does not want to auto-mount */
				syslog(LOG_INFO,
					"Skipping automatic Tse mount");
				return 0;
			}
			/* run mount.tse_private as the user */
			setresuid(pwd->pw_uid, pwd->pw_uid, pwd->pw_uid);
			execl("/sbin/mount.tse_private",
			      "mount.tse_private", NULL);
		} else {
			if (stat(autofile, &s) != 0) {
				/* User does not want to auto-unmount */
				syslog(LOG_INFO,
					"Skipping automatic Tse unmount");
				return 0;
			}
			/* run umount.tse_private as the user */
			setresuid(pwd->pw_uid, pwd->pw_uid, pwd->pw_uid);
			execl("/sbin/umount.tse_private",
 			      "umount.tse_private", NULL);
		}
		return 1;
	} else {
		waitpid(pid, &rc, 0);
		goto out;
	}
out:
	return 0;
}

static int mount_private_dir(pam_handle_t *pamh)
{
	return private_dir(pamh, 1);
}

static int umount_private_dir(pam_handle_t *pamh)
{
	return private_dir(pamh, 0);
}

PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int flags,
		    int argc, const char *argv[])
{
	mount_private_dir(pamh);
	return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh, int flags,
		     int argc, const char *argv[])
{
	umount_private_dir(pamh);
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t * pamh, int flags,
                                int argc, const char **argv)
{
	uid_t uid = 0;
	char *homedir = NULL;
	uid_t saved_uid = 0;
	const char *username;
	char *old_passphrase = NULL;
	char *new_passphrase = NULL;
	char *wrapped_pw_filename;
	char *unwrapped_pw_filename;
	char *name = NULL;
	char salt[TSE_SALT_SIZE];
	char salt_hex[TSE_SALT_SIZE_HEX];
	pid_t child_pid, tmp_pid;
	struct stat s;
	int rc = PAM_SUCCESS;

	rc = pam_get_user(pamh, &username, NULL);
	if (rc == PAM_SUCCESS) {
		struct passwd *pwd;

		pwd = getpwnam(username);
		if (pwd) {
			uid = pwd->pw_uid;
			homedir = pwd->pw_dir;
			name = pwd->pw_name;
		}
	} else {
		syslog(LOG_ERR, "Error getting passwd info for user [%s]; "
		       "rc = [%ld]\n", username, rc);
		goto out;
	}
	saved_uid = geteuid();
	seteuid(uid);
	if ((rc = pam_get_item(pamh, PAM_OLDAUTHTOK,
			       (const void **)&old_passphrase))
	    != PAM_SUCCESS) {
		syslog(LOG_ERR, "Error retrieving old passphrase; rc = [%d]\n",
		       rc);
		seteuid(saved_uid);
		goto out;
	}
	/* On the first pass, do nothing except check that we have a password */
	if ((flags & PAM_PRELIM_CHECK)) {
		if (!old_passphrase)
		{
			syslog(LOG_WARNING, "Tse PAM passphrase change "
			       "module retrieved a NULL passphrase; nothing to "
			       "do\n");
			rc = PAM_AUTHTOK_RECOVER_ERR;
		}
		seteuid(saved_uid);
		goto out;
	}
	if ((rc = pam_get_item(pamh, PAM_AUTHTOK,
			       (const void **)&new_passphrase))
	    != PAM_SUCCESS) {
		syslog(LOG_ERR, "Error retrieving new passphrase; rc = [%d]\n",
		       rc);
		seteuid(saved_uid);
		goto out;
	}
	if ((rc = asprintf(&wrapped_pw_filename, "%s/.tse/%s", homedir,
			   TSE_DEFAULT_WRAPPED_PASSPHRASE_FILENAME))
	    == -1) {
		syslog(LOG_ERR, "Unable to allocate memory\n");
		rc = -ENOMEM;
		goto out;
	}
	rc = asprintf(&unwrapped_pw_filename, "/dev/shm/.tse-%s", name);
	if (rc == -1) {
		syslog(LOG_ERR, "Unable to allocate memory\n");
		rc = -ENOMEM;
		goto out;
	}
	if ((rc = tse_read_salt_hex_from_rc(salt_hex))) {
		from_hex(salt, TSE_DEFAULT_SALT_HEX, TSE_SALT_SIZE);
	} else {
		from_hex(salt, salt_hex, TSE_SALT_SIZE);
	}
	/* If /dev/shm/.tse-$USER exists and owned by the user
	   and ~/.tse/wrapped-passphrase does not exist
	   and a new_passphrase is set:
	   wrap the unwrapped passphrase file */
	if (stat(unwrapped_pw_filename, &s) == 0 && (s.st_uid == uid) &&
	    stat(wrapped_pw_filename, &s) != 0  &&
	    new_passphrase != NULL && *new_passphrase != '\0' &&
	    name != NULL && *name != '\0') {
		setuid(uid);
		rc = tse_wrap_passphrase_file(wrapped_pw_filename,
			new_passphrase, salt, unwrapped_pw_filename);
		if (rc != 0) {
			syslog(LOG_ERR,
			  "Error wrapping cleartext password; "
	       		  "rc = [%d]\n", rc);
		}
		goto out;
	}
	seteuid(saved_uid);
	if (!old_passphrase || !new_passphrase || *new_passphrase == '\0') {
		syslog(LOG_WARNING, "Tse PAM passphrase change module "
		       "retrieved at least one NULL passphrase; nothing to "
		       "do\n");
		rc = PAM_AUTHTOK_RECOVER_ERR;
		goto out;
	}
	rc = PAM_SUCCESS;
	if ((child_pid = fork()) == 0) {
		char passphrase[TSE_MAX_PASSWORD_LENGTH + 1];

		setuid(uid);
		if ((rc = tse_unwrap_passphrase(passphrase,
						     wrapped_pw_filename,
						     old_passphrase, salt))) {
			syslog(LOG_ERR, "Error attempting to unwrap "
			       "passphrase; rc = [%d]\n", rc);
			goto out_child;
		}
		if ((rc = tse_wrap_passphrase(wrapped_pw_filename,
						   new_passphrase, salt,
						   passphrase))) {
			syslog(LOG_ERR, "Error attempting to wrap passphrase; "
			       "rc = [%d]", rc);
			goto out_child;
		}
out_child:
		exit(0);
	}
	if ((tmp_pid = waitpid(child_pid, NULL, 0)) == -1)
		syslog(LOG_WARNING,
		       "waitpid() returned with error condition\n");
	free(wrapped_pw_filename);
out:
	return rc;
}
