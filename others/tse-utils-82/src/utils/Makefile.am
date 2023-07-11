MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

EXTRA_DIST=tserc tse-rewrite-file tse-setup-private tse-setup-swap tse-mount-private tse-umount-private

rootsbin_PROGRAMS=mount.tse \
		  umount.tse \
		  mount.tse_private
bin_PROGRAMS=tse-manager tse-wrap-passphrase \
	     tse-unwrap-passphrase \
	     tse-insert-wrapped-passphrase-into-keyring \
	     tse-rewrap-passphrase \
	     tse-add-passphrase \
	     tse-stat
bin_SCRIPTS = tse-setup-private \
	      tse-setup-swap \
	      tse-mount-private \
	      tse-umount-private \
	      tse-rewrite-file
bin2dir = $(bindir)

noinst_PROGRAMS=test

if ENABLE_TESTS
TESTS=test
endif

if BUILD_TSPI
bin_PROGRAMS+=tse-generate-tpm-key
endif

INCLUDES = -I$(top_srcdir)/src/include

mount_tse_SOURCES = mount.tse.c io.c io.h gen_key.c plaintext_decision_graph.c
mount_tse_CFLAGS = $(AM_CFLAGS) $(KEYUTILS_CFLAGS) $(LIBGCRYPT_CFLAGS)
mount_tse_LDADD = $(top_builddir)/src/libtse/libtse.la $(KEYUTILS_LIBS) $(LIBGCRYPT_LIBS)
umount_tse_SOURCES = umount.tse.c
umount_tse_CFLAGS = $(AM_CFLAGS) $(KEYUTILS_CFLAGS)
umount_tse_LDADD = $(top_builddir)/src/libtse/libtse.la
tse_manager_SOURCES = manager.c io.c io.h gen_key.c
tse_manager_CFLAGS = $(AM_CFLAGS) $(KEYUTILS_CFLAGS) $(LIBGCRYPT_CFLAGS)
tse_manager_LDADD = $(top_builddir)/src/libtse/libtse.la $(KEYUTILS_LIBS) $(LIBGCRYPT_LIBS)
tse_wrap_passphrase_SOURCES = tse_wrap_passphrase.c
tse_wrap_passphrase_LDADD = $(top_builddir)/src/libtse/libtse.la
tse_unwrap_passphrase_SOURCES = tse_unwrap_passphrase.c
tse_unwrap_passphrase_LDADD = $(top_builddir)/src/libtse/libtse.la
tse_insert_wrapped_passphrase_into_keyring_SOURCES = tse_insert_wrapped_passphrase_into_keyring.c
tse_insert_wrapped_passphrase_into_keyring_LDADD = $(top_builddir)/src/libtse/libtse.la
tse_rewrap_passphrase_SOURCES = tse_rewrap_passphrase.c
tse_rewrap_passphrase_LDADD = $(top_builddir)/src/libtse/libtse.la
tse_add_passphrase_SOURCES = tse_add_passphrase.c
tse_add_passphrase_LDADD = $(top_builddir)/src/libtse/libtse.la

tse_generate_tpm_key_SOURCES = tse_generate_tpm_key.c
tse_generate_tpm_key_CFLAGS = $(AM_CFLAGS) $(TSPI_CFLAGS)
tse_generate_tpm_key_LDADD = $(TSPI_LIBS)

mount_tse_private_SOURCES = mount.tse_private.c
mount_tse_private_LDADD = $(top_builddir)/src/libtse/libtse.la $(KEYUTILS_LIBS)

tse_stat_SOURCES = tse-stat.c
tse_stat_LDADD = $(top_builddir)/src/libtse/libtse.la

test_SOURCES = test.c io.c
test_LDADD = $(top_builddir)/src/libtse/libtse.la

install-exec-hook:	install-rootsbinPROGRAMS
	-rm -f "$(DESTDIR)/$(rootsbindir)/umount.tse_private"
	$(LN_S) "mount.tse_private" "$(DESTDIR)/$(rootsbindir)/umount.tse_private"
