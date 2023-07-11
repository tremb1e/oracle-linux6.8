MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

tsekeymod_LTLIBRARIES=libtse_key_mod_passphrase.la

if BUILD_OPENSSL
tsekeymod_LTLIBRARIES+=libtse_key_mod_openssl.la
endif
if BUILD_PKCS11_HELPER
tsekeymod_LTLIBRARIES+=libtse_key_mod_pkcs11_helper.la
endif
if BUILD_TSPI
tsekeymod_LTLIBRARIES+=libtse_key_mod_tspi.la
endif
if BUILD_GPG
tsekeymod_LTLIBRARIES+=libtse_key_mod_gpg.la
endif

libtse_key_mod_openssl_la_SOURCES = tse_key_mod_openssl.c
libtse_key_mod_openssl_la_CFLAGS = $(AM_CFLAGS) $(OPENSSL_CFLAGS)
libtse_key_mod_openssl_la_LIBADD = $(OPENSSL_LIBS)
libtse_key_mod_openssl_la_LDFLAGS = $(AM_LDFLAGS) -module -avoid-version -shared

libtse_key_mod_pkcs11_helper_la_SOURCES = tse_key_mod_pkcs11_helper.c
libtse_key_mod_pkcs11_helper_la_CFLAGS = $(AM_CFLAGS) $(PKCS11_HELPER_CFLAGS) $(OPENSSL_CFLAGS)
libtse_key_mod_pkcs11_helper_la_LIBADD = $(PKCS11_HELPER_LIBS) $(OPENSSL_LIBS)
libtse_key_mod_pkcs11_helper_la_LDFLAGS = $(AM_LDFLAGS) -module -avoid-version -shared

libtse_key_mod_tspi_la_SOURCES = tse_key_mod_tspi.c
libtse_key_mod_tspi_la_CFLAGS = $(AM_CFLAGS) $(TSPI_CFLAGS)
libtse_key_mod_tspi_la_LIBADD = $(TSPI_LIBS)
libtse_key_mod_tspi_la_LDFLAGS = $(AM_LDFLAGS) -module -avoid-version -shared

libtse_key_mod_gpg_la_SOURCES = tse_key_mod_gpg.c
libtse_key_mod_gpg_la_CFLAGS = $(AM_CFLAGS) $(GPGME_CFLAGS)
libtse_key_mod_gpg_la_LIBADD = $(GPGME_LIBS)
libtse_key_mod_gpg_la_LDFLAGS = $(AM_LDFLAGS) -module -avoid-version -shared

libtse_key_mod_passphrase_la_SOURCES = tse_key_mod_passphrase.c
libtse_key_mod_passphrase_la_CFLAGS = $(AM_CFLAGS) $(LIBGCRYPT_CFLAGS)
libtse_key_mod_passphrase_la_LIBADD = $(LIBGCRYPT_LIBS)
libtse_key_mod_passphrase_la_LDFLAGS = $(AM_LDFLAGS) -module -avoid-version -shared

# Needed until libtool-2
install-data-hook:	install-tsekeymodLTLIBRARIES
	for f in `echo "$(tsekeymod_LTLIBRARIES)" | $(SED) 's/\.la//g'`; do \
		rm -f "$(DESTDIR)$(tsekeymoddir)/$$f.la"; \
		rm -f "$(DESTDIR)$(tsekeymoddir)/$$f.a"; \
	done
uninstall-local:
	for f in `echo "$(tsekeymod_LTLIBRARIES)" | $(SED) 's/\.la//g'`; do \
		rm -f "$(DESTDIR)$(tsekeymoddir)/$$f.so"; \
	done
