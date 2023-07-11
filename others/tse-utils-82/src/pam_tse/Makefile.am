MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

if BUILD_PAM
pam_LTLIBRARIES = pam_tse.la

# Needed until libtool-2
install-data-hook:	install-pamLTLIBRARIES
	rm -f "$(DESTDIR)$(pamdir)/pam_tse.la"
	rm -f "$(DESTDIR)$(pamdir)/pam_tse.a"
uninstall-local:
	rm -f "$(DESTDIR)$(pamdir)/pam_tse.so"
endif

pam_tse_la_SOURCES = pam_tse.c
pam_tse_la_CFLAGS = $(AM_CFLAGS)
pam_tse_la_LIBADD = $(top_builddir)/src/libtse/libtse.la $(PAM_LIBS)
pam_tse_la_LDFLAGS = $(AM_LDFLAGS) -module -avoid-version -shared
