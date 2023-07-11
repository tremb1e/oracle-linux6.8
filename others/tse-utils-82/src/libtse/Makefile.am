MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

lib_LTLIBRARIES = libtse.la

pkgconfig_DATA = libtse.pc

libtse_la_SOURCES = \
	main.c \
	cipher_list.c \
	messaging.c \
	packets.c \
	netlink.c \
	miscdev.c \
	sysfs.c \
	key_management.c \
	decision_graph.c \
	cmd_ln_parser.c \
	module_mgr.c \
	key_mod.c \
	tse-stat.c \
	$(top_srcdir)/src/key_mod/tse_key_mod_passphrase.c

libtse_la_LDFLAGS = \
	-version-info @LIBTSE_LT_CURRENT@:@LIBTSE_LT_REVISION@:@LIBTSE_LT_AGE@ \
	-no-undefined
libtse_la_CFLAGS = $(AM_CFLAGS) $(CRYPTO_CFLAGS) $(KEYUTILS_CFLAGS)
libtse_la_LIBADD = $(CRYPTO_LIBS) $(KEYUTILS_LIBS)

splint:
	splint -warnposix -preproc -unrecog -predboolint -boolops +matchanyintegral *.c
