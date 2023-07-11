MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

bin_PROGRAMS=tsed

tsed_SOURCES = main.c
tsed_CFLAGS = $(AM_CFLAGS) $(LIBGCRYPT_CFLAGS) $(KEYUTILS_CFLAGS)
tsed_LDADD = $(top_builddir)/src/libtse/libtse.la $(KEYUTILS_LIBS) $(LIBGCRYPT_LIBS)
