if BUILD_PYWRAP

BUILT_SOURCES = $(srcdir)/libtse_wrap.c
SWIG_SOURCES = libtse.i

pkgpython_PYTHON = libtse.py
pkgpyexec_LTLIBRARIES = _libtse.la
_libtse_la_SOURCES = $(srcdir)/libtse_wrap.c $(SWIG_SOURCES)
_libtse_la_CFLAGS = $(SWIG_PYTHON_CPPFLAGS) -I$(top_srcdir)/src/include
_libtse_la_LDFLAGS = -module
_libtse_la_LIBADD = ../libtse/.libs/libtse.la

$(srcdir)/libtse_wrap.c : $(SWIG_SOURCES)
	$(SWIG) $(SWIG_PYTHON_OPT) -I$(top_srcdir)/src/include -o $@ $<

endif
