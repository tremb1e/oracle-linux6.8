MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

SUBDIRS = manpage

dist_doc_DATA =
dist_noinst_DATA =
dist_html_DATA = tse-faq.html

if BUILD_PAM
dist_doc_DATA += tse-pam-doc.txt
else
dist_noinst_DATA += tse-pam-doc.txt
endif

if BUILD_PKCS11_HELPER
dist_doc_DATA += tse-pkcs11-helper-doc.txt
else
dist_noinst_DATA += tse-pkcs11-helper-doc.txt
endif

dist_pkgdata_DATA = tse-mount-private.txt
