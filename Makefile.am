AM_CFLAGS = @LUKSMETA_CFLAGS@ @cryptsetup_CFLAGS@

noinst_LTLIBRARIES = libcrc32c.la
libcrc32c_la_SOURCES = crc32c.c crc32c.h

include_HEADERS = luksmeta.h
lib_LTLIBRARIES = libluksmeta.la
libluksmeta_la_LDFLAGS = -export-symbols-regex '^luksmeta_'
libluksmeta_la_LIBADD = libcrc32c.la @cryptsetup_LIBS@

bin_PROGRAMS = luksmeta
luksmeta_LDADD = libluksmeta.la @cryptsetup_LIBS@

man8_MANS = luksmeta.8

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = luksmeta.pc

check_LTLIBRARIES = libtest.la
libtest_la_SOURCES = test.c test.h

check_PROGRAMS = test-crc32c test-lm-assumptions test-lm-init test-lm-one test-lm-two test-lm-big
test_crc32c_LDADD = libcrc32c.la
test_lm_assumptions_LDADD = libtest.la libluksmeta.la @cryptsetup_LIBS@
test_lm_init_LDADD = libtest.la libluksmeta.la @cryptsetup_LIBS@
test_lm_one_LDADD = libtest.la libluksmeta.la @cryptsetup_LIBS@
test_lm_two_LDADD = libtest.la libluksmeta.la @cryptsetup_LIBS@
test_lm_big_LDADD = libtest.la libluksmeta.la @cryptsetup_LIBS@

EXTRA_DIST = $(man8_MANS) test-luksmeta
TESTS = $(check_PROGRAMS) test-luksmeta

