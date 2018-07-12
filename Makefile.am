AM_CFLAGS = @LUKSMETA_CFLAGS@ @cryptsetup_CFLAGS@
BUILT_SOURCES=
CLEANFILES=
noinst_LTLIBRARIES = libcrc32c.la
libcrc32c_la_SOURCES = crc32c.c crc32c.h

include_HEADERS = luksmeta.h
lib_LTLIBRARIES = libluksmeta.la
libluksmeta_la_LDFLAGS = -export-symbols-regex '^luksmeta_'
libluksmeta_la_LIBADD = libcrc32c.la @cryptsetup_LIBS@

bin_PROGRAMS = luksmeta
luksmeta_LDADD = libluksmeta.la @cryptsetup_LIBS@
man_ADOC_FILES = luksmeta.8.adoc

if HAVE_A2X
man_ROFF_FILES = $(man_ADOC_FILES:.adoc=.roff)
BUILT_SOURCES += $(man_ROFF_FILES)
CLEANFILES += $(man_ROFF_FILES) $(man_ROFF_FILES:.roff=)

$(top_builddir)/%.roff: %.adoc
	$(MKDIR_P) $$(dirname $@)
	$(A2X) -v -f manpage $^ -D $(top_builddir)/$$(dirname $@)
	$(INSTALL) -m 644 $(top_builddir)/$(@:.roff=) $(top_builddir)/$@

man8_MANS = luksmeta.8
else
man8_MANS =
endif

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

EXTRA_DIST = $(man_ADOC_FILES) test-luksmeta
TESTS = $(check_PROGRAMS) test-luksmeta
