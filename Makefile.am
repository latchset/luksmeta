AM_CFLAGS = @LUKSMETA_CFLAGS@ @cryptsetup_CFLAGS@

noinst_LTLIBRARIES = libcrc32c.la
libcrc32c_la_SOURCES = crc32c.c crc32c.h

include_HEADERS = luksmeta.h
lib_LTLIBRARIES = libluksmeta.la
libluksmeta_la_SOURCES = luksmeta.c
libluksmeta_la_LIBADD = libcrc32c.la @cryptsetup_LIBS@

check_PROGRAMS = test-crc32c
test_crc32c_LDADD = libcrc32c.la

TESTS = $(check_PROGRAMS)

