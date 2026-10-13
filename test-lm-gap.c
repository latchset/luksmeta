/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */
/*
 * Copyright (c) 2026 Red Hat, Inc.
 * Author: Sergio Correia <scorreia@redhat.com>
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "test.h"
#include "crc32c.h"
#include <error.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static const luksmeta_uuid_t UUID0 = {
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11
};

static const luksmeta_uuid_t UUID1 = {
    0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
    0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22
};

static const luksmeta_uuid_t UUID2 = {
    0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
    0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33
};

/* On-disk header layout; integer fields are stored in big-endian order. */
typedef struct __attribute__((packed)) {
    luksmeta_uuid_t uuid;
    uint32_t offset;
    uint32_t length;
    uint32_t crc32c;
    uint32_t reserved;
} test_slot_t;

typedef struct __attribute__((packed)) {
    uint8_t magic[8];
    uint32_t version;
    uint32_t crc32c;
    test_slot_t slots[8];
} test_header_t;

/* Reset the filename template so mkstemp() in test_format() works on
 * each call.  The existing tests only call test_format() once, but we
 * call it for every scenario. */
static void
reset_filename(void)
{
    strcpy(filename, "/tmp/luksmetaXXXXXX");
}

/* Read a region of the image file into a freshly allocated buffer. */
static uint8_t *
read_image(size_t off, size_t len)
{
    uint8_t *buf = NULL;
    int fd;

    buf = malloc(len);
    if (!buf)
        error(EXIT_FAILURE, errno, "%s:%d", __FILE__, __LINE__);

    fd = open(filename, O_RDONLY);
    if (fd < 0)
        error(EXIT_FAILURE, errno, "%s:%d", __FILE__, __LINE__);

    if (lseek(fd, off, SEEK_SET) == -1) {
        free(buf);
        close(fd);
        error(EXIT_FAILURE, errno, "%s:%d", __FILE__, __LINE__);
    }

    if (read(fd, buf, len) != (ssize_t) len) {
        free(buf);
        close(fd);
        error(EXIT_FAILURE, errno, "%s:%d", __FILE__, __LINE__);
    }

    close(fd);
    return buf;
}

/*
 * Bug 1 regression: occupied slot 0 shifts the hard limit, allowing a
 * save to write past the gap into the encrypted payload area.
 */
static void
test_bug1(void)
{
    struct crypt_device *cd = NULL;
    luksmeta_uuid_t uuid = {};
    uint32_t offset = 0;
    uint32_t length = 0;
    uint8_t *before = NULL;
    uint8_t *after = NULL;
    uint8_t small[16];
    uint8_t *big = NULL;
    size_t capacity;
    int r;

    reset_filename();
    crypt_free(test_format());
    cd = test_init();
    test_hole(cd, &offset, &length);

    assert(length % 4096 == 0);
    assert(length >= 12288);

    /* Usable data area: gap minus the header page. */
    capacity = length - ALIGN(1, true);

    /* Fill small data with a known pattern. */
    memset(small, 'S', sizeof(small));

    /* Save a small entry in slot 0. */
    r = luksmeta_save(cd, 0, UUID0, small, sizeof(small));
    assert(r == 0);

    /* Seed the payload boundary so we can detect overwrites. */
    {
        int fd = open(filename, O_RDWR);
        uint8_t sentinel[4096];
        assert(fd >= 0);
        memset(sentinel, 'P', sizeof(sentinel));
        assert(lseek(fd, offset + length, SEEK_SET) != -1);
        assert(write(fd, sentinel, sizeof(sentinel)) == sizeof(sentinel));
        close(fd);
    }

    /* Snapshot the image before the rejected save. */
    before = read_image(offset, length + 4096);

    /* Attempt to save capacity bytes — must fail, slot 0 already occupies
     * space in the gap. */
    big = calloc(1, capacity);
    assert(big != NULL);
    memset(big, 'B', capacity);

    r = luksmeta_save(cd, 1, UUID1, big, capacity);
    assert(r == -ENOSPC);
    free(big);

    /* Image must be unchanged. */
    after = read_image(offset, length + 4096);
    assert(memcmp(before, after, length + 4096) == 0);
    free(before);
    free(after);

    /* Original entry still loads correctly. */
    {
        uint8_t out[sizeof(small)] = {};
        r = luksmeta_load(cd, 0, uuid, out, sizeof(out));
        assert(r == (int) sizeof(small));
        assert(memcmp(uuid, UUID0, sizeof(UUID0)) == 0);
        assert(memcmp(out, small, sizeof(small)) == 0);
    }

    /* Destination slot is still empty. */
    r = luksmeta_load(cd, 1, uuid, NULL, 0);
    assert(r == -ENODATA);

    crypt_free(cd);
    unlink(filename);
}

/*
 * Control: same sizes as Bug 1 but with the small entry in slot 1
 * instead of slot 0. Verifies the rejection is not slot-0-specific.
 */
static void
test_control(void)
{
    struct crypt_device *cd = NULL;
    luksmeta_uuid_t uuid = {};
    uint32_t offset = 0;
    uint32_t length = 0;
    uint8_t *before = NULL;
    uint8_t *after = NULL;
    uint8_t small[16];
    uint8_t *big = NULL;
    size_t capacity;
    int r;

    reset_filename();
    crypt_free(test_format());
    cd = test_init();
    test_hole(cd, &offset, &length);

    capacity = length - ALIGN(1, true);
    memset(small, 'S', sizeof(small));

    /* Save a small entry in slot 1 (not slot 0). */
    r = luksmeta_save(cd, 1, UUID1, small, sizeof(small));
    assert(r == 1);

    /* Seed payload boundary. */
    {
        int fd = open(filename, O_RDWR);
        uint8_t sentinel[4096];
        assert(fd >= 0);
        memset(sentinel, 'P', sizeof(sentinel));
        assert(lseek(fd, offset + length, SEEK_SET) != -1);
        assert(write(fd, sentinel, sizeof(sentinel)) == sizeof(sentinel));
        close(fd);
    }

    before = read_image(offset, length + 4096);

    big = calloc(1, capacity);
    assert(big != NULL);
    memset(big, 'B', capacity);

    r = luksmeta_save(cd, 2, UUID2, big, capacity);
    assert(r == -ENOSPC);
    free(big);

    after = read_image(offset, length + 4096);
    assert(memcmp(before, after, length + 4096) == 0);
    free(before);
    free(after);

    /* Original entry still loads. */
    {
        uint8_t out[sizeof(small)] = {};
        r = luksmeta_load(cd, 1, uuid, out, sizeof(out));
        assert(r == (int) sizeof(small));
        assert(memcmp(uuid, UUID1, sizeof(UUID1)) == 0);
        assert(memcmp(out, small, sizeof(small)) == 0);
    }

    r = luksmeta_load(cd, 2, uuid, NULL, 0);
    assert(r == -ENODATA);

    crypt_free(cd);
    unlink(filename);
}

/*
 * Bug 2 regression: a new small entry whose candidate position falls
 * entirely inside an existing entry longer than two pages. The allocator
 * must skip the existing range and place the new entry after it.
 */
static void
test_bug2(void)
{
    struct crypt_device *cd = NULL;
    luksmeta_uuid_t uuid = {};
    uint32_t offset = 0;
    uint32_t length = 0;
    uint8_t big[9000];
    uint8_t small[100];
    int r;

    reset_filename();
    crypt_free(test_format());
    cd = test_init();
    test_hole(cd, &offset, &length);

    /* Need room for the header page + 9000 bytes (3 aligned pages) +
     * the second entry (1 aligned page) = 5 pages minimum. */
    assert(length >= 24576);

    memset(big, 'A', sizeof(big));
    memset(small, 'X', sizeof(small));

    /* Slot 1: 9000 bytes, occupies gap-relative [4096, 13096). */
    r = luksmeta_save(cd, 1, UUID1, big, sizeof(big));
    assert(r == 1);

    /* Slot 2: 100 bytes. Must skip the existing range and succeed. */
    r = luksmeta_save(cd, 2, UUID2, small, sizeof(small));
    assert(r == 2);

    /* Both entries load with their original data. */
    {
        uint8_t out_big[sizeof(big)] = {};
        r = luksmeta_load(cd, 1, uuid, out_big, sizeof(out_big));
        assert(r == (int) sizeof(big));
        assert(memcmp(uuid, UUID1, sizeof(UUID1)) == 0);
        assert(memcmp(out_big, big, sizeof(big)) == 0);
    }

    {
        uint8_t out_small[sizeof(small)] = {};
        r = luksmeta_load(cd, 2, uuid, out_small, sizeof(out_small));
        assert(r == (int) sizeof(small));
        assert(memcmp(uuid, UUID2, sizeof(UUID2)) == 0);
        assert(memcmp(out_small, small, sizeof(small)) == 0);
    }

    crypt_free(cd);
    unlink(filename);
}

/*
 * Zero-length metadata: a zero-length entry coexists with a normal entry.
 */
static void
test_zero_length(void)
{
    struct crypt_device *cd = NULL;
    luksmeta_uuid_t uuid = {};
    uint8_t dummy = 0;
    uint8_t normal[64];
    int r;

    reset_filename();
    crypt_free(test_format());
    cd = test_init();

    /* Save a zero-length entry. Use a non-NULL buffer to avoid UB. */
    r = luksmeta_save(cd, 0, UUID0, &dummy, 0);
    assert(r == 0);

    /* It loads back with length 0 and the correct UUID. */
    r = luksmeta_load(cd, 0, uuid, NULL, 0);
    assert(r == 0);
    assert(memcmp(uuid, UUID0, sizeof(UUID0)) == 0);

    /* Save a normal entry in the next slot. */
    memset(normal, 'N', sizeof(normal));
    r = luksmeta_save(cd, 1, UUID1, normal, sizeof(normal));
    assert(r == 1);

    /* Both coexist: zero-length still loads. */
    memset(uuid, 0, sizeof(uuid));
    r = luksmeta_load(cd, 0, uuid, NULL, 0);
    assert(r == 0);
    assert(memcmp(uuid, UUID0, sizeof(UUID0)) == 0);

    /* Normal entry loads with full contents. */
    {
        uint8_t out[sizeof(normal)] = {};
        r = luksmeta_load(cd, 1, uuid, out, sizeof(out));
        assert(r == (int) sizeof(normal));
        assert(memcmp(uuid, UUID1, sizeof(UUID1)) == 0);
        assert(memcmp(out, normal, sizeof(normal)) == 0);
    }

    crypt_free(cd);
    unlink(filename);
}

/*
 * Exact-fit boundary: fill the entire usable data area.
 */
static void
test_exact_fit(void)
{
    struct crypt_device *cd = NULL;
    luksmeta_uuid_t uuid = {};
    uint32_t offset = 0;
    uint32_t length = 0;
    size_t capacity;
    uint8_t *data = NULL;
    int r;

    reset_filename();
    crypt_free(test_format());
    cd = test_init();
    test_hole(cd, &offset, &length);

    assert(length % 4096 == 0);
    capacity = length - ALIGN(1, true);

    data = malloc(capacity);
    assert(data != NULL);
    memset(data, 'F', capacity);

    /* Save exactly capacity bytes — should succeed. */
    r = luksmeta_save(cd, 0, UUID0, data, capacity);
    assert(r == 0);

    /* Verify full readback. */
    {
        uint8_t *out = malloc(capacity);
        assert(out != NULL);
        r = luksmeta_load(cd, 0, uuid, out, capacity);
        assert(r == (int) capacity);
        assert(memcmp(uuid, UUID0, sizeof(UUID0)) == 0);
        assert(memcmp(out, data, capacity) == 0);
        free(out);
    }

    free(data);
    crypt_free(cd);
    unlink(filename);
}

/*
 * One byte over capacity: must be rejected without changing the image.
 */
static void
test_over_capacity(void)
{
    struct crypt_device *cd = NULL;
    luksmeta_uuid_t uuid = {};
    uint32_t offset = 0;
    uint32_t length = 0;
    size_t capacity;
    uint8_t *data = NULL;
    uint8_t *before = NULL;
    uint8_t *after = NULL;
    int r;

    reset_filename();
    crypt_free(test_format());
    cd = test_init();
    test_hole(cd, &offset, &length);

    assert(length % 4096 == 0);
    capacity = length - ALIGN(1, true);

    data = calloc(1, capacity + 1);
    assert(data != NULL);
    memset(data, 'O', capacity + 1);

    before = read_image(offset, length);

    r = luksmeta_save(cd, 0, UUID0, data, capacity + 1);
    assert(r == -ENOSPC);
    free(data);

    after = read_image(offset, length);
    assert(memcmp(before, after, length) == 0);
    free(before);
    free(after);

    /* Slot remains empty. */
    r = luksmeta_load(cd, 0, uuid, NULL, 0);
    assert(r == -ENODATA);

    crypt_free(cd);
    unlink(filename);
}

/*
 * Adjacent allocation: second entry starts at the first's endpoint.
 */
static void
test_adjacent(void)
{
    struct crypt_device *cd = NULL;
    luksmeta_uuid_t uuid = {};
    uint32_t offset = 0;
    uint32_t length = 0;
    uint8_t data0[4096];
    uint8_t data1[64];
    int r;

    reset_filename();
    crypt_free(test_format());
    cd = test_init();
    test_hole(cd, &offset, &length);

    memset(data0, 'A', sizeof(data0));
    memset(data1, 'B', sizeof(data1));

    /* First entry: exactly one aligned page. */
    r = luksmeta_save(cd, 0, UUID0, data0, sizeof(data0));
    assert(r == 0);

    /* Second entry: should start immediately after. */
    r = luksmeta_save(cd, 1, UUID1, data1, sizeof(data1));
    assert(r == 1);

    /* Both load correctly. */
    {
        uint8_t out[sizeof(data0)] = {};
        r = luksmeta_load(cd, 0, uuid, out, sizeof(out));
        assert(r == (int) sizeof(data0));
        assert(memcmp(uuid, UUID0, sizeof(UUID0)) == 0);
        assert(memcmp(out, data0, sizeof(data0)) == 0);
    }

    {
        uint8_t out[sizeof(data1)] = {};
        r = luksmeta_load(cd, 1, uuid, out, sizeof(out));
        assert(r == (int) sizeof(data1));
        assert(memcmp(uuid, UUID1, sizeof(UUID1)) == 0);
        assert(memcmp(out, data1, sizeof(data1)) == 0);
    }

    crypt_free(cd);
    unlink(filename);
}

/*
 * Space reuse: wipe an earlier entry, save a replacement into the freed
 * hole, and verify both the replacement and the untouched later entry.
 */
static void
test_reuse(void)
{
    struct crypt_device *cd = NULL;
    luksmeta_uuid_t uuid = {};
    uint8_t data0[64];
    uint8_t data1[64];
    uint8_t data_new[64];
    int r;

    reset_filename();
    crypt_free(test_format());
    cd = test_init();

    memset(data0, 'A', sizeof(data0));
    memset(data1, 'B', sizeof(data1));
    memset(data_new, 'C', sizeof(data_new));

    /* Two entries. */
    r = luksmeta_save(cd, 0, UUID0, data0, sizeof(data0));
    assert(r == 0);
    r = luksmeta_save(cd, 1, UUID1, data1, sizeof(data1));
    assert(r == 1);

    /* Wipe the first. */
    assert(luksmeta_wipe(cd, 0, UUID0) == 0);

    /* Save a replacement into the freed slot. */
    r = luksmeta_save(cd, 0, UUID2, data_new, sizeof(data_new));
    assert(r == 0);

    /* Replacement loads correctly. */
    {
        uint8_t out[sizeof(data_new)] = {};
        r = luksmeta_load(cd, 0, uuid, out, sizeof(out));
        assert(r == (int) sizeof(data_new));
        assert(memcmp(uuid, UUID2, sizeof(UUID2)) == 0);
        assert(memcmp(out, data_new, sizeof(data_new)) == 0);
    }

    /* Later entry is untouched. */
    {
        uint8_t out[sizeof(data1)] = {};
        r = luksmeta_load(cd, 1, uuid, out, sizeof(out));
        assert(r == (int) sizeof(data1));
        assert(memcmp(uuid, UUID1, sizeof(UUID1)) == 0);
        assert(memcmp(out, data1, sizeof(data1)) == 0);
    }

    crypt_free(cd);
    unlink(filename);
}

/* Rewrite a header with a valid checksum after changing a slot range. */
static void
rewrite_header(uint32_t offset, test_header_t header)
{
    int fd = open(filename, O_RDWR);

    assert(fd >= 0);
    header.crc32c = 0;
    header.crc32c = htobe32(crc32c(0, &header, sizeof(header)));
    assert(lseek(fd, offset, SEEK_SET) != -1);
    assert(write(fd, &header, sizeof(header)) == sizeof(header));
    assert(close(fd) == 0);
}

/* A checksum-valid occupied slot must not direct I/O outside the gap. */
static void
test_invalid_range(int scenario)
{
    struct crypt_device *cd = NULL;
    luksmeta_uuid_t uuid = {};
    test_header_t header;
    struct stat before_stat, after_stat;
    uint32_t offset = 0;
    uint32_t length = 0;
    uint32_t slot_offset;
    uint8_t data[16];
    uint8_t sentinel[4096];
    uint8_t *before, *after;
    int fd;

    reset_filename();
    crypt_free(test_format());
    cd = test_init();
    test_hole(cd, &offset, &length);
    assert(length >= 12288);
    assert(sizeof(data) <= length - ALIGN(sizeof(header), true));

    memset(data, 'D', sizeof(data));
    assert(luksmeta_save(cd, 0, UUID0, data, sizeof(data)) == 0);

    fd = open(filename, O_RDWR);
    assert(fd >= 0);
    assert(lseek(fd, offset, SEEK_SET) != -1);
    assert(read(fd, &header, sizeof(header)) == sizeof(header));
    memset(sentinel, 'P', sizeof(sentinel));
    assert(lseek(fd, (off_t) offset + length, SEEK_SET) != -1);
    assert(write(fd, sentinel, sizeof(sentinel)) == sizeof(sentinel));
    assert(close(fd) == 0);

    /* Prove the mutation/checksum helper produces an accepted header. */
    header.slots[0].offset = htobe32(length - sizeof(data));
    rewrite_header(offset, header);
    assert(luksmeta_test(cd) == 0);
    assert(luksmeta_load(cd, 0, uuid, NULL, 0) == sizeof(data));

    /* Inside-but-crossing, at the boundary, and a wrapping endpoint. */
    slot_offset = scenario == 0 ? length - 1 :
                  scenario == 1 ? length : UINT32_MAX - 7;
    assert(slot_offset > sizeof(header));
    assert((uint64_t) slot_offset + sizeof(data) > length);
    if (scenario == 2)
        assert((uint64_t) slot_offset + sizeof(data) > UINT32_MAX);
    header.slots[0].offset = htobe32(slot_offset);
    rewrite_header(offset, header);

    assert(stat(filename, &before_stat) == 0);
    before = read_image(0, before_stat.st_size);

    /* Validation must reject the header even without seeking to slot data. */
    assert(luksmeta_test(cd) == -EINVAL);
    assert(luksmeta_load(cd, 0, uuid, NULL, 0) == -EINVAL);
    assert(luksmeta_load(cd, 0, uuid, data, sizeof(data)) == -EINVAL);
    assert(luksmeta_save(cd, 1, UUID1, data, sizeof(data)) == -EINVAL);
    assert(luksmeta_wipe(cd, 0, UUID0) == -EINVAL);

    assert(stat(filename, &after_stat) == 0);
    assert(after_stat.st_size == before_stat.st_size);
    after = read_image(0, after_stat.st_size);
    assert(memcmp(before, after, before_stat.st_size) == 0);
    free(before);
    free(after);
    crypt_free(cd);
    unlink(filename);
}

int
main(int argc, char *argv[])
{
    test_invalid_range(0);
    test_invalid_range(1);
    test_invalid_range(2);
    test_bug1();
    test_control();
    test_bug2();
    test_zero_length();
    test_exact_fit();
    test_over_capacity();
    test_adjacent();
    test_reuse();
    return 0;
}
