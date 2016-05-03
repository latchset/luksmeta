/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */
/*
 * Copyright (c) 2016 Red Hat, Inc.
 * Author: Nathaniel McCallum <npmccallum@redhat.com>
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

#include <assert.h>
#include <error.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "test.h"

char filename[] = "/tmp/luksmetaXXXXXX";

static size_t
first_nonzero(FILE *file, size_t start, size_t length)
{
    uint8_t *buffer;

    buffer = malloc(length);
    if (!buffer)
        return false;

    if (fseek(file, start, SEEK_SET) != 0) {
        free(buffer);
        return false;
    }

    if (fread(buffer, length, 1, file) != 1) {
        free(buffer);
        return false;
    }

    for (size_t i = 0; i < length; i++) {
        if (buffer[i] != 0) {
            free(buffer);
            return i;
        }
    }

    free(buffer);
    return length;
}

bool
test_layout(range_t *ranges)
{
    bool valid = false;
    FILE *file = NULL;

    file = fopen(filename, "r");
    if (!file)
        return false;

    for (size_t i = 0; ranges[i].length != 0; i++) {
        size_t nonzero;

        fprintf(stderr, "%08zu:%08zu (%c= 0)\n",
                ranges[i].start, ranges[i].start + ranges[i].length,
                ranges[i].zero ? '=' : '!');

        nonzero = first_nonzero(file, ranges[i].start, ranges[i].length);
        if (ranges[i].zero && nonzero < ranges[i].length) {
            fprintf(stderr, "unexpected nonzero: %zu\n", nonzero);
            goto egress;
        } else if (!ranges[i].zero && nonzero == ranges[i].length) {
            fprintf(stderr, "unexpected zero: %zu-%zu\n",
                    ranges[i].start, ranges[i].start + ranges[i].length);
            goto egress;
        }
    }

    valid = true;

egress:
    fclose(file);
    return valid;

}

void
test_hole(struct crypt_device *cd, uint32_t *offset, uint32_t *length)
{
    uint64_t payload_offset = 0;
    uint64_t keyarea_end = 0;
    int r = 0;

    payload_offset = crypt_get_data_offset(cd) * 512;
    if (payload_offset < ALIGN(1, true))
        error(EXIT_FAILURE, -r, "%s:%d", __FILE__, __LINE__);

    for (int slot = 0; slot < crypt_keyslot_max(CRYPT_LUKS1); slot++) {
        uint64_t off = 0;
        uint64_t len = 0;

        r = crypt_keyslot_area(cd, slot, &off, &len);
        if (r < 0)
            error(EXIT_FAILURE, -r, "%s:%d", __FILE__, __LINE__);

        if (off + len > keyarea_end)
            keyarea_end = off + len;
    }

    *offset = ALIGN(keyarea_end, true);
    *length = ALIGN(payload_offset, false) - *offset;
}

struct crypt_device *
test_format(void)
{
    struct crypt_device *cd = NULL;
    int fd;
    int r;

    fd = mkstemp(filename);
    if (fd < 0)
        error(EXIT_FAILURE, errno, "%s:%d", __FILE__, __LINE__);

    /* Create a 4MB sparse file. */
    if (lseek(fd, 4194303, SEEK_SET) == -1)
        error(EXIT_FAILURE, errno, "%s:%d", __FILE__, __LINE__);
    if (write(fd, "", 1) != 1)
        error(EXIT_FAILURE, errno, "%s:%d", __FILE__, __LINE__);
    close(fd);

    r = crypt_init(&cd, filename);
    if (r < 0)
        error(EXIT_FAILURE, -r, "%s:%d", __FILE__, __LINE__);

    r = crypt_format(cd, CRYPT_LUKS1, "aes", "xts-plain64",
                     NULL, NULL, 32, NULL);
    if (r < 0)
        error(EXIT_FAILURE, -r, "%s:%d", __FILE__, __LINE__);

    return cd;
}

struct crypt_device *
test_init(void)
{
    struct crypt_device *cd = NULL;
    int r;

    r = crypt_init(&cd, filename);
    if (r < 0)
        error(EXIT_FAILURE, -r, "%s:%d", __FILE__, __LINE__);

    r = crypt_load(cd, CRYPT_LUKS1, NULL);
    if (r < 0)
        error(EXIT_FAILURE, -r, "%s:%d", __FILE__, __LINE__);

    r = luksmeta_init(cd);
    if (r < 0)
        error(EXIT_FAILURE, -r, "%s:%d", __FILE__, __LINE__);

    return cd;
}

