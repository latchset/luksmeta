/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */
/*
 * Copyright (c) 2016 Red Hat, Inc.
 * Author: Nathaniel McCallum <npmccallum@redhat.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "test.h"
#include <error.h>
#include <stdlib.h>
#include <string.h>

static const uint8_t UUID0[] = {
    0x35, 0x08, 0x50, 0xc3, 0x25, 0xc9, 0x85, 0xea, 0x1b, 0x55, 0x93, 0x56,
    0x36, 0x2a, 0xd9, 0x85, 0x13, 0x6b, 0xea, 0xb0, 0x27, 0xb3, 0x3d, 0xd9,
    0x46, 0xc4, 0xd8, 0x91, 0xd4, 0x5b, 0x2c, 0x70
};

static const uint8_t UUID1[] = {
    0xb4, 0xcb, 0x8c, 0x1c, 0x34, 0xea, 0xcc, 0x21, 0x0b, 0x9c, 0xc3, 0x9c,
    0x9a, 0x09, 0xc0, 0x0f, 0x4b, 0x9b, 0x02, 0x74, 0x57, 0x1e, 0x97, 0xd2,
    0xd3, 0xed, 0x33, 0x16, 0x02, 0xca, 0xae, 0x3c
};

int
main(int argc, char *argv[])
{
    uint8_t uuid[sizeof(UUID0)] = {};
    uint8_t data[sizeof(UUID0)] = {};
    struct crypt_device *cd = NULL;
    uint32_t offset = 0;
    uint32_t length = 0;
    int r;

    crypt_free(test_format());
    cd = test_init();
    test_hole(cd, &offset, &length);

    /* Add one metadata. */
    r = luksmeta_set(cd, 0, UUID0, UUID0, sizeof(UUID0));
    if (r < 0)
        error(EXIT_FAILURE, -r, "luksmeta_set()");

    assert(test_layout((range_t[]) {
        { 0, 1024 },                   /* LUKS header */
        { 1024, offset - 1024, true }, /* Keyslot Area */
        { offset, 4096 },              /* luksmeta header */
        { offset + 4096, 4096 },       /* luksmeta slot 0 */
        END(offset + 8192),            /* Rest of the file */
    }));

    assert(luksmeta_get(cd, 0, uuid, data, sizeof(data)) == sizeof(data));
    assert(memcmp(uuid, UUID0, sizeof(UUID0)) == 0);
    assert(memcmp(data, UUID0, sizeof(UUID0)) == 0);

    /* Add a second metadata. */
    r = luksmeta_set(cd, 1, UUID1, UUID1, sizeof(UUID1));
    if (r < 0)
        error(EXIT_FAILURE, -r, "luksmeta_set()");

    assert(test_layout((range_t[]) {
        { 0, 1024 },                   /* LUKS header */
        { 1024, offset - 1024, true }, /* Keyslot Area */
        { offset, 4096 },              /* luksmeta header */
        { offset + 4096, 4096 },       /* luksmeta slot 0 */
        { offset + 8192, 4096 },       /* luksmeta slot 1 */
        END(offset + 12288),           /* Rest of the file */
    }));

    assert(luksmeta_get(cd, 0, uuid, data, sizeof(data)) == sizeof(data));
    assert(memcmp(uuid, UUID0, sizeof(UUID0)) == 0);
    assert(memcmp(data, UUID0, sizeof(UUID0)) == 0);
    assert(luksmeta_get(cd, 1, uuid, data, sizeof(data)) == sizeof(data));
    assert(memcmp(uuid, UUID1, sizeof(UUID1)) == 0);
    assert(memcmp(data, UUID1, sizeof(UUID1)) == 0);

    /* Delete the first metadata. */
    assert(luksmeta_del(cd, 0) == 0);
    assert(test_layout((range_t[]) {
        { 0, 1024 },                   /* LUKS header */
        { 1024, offset - 1024, true }, /* Keyslot Area */
        { offset, 4096 },              /* luksmeta header */
        { offset + 4096, 4096, true }, /* luksmeta slot 0 */
        { offset + 8192, 4096 },       /* luksmeta slot 1 */
        END(offset + 12288),           /* Rest of the file */
    }));

    /* Delete the second metadata. */
    assert(luksmeta_del(cd, 1) == 0);
    assert(test_layout((range_t[]) {
        { 0, 1024 },                   /* LUKS header */
        { 1024, offset - 1024, true }, /* Keyslot Area */
        { offset, 4096 },              /* luksmeta header */
        END(offset + 4096),            /* Rest of the file */
    }));

    crypt_free(cd);
    unlink(filename);
    return 0;
}
