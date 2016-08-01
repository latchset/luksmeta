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

#include "test.h"
#include <error.h>
#include <stdlib.h>
#include <string.h>

static const luksmeta_uuid_t UUID0 = {
    0x35, 0x08, 0x50, 0xc3, 0x25, 0xc9, 0x85, 0xea,
    0x1b, 0x55, 0x93, 0x56, 0x36, 0x2a, 0xd9, 0x85
};

static const luksmeta_uuid_t UUID1 = {
    0xb4, 0xcb, 0x8c, 0x1c, 0x34, 0xea, 0xcc, 0x21,
    0x0b, 0x9c, 0xc3, 0x9c, 0x9a, 0x09, 0xc0, 0x0f
};

int
main(int argc, char *argv[])
{
    uint8_t data[sizeof(UUID0)] = {};
    struct crypt_device *cd = NULL;
    luksmeta_uuid_t uuid = {};
    uint32_t offset = 0;
    uint32_t length = 0;
    int r;

    crypt_free(test_format());
    cd = test_init();
    test_hole(cd, &offset, &length);

    /* Add one metadata. */
    r = luksmeta_save(cd, 0, UUID0, UUID0, sizeof(UUID0));
    if (r < 0)
        error(EXIT_FAILURE, -r, "luksmeta_save()");

    assert(test_layout((range_t[]) {
        { 0, 1024 },                   /* LUKS header */
        { 1024, offset - 1024, true }, /* Keyslot Area */
        { offset, 4096 },              /* luksmeta header */
        { offset + 4096, 4096 },       /* luksmeta slot 0 */
        END(offset + 8192),            /* Rest of the file */
    }));

    assert(luksmeta_load(cd, 0, uuid, data, sizeof(data)) == sizeof(data));
    assert(memcmp(uuid, UUID0, sizeof(UUID0)) == 0);
    assert(memcmp(data, UUID0, sizeof(UUID0)) == 0);

    /* Add a second metadata. */
    r = luksmeta_save(cd, 1, UUID1, UUID1, sizeof(UUID1));
    if (r < 0)
        error(EXIT_FAILURE, -r, "luksmeta_save()");

    assert(test_layout((range_t[]) {
        { 0, 1024 },                   /* LUKS header */
        { 1024, offset - 1024, true }, /* Keyslot Area */
        { offset, 4096 },              /* luksmeta header */
        { offset + 4096, 4096 },       /* luksmeta slot 0 */
        { offset + 8192, 4096 },       /* luksmeta slot 1 */
        END(offset + 12288),           /* Rest of the file */
    }));

    assert(luksmeta_load(cd, 0, uuid, data, sizeof(data)) == sizeof(data));
    assert(memcmp(uuid, UUID0, sizeof(UUID0)) == 0);
    assert(memcmp(data, UUID0, sizeof(UUID0)) == 0);
    assert(luksmeta_load(cd, 1, uuid, data, sizeof(data)) == sizeof(data));
    assert(memcmp(uuid, UUID1, sizeof(UUID1)) == 0);
    assert(memcmp(data, UUID1, sizeof(UUID1)) == 0);

    /* Delete the first metadata. */
    assert(luksmeta_wipe(cd, 0, UUID0) == 0);
    assert(test_layout((range_t[]) {
        { 0, 1024 },                   /* LUKS header */
        { 1024, offset - 1024, true }, /* Keyslot Area */
        { offset, 4096 },              /* luksmeta header */
        { offset + 4096, 4096, true }, /* luksmeta slot 0 */
        { offset + 8192, 4096 },       /* luksmeta slot 1 */
        END(offset + 12288),           /* Rest of the file */
    }));

    /* Delete the second metadata. */
    assert(luksmeta_wipe(cd, 1, UUID1) == 0);
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
