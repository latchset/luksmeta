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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <error.h>
#include <stdio.h>
#include <stdlib.h>

static const luksmeta_uuid_t UUID = {
    0xfb, 0x06, 0x8c, 0x1f, 0x68, 0x04, 0x87, 0x9f,
    0xf4, 0xcd, 0x32, 0x25, 0xb2, 0x1a, 0x7e, 0xf8
};

int
main(int argc, char *argv[])
{
    uint8_t data[sizeof(UUID)] = {};
    struct crypt_device *cd = NULL;
    luksmeta_uuid_t uuid = {};
    uint32_t offset = 0;
    uint32_t length = 0;
    int fd;

    /* Test for -ENOENT when there is no luksmeta header. */
    cd = test_format();
    for (int slot = 0; slot < crypt_keyslot_max(CRYPT_LUKS1); slot++) {
        assert(luksmeta_save(cd, slot, UUID, UUID, sizeof(UUID)) == -ENOENT);
        assert(luksmeta_load(cd, slot, uuid, data, sizeof(data)) == -ENOENT);
        assert(luksmeta_wipe(cd, slot, UUID) == -ENOENT);
        assert(luksmeta_test(cd) == -ENOENT);
    }
    crypt_free(cd);

    cd = test_init();
    test_hole(cd, &offset, &length);

    /* Test the layout state. */
    assert(test_layout((range_t[]) {
        { 0, 1024 },                   /* LUKS header */
        { 1024, offset - 1024, true }, /* Keyslot Area */
        { offset, 4096 },              /* luksmeta header */
        END(offset + 4096),            /* Rest of the file */
    }));

    /* Test error codes for a valid luksmeta header but no slot. */
    for (int slot = 0; slot < crypt_keyslot_max(CRYPT_LUKS1); slot++) {
        assert(luksmeta_load(cd, slot, uuid, data, sizeof(data)) == -ENODATA);
        assert(luksmeta_wipe(cd, slot, UUID) == -EALREADY);
    }

    /* Test for -EALREADY when a valid header is present. */
    assert(luksmeta_init(cd) == -EALREADY);
    assert(luksmeta_test(cd) == 0);

    /* Test for -EBADSLT when an invalid slot is used. */
    assert(luksmeta_save(cd, 10, UUID, UUID, sizeof(UUID)) == -EBADSLT);
    assert(luksmeta_load(cd, 10, uuid, data, sizeof(data)) == -EBADSLT);
    assert(luksmeta_wipe(cd, 10, UUID) == -EBADSLT);
    assert(luksmeta_save(cd, -10, UUID, UUID, sizeof(UUID)) == -EBADSLT);
    assert(luksmeta_load(cd, -10, uuid, data, sizeof(data)) == -EBADSLT);
    assert(luksmeta_wipe(cd, -10, UUID) == -EBADSLT);
    assert(luksmeta_load(cd, -1, uuid, data, sizeof(data)) == -EBADSLT);
    assert(luksmeta_wipe(cd, -1, UUID) == -EBADSLT);

    /* Test for -EKEYREJECTED when a reserved UUID is used. */
    assert(luksmeta_save(cd, CRYPT_ANY_SLOT, (luksmeta_uuid_t) {},
                        UUID, sizeof(UUID)) == -EKEYREJECTED);

    /* Test to make sure that data corruption is picked up correctly. */
    fd = open(filename, O_RDWR | O_SYNC);
    if (fd < 0)
        error(EXIT_FAILURE, errno, "%s:%d", __FILE__, __LINE__);
    if (lseek(fd, offset + 16, SEEK_SET) == -1)
        error(EXIT_FAILURE, errno, "%s:%d", __FILE__, __LINE__);
    if (write(fd, &(char) { 17 }, 1) != 1)
        error(EXIT_FAILURE, errno, "%s:%d", __FILE__, __LINE__);
    close(fd);
    assert(luksmeta_save(cd, 2, UUID, UUID, sizeof(UUID)) == -EINVAL);
    assert(luksmeta_load(cd, 2, uuid, data, sizeof(data)) == -EINVAL);
    assert(luksmeta_wipe(cd, 2, UUID) == -EINVAL);

    crypt_free(cd);
    unlink(filename);
    return 0;
}
