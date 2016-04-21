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

#include "luksmeta.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#define LUKS_NSLOTS 8
#define KEYSLOT_ALIGN 4096
#define DATASLOT_ALIGN 512

static const uint8_t MAGIC[] = { 'L', 'U', 'K', 'S', 'M', 'E', 'T', 'A' };

struct luksmeta {
    uint8_t magic[sizeof(MAGIC)];
    uint32_t length;
    uint32_t crc;
    struct {
        uint32_t offset;
        uint32_t length;
    } slots[LUKS_NSLOTS];

    uint8_t data[];
} __attribute__((packed));

static int
hole(struct crypt_device *cd, uint64_t *length)
{
    const char *name = NULL;
    const char *type = NULL;
    uint64_t hole = 0;
    uint64_t data = 0;
    int fd = 0;
    int r = 0;

    type = crypt_get_type(cd);
    if (!type || strcmp(CRYPT_LUKS1, type) != 0)
        return -ENOTSUP;

    data = crypt_get_data_offset(cd);

    for (int slot = 0; slot < crypt_keyslot_max(CRYPT_LUKS1); slot++) {
        uint64_t off = 0;
        uint64_t len = 0;

        r = crypt_keyslot_area(cd, slot, &off, &len);
        if (r < 0)
            return r;

        if (hole < off + len)
            hole = off + len;
    }

    hole = (hole + KEYSLOT_ALIGN - 1) / KEYSLOT_ALIGN * KEYSLOT_ALIGN;
    if (hole > data)
        return -ENOSPC;

    *length = data - hole;
    if (*length < DATASLOT_ALIGN * (LUKS_NSLOTS + 1))
        return -ENOSPC;

    name = crypt_get_device_name(cd);
    if (!name)
        return -ENOTSUP;

    fd = open(name, O_RDONLY);
    if (fd < 0)
        return -errno;

    if (lseek(fd, hole, SEEK_SET) == -1) {
        close(fd);
        return -errno;
    }

    return fd;
}

int
luksmeta_init(struct crypt_device *cd)
{
    uint64_t length = 0;
    int fd = -1;

    fd = hole(cd, &length);
    if (fd < 0)
        return fd;

    return 0;
}

int
luksmeta_get(struct crypt_device *cd, int slot,
             uint8_t type[32], uint8_t *buf, int size)
{
    return 0;
}

int
luksmeta_set(struct crypt_device *cd, int slot,
             const uint8_t type[32], const uint8_t *buf, int size)
{
    return 0;
}

int
luksmeta_del(struct crypt_device *cd, int slot)
{
    return 0;
}


