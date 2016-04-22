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

#include "crc32c.h"
#include "luksmeta.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define align(n, up) ((n + (up ? 4095 : 0)) / 4096 * 4096)

#define LUKS_NSLOTS 8
#define UUID_LEN 32
#define LM_VERSION htobe32(1)

static const uint8_t LM_MAGIC[] = { 'L', 'U', 'K', 'S', 'M', 'E', 'T', 'A' };

typedef struct __attribute__((packed)) {
    uint8_t uuid[UUID_LEN];
    uint32_t offset;   /* Bytes from the start of the hole */
    uint32_t length;   /* Bytes */
    uint32_t crc32c;
    uint32_t _reserved; /* Reserved */
} lm_slot_t;

typedef struct __attribute__((packed)) {
    uint8_t magic[sizeof(LM_MAGIC)];
    uint32_t version;
    uint32_t crc32c;
    lm_slot_t slots[LUKS_NSLOTS];
} lm_t;

static bool
uuid_is_zero(uint8_t uuid[UUID_LEN])
{
    for (size_t i = 0; i < UUID_LEN; i++) {
        if (uuid[i] != 0)
            return false;
    }

    return true;
}

static inline uint32_t
checksum(lm_t lm)
{
    lm.crc32c = 0;
    return crc32c(0, &lm, sizeof(lm_t));
}

static inline ssize_t
readall(int fd, void *data, size_t size)
{
    uint8_t *tmp = data;

    for (ssize_t r, t = 0; t < (ssize_t) size; t += r) {
        r = read(fd, &tmp[t], size - t);
        if (r < 0 && errno != EAGAIN)
            return -errno;
    }

    return size;
}

static inline ssize_t
writeall(int fd, const void *buf, size_t size)
{
    const uint8_t *tmp = buf;

    for (ssize_t r, t = 0; t < (ssize_t) size; t += r) {
        r = write(fd, &tmp[t], size - t);
        if (r < 0 && errno != EAGAIN)
            return -errno;
    }

    return size;
}

/**
 * Opens the device with the specified flags.
 *
 * The length parameter is set to the amount of space in the gap between the
 * end of the last slot and the start of the encrypted data.
 *
 * The function returns either the file descriptor positioned to the start of
 * the hole or a negative errno.
 */
static int
open_hole(struct crypt_device *cd, int flags, uint32_t *length)
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
    if (data == 0)
        return -ENOTSUP; /* We don't support detatched headers */

    for (int slot = 0; slot < LUKS_NSLOTS; slot++) {
        uint64_t off = 0;
        uint64_t len = 0;

        r = crypt_keyslot_area(cd, slot, &off, &len);
        if (r < 0)
            return r;

        if (hole < off + len)
            hole = align(off + len, true);
    }

    if (hole == 0)
        return -ENOTSUP;

    if (hole >= data)
        return -ENOSPC;

    name = crypt_get_device_name(cd);
    if (!name)
        return -ENOTSUP;

    fd = open(name, flags);
    if (fd < 0)
        return -errno;

    if (lseek(fd, hole, SEEK_SET) == -1) {
        close(fd);
        return -errno;
    }

    *length = align(data - hole, false);
    return fd;
}

static int
read_header(struct crypt_device *cd, int flags, uint32_t *length, lm_t *lm)
{
    int fd = -1;
    int r = 0;

    fd = open_hole(cd, flags, length);
    if (fd < 0)
        return fd;

    r = *length >= sizeof(lm_t) ? 0 : -ENOENT;
    if (r < 0)
        goto error;

    r = readall(fd, lm, sizeof(lm_t));
    if (r < 0)
        goto error;

    r = memcmp(LM_MAGIC, lm->magic, sizeof(LM_MAGIC)) == 0 ? 0 : -ENOENT;
    if (r < 0)
        goto error;

    r = lm->version == LM_VERSION ? 0 : -ENOTSUP;
    if (r < 0)
        goto error;

    r = checksum(*lm) == be32toh(lm->crc32c) ? 0 : -EINVAL;
    if (r < 0)
        goto error;

    return fd;

error:
    close(fd);
    return r;
}

int
luksmeta_init(struct crypt_device *cd)
{
    uint32_t length = 0;
    lm_t lm = {};
    int fd = -1;
    int r = 0;

    fd = open_hole(cd, O_RDWR, &length);
    if (fd < 0)
        return fd;

    if (length < align(sizeof(lm_t), true)) {
        close(fd);
        return -ENOSPC;
    }

    memcpy(lm.magic, LM_MAGIC, sizeof(LM_MAGIC));
    lm.version = LM_VERSION;
    lm.crc32c = htobe32(checksum(lm));

    r = writeall(fd, &lm, sizeof(lm));
    if (r < 0) {
        close(fd);
        return r;
    }

    r = fsync(fd) == 0 ? 0 : -errno;
    close(fd);
    return r;
}

int
luksmeta_get(struct crypt_device *cd, int slot,
             uint8_t uuid[UUID_LEN], uint8_t *buf, size_t size)
{
    uint32_t length = 0;
    lm_slot_t *s = NULL;
    lm_t lm = {};
    int fd = -1;
    int r = 0;

    if (slot >= LUKS_NSLOTS)
        return -EBADSLT;

    fd = read_header(cd, O_RDONLY, &length, &lm);
    if (fd < 0)
        return fd;

    r = uuid_is_zero(lm.slots[slot].uuid) ? -EBADSLT : 0;
    if (r < 0)
        goto error;

    s = &lm.slots[slot];
    s->offset = be32toh(s->offset);
    s->length = be32toh(s->length);
    s->crc32c = be32toh(s->crc32c);

    if (s->offset < align(sizeof(lm), true) || s->offset + s->length > length) {
        r = -EINVAL;
        goto error;
    }

    if (buf && size >= s->length) {
        r = lseek(fd, s->offset - sizeof(lm), SEEK_CUR) == -1 ? -errno : 0;
        if (r < 0)
            goto error;

        r = readall(fd, buf, s->length);
        if (r < 0)
            goto error;

        r = crc32c(0, buf, s->length) == s->crc32c ? 0 : -EINVAL;
        if (r < 0)
            goto error;
    }

    memcpy(uuid, s->uuid, UUID_LEN);
    close(fd);
    return s->length;

error:
    close(fd);
    return r;
}

static inline bool
overlap(const lm_t *lm, int skip, uint32_t start, size_t end)
{
    for (int i = 0; i < LUKS_NSLOTS; i++) {
        uint32_t s = be32toh(lm->slots[i].offset);
        uint32_t e = s + be32toh(lm->slots[i].length);

        if (i == skip)
            continue;

        if (start <= s && s < end)
            return true;

        if (start < e && e <= end)
            return true;
    }

    return false;
}

static inline uint32_t
find_gap(const lm_t *lm, uint32_t length, int skip, size_t size)
{
    size = align(size, true);

    for (uint32_t off = align(1, true); off < length; off += align(1, true)) {
        if (!overlap(lm, skip, off, off + size))
            return off;
    }

    return 0;
}

int
luksmeta_set(struct crypt_device *cd, int slot,
             const uint8_t uuid[UUID_LEN], const uint8_t *buf, size_t size)
{
    uint32_t length = 0;
    lm_slot_t *s = NULL;
    lm_t lm = {};
    int fd = -1;
    int r = 0;

    if (slot >= LUKS_NSLOTS)
        return -EBADSLT;
    s = &lm.slots[slot];

    fd = read_header(cd, O_RDWR, &length, &lm);
    if (fd < 0)
        return fd;

    r = uuid_is_zero(s->uuid) ? 0 : -EBADSLT;
    if (r < 0)
        goto error;

    s->offset = find_gap(&lm, slot, length, size);
    r = s->offset >= align(sizeof(lm), true) ? 0 : -ENOSPC;
    if (r < 0)
        goto error;

    memcpy(s->uuid, uuid, UUID_LEN);
    s->length = size;
    s->crc32c = crc32c(0, buf, size);

    r = lseek(fd, s->offset - sizeof(lm), SEEK_CUR) == -1 ? -errno : 0;
    if (r < 0)
        goto error;

    r = writeall(fd, buf, size);
    if (r < 0)
        goto error;

    r = lseek(fd, -(s->offset + s->length), SEEK_CUR) == -1 ? -errno : 0;
    if (r < 0)
        goto error;

    r = writeall(fd, &lm, sizeof(lm));
    if (r < 0)
        goto error;

error:
    close(fd);
    return r < 0 ? r : (int) size;
}

int
luksmeta_del(struct crypt_device *cd, int slot)
{
    uint32_t length = 0;
    lm_t lm = {};
    int fd = -1;
    int r = 0;

    if (slot >= LUKS_NSLOTS)
        return -EBADSLT;

    fd = read_header(cd, O_RDWR, &length, &lm);
    if (fd < 0)
        return fd;

    r = uuid_is_zero(lm.slots[slot].uuid) ? -EBADSLT : 0;
    if (r < 0)
        goto error;

    memset(&lm.slots[slot], 0, sizeof(lm_slot_t));
    lm.crc32c = htobe32(checksum(lm));

    r = lseek(fd, -(off_t) sizeof(lm_t), SEEK_CUR) == -1 ? -errno : 0;
    if (r < 0)
        goto error;

    r = writeall(fd, &lm, sizeof(lm));
    if (r < 0)
        goto error;

    r = fsync(fd) == 0 ? 0 : -errno;
    if (r < 0)
        goto error;

    close(fd);
    return 0;

error:
    close(fd);
    return r;
}

