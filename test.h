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

#include "luksmeta.h"
#include <stdbool.h>

#include <assert.h> /* All tests need assert() */
#include <unistd.h> /* All tests need unlink() */

#define FILESIZE 4194304
#define END(s) { (s), FILESIZE - (s), true }, { 0, 0 }
#define ALIGN(s, up) (((s) + (up ? 4095 : 0)) & ~4095ULL)

typedef struct {
    size_t start;
    size_t length;
    bool zero;
} range_t;

extern char filename[];

bool
test_layout(range_t *ranges);

void
test_hole(struct crypt_device *cd, uint32_t *offset, uint32_t *length);

struct crypt_device *
test_format(void);

struct crypt_device *
test_init(void);

