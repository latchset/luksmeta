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

#pragma once

#include <libcryptsetup.h>

int
luksmeta_init(struct crypt_device *cd);

int
luksmeta_get(struct crypt_device *cd, int slot,
             uint8_t type[32], uint8_t *buf, int size);

int
luksmeta_set(struct crypt_device *cd, int slot,
             const uint8_t type[32], const uint8_t *buf, int size);

int
luksmeta_del(struct crypt_device *cd, int slot);
