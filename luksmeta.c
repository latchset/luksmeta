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

#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>

#define UUID_TMPL \
    "%02hhx%02hhx%02hhx%02hhx-" \
    "%02hhx%02hhx-%02hhx%02hhx-%02hhx%02hhx-" \
    "%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx"

#define UUID_ARGS(u) \
    u[0x0], u[0x1], u[0x2], u[0x3], u[0x4], u[0x5], u[0x6], u[0x7], \
    u[0x8], u[0x9], u[0xa], u[0xb], u[0xc], u[0xd], u[0xe], u[0xf]

struct options {
    const char *device;
    luksmeta_uuid_t uuid;
    bool have_uuid;
    bool force;
    int slot;
};

static int
cmd_test(const struct options *opts, struct crypt_device *cd)
{
    return luksmeta_test(cd) == 0 ? EX_OK : EX_OSFILE;
}

static int
cmd_init(const struct options *opts, struct crypt_device *cd)
{
    int r = 0;

    if (!opts->force) {
        int c = 'X';

        fprintf(stderr,
            "You are about to initialize a LUKS device for metadata storage.\n"
            "Attempting to initialize it may result in data loss if data was\n"
            "already written into the LUKS header gap in a different format.\n"
            "A backup is advised before initialization is performed.\n\n");

        while (!strchr("YyNn", c)) {
            fprintf(stderr, "Do you wish to initialize %s? [yn] ",
                    crypt_get_device_name(cd));
            c = getc(stdin);
        }

        if (strchr("Nn", c))
            return EX_NOPERM;
    }

    r = luksmeta_init(cd);
    switch (r) {
    case 0: /* fallthrough */
    case -EALREADY:
        return EX_OK;

    case -ENOSPC:
        fprintf(stderr, "Insufficient space in the LUKS header (%s)\n",
                opts->device);
        return EX_CANTCREAT;

    default:
        fprintf(stderr, "Error while initializing device (%s): %s\n",
                opts->device, strerror(-r));
        return EX_OSERR;
    }

    return EX_OK;
}

static const char *
status(struct crypt_device *cd, int keyslot)
{
    switch (crypt_keyslot_status(cd, keyslot)) {
    case CRYPT_SLOT_INVALID: return "invalid";
    case CRYPT_SLOT_INACTIVE: return "inactive";
    case CRYPT_SLOT_ACTIVE: return "active";
    case CRYPT_SLOT_ACTIVE_LAST: return "active";
    default: return "unknown";
    }
}

static int
cmd_show(const struct options *opts, struct crypt_device *cd)
{
    luksmeta_uuid_t uuid = {};

    for (int i = 0, r = 0; i < crypt_keyslot_max(CRYPT_LUKS1); i++) {
        if (opts->slot >= 0 && i != opts->slot)
            continue;

        r = luksmeta_load(cd, i, uuid, NULL, 0);
        switch (r) {
        case -EBADSLT:
            fprintf(stderr, "Invalid slot (%d)\n", opts->slot);
            return EX_USAGE;

        case -ENOENT:
            fprintf(stderr, "Device is not initialized (%s)\n",
                    opts->device);
            return EX_OSFILE;

        case -EINVAL:
            fprintf(stderr, "LUKSMeta data appears corrupt (%s)\n",
                    opts->device);
            return EX_OSFILE;

        case -ENODATA:
            if (opts->slot < 0)
                fprintf(stdout, "%d %8s %s\n", i, status(cd, i), "empty");
            break;

        default:
            if (r < 0) {
                fprintf(stderr, "%d %8s %s\n",
                        i, status(cd, i), "unknown error");
            } else {
                if (opts->slot < 0)
                    fprintf(stdout, "%d %8s ", i, status(cd, i));

                fprintf(stdout, UUID_TMPL "\n", UUID_ARGS(uuid));
            }
            break;
        }
    }

    return EX_OK;
}

static int
cmd_save(const struct options *opts, struct crypt_device *cd)
{
    uint8_t *in = NULL;
    size_t inl = 0;
    int r = 0;

    if (!opts->have_uuid) {
        fprintf(stderr, "UUID required\n");
        return EX_USAGE;
    }

    while (!feof(stdin)) {
        uint8_t *tmp = NULL;

        tmp = realloc(in, inl + 4096);
        if (!tmp) {
            fprintf(stderr, "Out of memory\n");
            free(in);
            return EX_OSERR;
        }

        in = tmp;
        r = fread(&in[inl], 1, 4096, stdin);
        inl += r;
        if (r < 4096 && (ferror(stdin) || inl == 0)) {
            fprintf(stderr, "Error reading from standard input\n");
            free(in);
            return EX_NOINPUT;
        }
    }

    if (!in) {
        fprintf(stderr, "No data on standard input\n");
        return EX_NOINPUT;
    }

    r = luksmeta_save(cd, opts->slot, opts->uuid, in, inl);
    memset(in, 0, inl);
    free(in);
    switch (r) {
    case -ENOENT:
        fprintf(stderr, "Device is not initialized (%s)\n", opts->device);
        return EX_OSFILE;

    case -EINVAL:
        fprintf(stderr, "LUKSMeta data appears corrupt (%s)\n", opts->device);
        return EX_OSFILE;

    case -EBADSLT:
        fprintf(stderr, "The specified slot is invalid (%d)\n", opts->slot);
        return EX_USAGE;

    case -EKEYREJECTED:
        fprintf(stderr, "The specified UUID is reserved (" UUID_TMPL ")\n",
                UUID_ARGS(opts->uuid));
        return EX_USAGE;

    case -EALREADY:
        fprintf(stderr, "Will not overwrite existing slot (%d)\n", opts->slot);
        return EX_UNAVAILABLE;

    case -ENOSPC:
        fprintf(stderr, "Insufficient space in the LUKS header (%s)\n",
                opts->device);
        return EX_CANTCREAT;

    default:
        if (r < 0)
            fprintf(stderr, "An unknown error occurred\n");
        else if (opts->slot < 0)
            fprintf(stdout, "%d\n", r);

        return r < 0 ? EX_OSERR : EX_OK;
    }
}

static int
cmd_load(const struct options *opts, struct crypt_device *cd)
{
    luksmeta_uuid_t uuid = {};
    int r = 0;

    if (opts->slot < 0) {
        fprintf(stderr, "Slot required\n");
        return EX_USAGE;
    }

    r = luksmeta_load(cd, opts->slot, uuid, NULL, 0);
    if (r >= 0) {
        uint8_t *out = NULL;

        if (opts->have_uuid && memcmp(opts->uuid, uuid, sizeof(uuid)) != 0) {
            fprintf(stderr,
                    "The given UUID does not match the slot UUID:\n"
                    "UUID: " UUID_TMPL "\n"
                    "SLOT: " UUID_TMPL "\n",
                    UUID_ARGS(opts->uuid),
                    UUID_ARGS(uuid));
            return EX_DATAERR;
        }

        out = malloc(r);
        if (!out) {
            fprintf(stderr, "Out of memory!\n");
            return EX_OSERR;
        }

        r = luksmeta_load(cd, opts->slot, uuid, out, r);
        if (r >= 0) {
            fwrite(out, 1, r, stdout);
            memset(out, 0, r);
        }

        free(out);
    }

    switch (r) {
    case -ENOENT:
        fprintf(stderr, "Device is not initialized (%s)\n", opts->device);
        return EX_OSFILE;

    case -EINVAL:
        fprintf(stderr, "LUKSMeta data appears corrupt (%s)\n", opts->device);
        return EX_OSFILE;

    case -EBADSLT:
        fprintf(stderr, "The specified slot is invalid (%d)\n", opts->slot);
        return EX_USAGE;

    case -ENODATA:
        fprintf(stderr, "The specified slot is empty (%d)\n", opts->slot);
        return EX_UNAVAILABLE;

    default:
        if (r < 0)
            fprintf(stderr, "An unknown error occurred\n");

        return r < 0 ? EX_OSERR : EX_OK;
    }
}

static int
cmd_wipe(const struct options *opts, struct crypt_device *cd)
{
    luksmeta_uuid_t uuid = {};
    int r = 0;

    if (opts->slot < 0) {
        fprintf(stderr, "Slot required\n");
        return EX_USAGE;
    }

    if (!opts->force) {
        int c = 'X';

        fprintf(stderr,
            "You are about to wipe a slot. This operation is unrecoverable.\n"
            "A backup is advised before proceeding.\n\n");

        while (!strchr("YyNn", c)) {
            fprintf(stderr, "Do you wish to erase slot %d on %s? [yn] ",
                    opts->slot, crypt_get_device_name(cd));
            c = getc(stdin);
        }

        if (strchr("Nn", c))
            return EX_NOPERM;
    }

    r = luksmeta_wipe(cd, opts->slot, opts->have_uuid ? opts->uuid : NULL);
    switch (r) {
    case -EALREADY:
        return EX_OK;

    case -ENOENT:
        fprintf(stderr, "Device is not initialized (%s)\n", opts->device);
        return EX_OSFILE;

    case -EINVAL:
        fprintf(stderr, "LUKSMeta data appears corrupt (%s)\n", opts->device);
        return EX_OSFILE;

    case -EBADSLT:
        fprintf(stderr, "The specified slot is invalid (%d)\n", opts->slot);
        return EX_USAGE;

    case -EKEYREJECTED:
        r = luksmeta_load(cd, opts->slot, uuid, NULL, 0);
        if (r >= 0) {
            fprintf(stderr,
                    "The given UUID does not match the slot UUID:\n"
                    "UUID: " UUID_TMPL "\n"
                    "SLOT: " UUID_TMPL "\n",
                    UUID_ARGS(opts->uuid),
                    UUID_ARGS(uuid));
        } else {
            fprintf(stderr,
                    "The given UUID does not match the slot UUID:\n"
                    "UUID: " UUID_TMPL "\n"
                    "SLOT: UNKNOWN\n",
                    UUID_ARGS(opts->uuid));
        }
        return EX_DATAERR;

    default:
        if (r < 0)
            fprintf(stderr, "An unknown error occurred\n");

        return r < 0 ? EX_OSERR : EX_OK;
    }
}

static const struct option opts[] = {
    { "help",                      .val = 'h' },
    { "force",  no_argument,       .val = 'f' },
    { "device", required_argument, .val = 'd' },
    { "uuid",   required_argument, .val = 'u' },
    { "slot",   required_argument, .val = 's' },
    {}
};

static const struct {
    int (*func)(const struct options *opts, struct crypt_device *cd);
    const char *name;
} commands[] = {
    { cmd_test, "test", },
    { cmd_init, "init", },
    { cmd_show, "show", },
    { cmd_save, "save", },
    { cmd_load, "load", },
    { cmd_wipe, "wipe", },
    {}
};

int
main(int argc, char *argv[])
{
    struct options o = { .slot = CRYPT_ANY_SLOT };

    for (int c; (c = getopt_long(argc, argv, "hfd:u:s:", opts, NULL)) != -1; ) {
        switch (c) {
        case 'h': goto usage;
        case 'd': o.device = optarg; break;
        case 'f': o.force = true; break;
        case 'u':
            if (sscanf(optarg, UUID_TMPL, UUID_ARGS(&o.uuid)) != 16) {
                fprintf(stderr, "Invalid UUID (%s)\n", optarg);
                return EX_USAGE;
            }

            o.have_uuid = true;
            break;
        case 's':
            if (sscanf(optarg, "%d", &o.slot) != 1 || o.slot < 0 ||
                o.slot >= crypt_keyslot_max(CRYPT_LUKS1)) {
                fprintf(stderr, "Invalid slot (%s)\n", optarg);
                return EX_USAGE;
            }
            break;
        }
    }

    if (argc > 1 && !o.device) {
        fprintf(stderr, "Device must be specified\n\n");
        goto usage;
    }

    if (optind != argc - 1)
        goto usage;

    for (size_t i = 0; argc > 1 && commands[i].name; i++) {
        struct crypt_device *cd = NULL;
        const char *type = NULL;
        int r = 0;

        if (strcmp(argv[optind], commands[i].name) != 0)
            continue;

        r = crypt_init(&cd, o.device);
        if (r != 0) {
            fprintf(stderr, "Unable to open device (%s): %s\n",
                    o.device, strerror(-r));
            return EX_IOERR;
        }

        r = crypt_load(cd, NULL, NULL);
        if (r != 0) {
            fprintf(stderr, "Unable to load device (%s): %s\n",
                    o.device, strerror(-r));
            crypt_free(cd);
            return EX_IOERR;
        }

        type = crypt_get_type(cd);
        if (type == NULL) {
            fprintf(stderr, "Unable to determine device type for %s\n",
                    o.device);
            crypt_free(cd);
            return EX_OSFILE;
        }

        if (strcmp(type, CRYPT_LUKS1) != 0) {
            fprintf(stderr, "%s (%s) is not a LUKS device\n", o.device, type);
            crypt_free(cd);
            return EX_OSFILE;
        }

        r = commands[i].func(&o, cd);
        crypt_free(cd);
        return r;
    }

    fprintf(stderr, "Invalid command\n\n");

usage:
    fprintf(stderr,
            "Usage: %s test -d DEVICE\n"
            "   or: %s init -d DEVICE [-f]\n"
            "   or: %s show -d DEVICE [-s SLOT]\n"
            "   or: %s save -d DEVICE [-s SLOT]  -u UUID  < DATA\n"
            "   or: %s load -d DEVICE  -s SLOT  [-u UUID] > DATA\n"
            "   or: %s wipe -d DEVICE  -s SLOT  [-u UUID] [-f]\n",
            argv[0], argv[0], argv[0], argv[0], argv[0], argv[0]);
    return EX_USAGE;
}
