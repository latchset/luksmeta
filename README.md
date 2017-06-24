[![License](http://img.shields.io/:license-lgpl2-blue.svg?style=flat-square)](http://www.gnu.org/licenses/lgpl-2.1.html)
[![Build Status](https://travis-ci.org/latchset/luksmeta.svg?branch=master)](https://travis-ci.org/latchset/luksmeta)
[![Code Coverage](http://codecov.io/github/latchset/luksmeta/coverage.svg?branch=master)](http://codecov.io/github/latchset/luksmeta?branch=master)
[![Coverity Scan Build Status](https://scan.coverity.com/projects/8706/badge.svg)](https://scan.coverity.com/projects/latchset-luksmeta)

# LUKSMeta

Welcome to LUKSMeta! LUKSMeta is a simple library for storing metadata in the LUKSv1 header. This library is licensed under the GNU LGPLv2+.

## Why LUKSMeta?

Some projects need to store additional metadata about a LUKS volume that is accessable before unlocking it. Two such examples are [USBGuard][usbguard] and [Tang][tang]. Fortunately, there is a gap in the LUKS header between the end of the slot area and the payload offset:

    +---------------+------------------+-----------------------------------------+----------------+
    | LUKSv1 header | LUKSv1 slots (8) |                                         | Encrypted Data |
    +---------------+------------------+-----------------------------------------+----------------+

LUKSMeta uses this hole to store additional metadata.

## How does LUKSMeta work?

LUKSMeta's on-disk format consists of a header block, followed by 0-8 data blocks. Each block is aligned to 4096 bytes. The LUKSMeta header contains a checksum (CRC32c) of itself and of each data block to detect data corruption. Each data block is also given a 16 byte UUID type to uniquely identify the contents of the block.

The end result looks like this on disk:

    +---------------+------------------+-----------------+-----------------------+----------------+
    | LUKSv1 header | LUKSv1 slots (8) | LUKSMeta header | LUKSMeta blocks (0-8) | Encrypted Data |
    +---------------+------------------+-----------------+-----------------------+----------------+

## LUKSMeta Command Line Interface

    luksmeta test -d DEVICE
    luksmeta nuke -d DEVICE [-f]
    luksmeta init -d DEVICE [-f] [-n]
    luksmeta show -d DEVICE [-s SLOT]
    luksmeta save -d DEVICE [-s SLOT]  -u UUID  < DATA
    luksmeta load -d DEVICE  -s SLOT  [-u UUID] > DATA
    luksmeta wipe -d DEVICE  -s SLOT  [-u UUID] [-f]

### Examples

Destroy all data (including LUKSMeta data) in the LUKSv1 header gap and
initalize the gap for LUKSMeta storage:

    $ luksmeta init -n -d /dev/sdz
    You are about to initialize a LUKS device for metadata storage.
    Attempting to initialize it may result in data loss if data was
    already written into the LUKS header gap in a different format.
    A backup is advised before initialization is performed.

    Do you wish to initialize /dev/sdz? [yn] y

If already initialized, do nothing. Otherwise, destroy all non-LUKSMeta data
in the LUKSv1 header gap and initialize the gap for LUKSMeta storage. Skip
user confirmation (dangerous!):

    $ luksmeta init -f -d /dev/sdz

Write some data to a slot:

    $ UUID=`uuidgen`
    $ echo $UUID
    31c25e3b-b8e2-4eaa-a427-23aa882feef2
    $ echo "Hello, World" | luksmeta save -d /dev/sdz -s 0 -u $UUID

Read the data back:

    $ luksmeta load -d /dev/sdz -s 0 -u $UUID
    Hello, World

Wipe the data from the slot:

    $ luksmeta wipe -d /dev/sdz -s 0 -u $UUID

Erase all trace of LUKSMeta:

    $ luksmeta nuke -d /dev/sdz
    You are about to erase all data in the LUKSMeta storage area.
    A backup is advised before erasure is performed.

    Do you wish to nuke /dev/sdz? [yn] y

[usbguard]: https://github.com/dkopecek/usbguard
[tang]: https://github.com/latchset/tang
