luksmeta(1) -- Utility for storing metadata in a LUKSv1 header
==============================================================

## SYNOPSIS

`luksmeta test` -d DEVICE

`luksmeta init` -d DEVICE [-f]

`luksmeta show` -d DEVICE [-s SLOT]

`luksmeta save` -d DEVICE [-s SLOT]  -u UUID  < DATA

`luksmeta load` -d DEVICE  -s SLOT  [-u UUID] > DATA

`luksmeta wipe` -d DEVICE  -s SLOT  [-u UUID] [-f]

## OVERVIEW

The `luksmeta` utility enables an administrator to store metadata in the gap
between the end of the LUKSv1 header and the start of the encrypted data.

The metadata is stored in a series of UUID-typed slots, allowing multiple
blocks of metadata. Although the `luksmeta` slots are inspired by the LUKS
slots, they are functionally independent and share only a casual relationship.

After a LUKSv1 volume is initialized using `cryptsetup`(8), it must also be
initialized for metadata storage by `luksmeta init`. Once this is complete,
the device is ready to store medata.

Data can be written to a slot using `luksmeta save` or read from a slot
using `luksmeta load`. You can also erase the data in an existing slot using
`luksmeta wipe` or query the slots using `luksmeta show`.

## UUID GENERATION

It is often presumed that saving metadata to a slot requires a specific UUID.
This is incorrect. The UUID is not in any way special, it simply identifies
the type of data you store in the slot. If you are defining a new type of
metadata, simply generate a random UUID and use it to identify your metadata.
The easiest way to generate a UUID is to use `uuidgen`(1).

## INITIALIZATION

Before reading or writing metadata, the LUKSv1 block device must be
initialized for metadata storage. Two commands help with this process:
`luksmeta test` and `luksmeta init`.

The `luksmeta test` command simply checks an existing block device to see
if it is initialized for metadata storage. It returns zero if the device
is already initialized. Otherwise, it returns non-zero.

The `luksmeta init` command initializes the LUKSv1 block device for metadata
storage. This process will wipe out any data in the LUKSv1 header gap. For
this reason, you should use great care with this command. However, if the
block device already contains a `luksmeta` header, no modifications will be
performed. Because initialization is a destructive operation, this command
will require user confirmation before any data is written, unless the `-f`
option is supplied.

## METADATA STATE

The `luksmeta show` command displays the current state of slots on the LUKSv1
block device. If no slot is specified, it prints a table consisting of the
slot number, the corresponding LUKSv1 slot state and the UUID of the data
stored in the `luksmeta` slot (or "empty" if no data is stored). If a slot is
specified, this command simply prints out the UUID of the data in the slot. If
the slot does not contain data, it prints nothing.

## MANAGING METADATA

Managing the metadata in the slots is performed with three commands:
`luksmeta save`, `luksmeta load` and `luksmeta wipe`. These commands write
metadata to a slot, read metadata from a slot and erase metadata in a slot,
respectively.

The `luksmeta save` command reads metadata on standard input and writes it to
the specified slot using the specified UUID. If no slot is specified, the
metadata is written to the first empty slot using the specified UUID. In this
case, the slot written to is printed to standard output. This command will
never overwrite existing data. To replace data in a slot you will need to
execute `luksmeta wipe` before `luksmeta save`.

The `luksmeta load` command reads data from the specified slot and writes it
to standard output. If a UUID is specified, the command will verify that the
UUID associated with the metadata in the slot matches the specified UUID. This
type check helps to ensure that you always receive the type of data you are
expecting as output. If the UUIDs do not match, the command will fail.

The `luksmeta wipe` command erases the data from the given slot. If a UUID is
specified, the command will verify that the UUID associated with the metadata
in the slot matches the specified UUID. This type check helps to ensure that
you only erase the data you intended to erase. Because this is a destructive
operation, this command will require user confirmation before any data is
erased, unless the `-f` option is supplied.

## CAVEATS

The ammount of storage in the LUKSv1 header gap is extremely limited. It also
varies based upon the configuration used by LUKSv1 at device initialization
time. In some LUKSv1 configurations, there is not even enough space for
all the metadata slots even at the smallest possible slot size.

During the design of this utility, we considered it likely that users would
want to reduce the number of available slots in exchange for more storage
space in the remaining slots. In order to provide this flexibility, the amount
of storage available per-slot is dynamic. Put simply, slots are not a fixed
size. This means that it is possible (and even somewhat likely) to encounter
an error during `luksmeta save` indicating that there is insufficient space.

This error is not a programming bug. If you encounter this error it likely
means that either all space is being consumed by the already-written slots or
that the metadata you are attempting to write simply does not fit.

## OPTIONS

* `-d` _DEVICE_ :
  The device on which to perform the operation.

* `-s` _SLOT_ :
  The slot on which to perform the operation.

* `-u` _UUID_ :
  The UUID to associate with the operation.

* `-f` :
  Forcibly suppress all user prompting.

## AUTHOR

Nathaniel McCallum &lt;npmccallum@redhat.com&gt;

## SEE ALSO

`cryptsetup`(8),
`uuidgen`(1)
