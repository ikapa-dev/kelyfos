# Hostile inputs

Everything in here is authored by the untrusted side. It is committed, it is run
by CI, and each file exists because something on the trust boundary did the wrong
thing with it.

## Why this directory exists at all

Before it, this project had nineteen fuzz targets and every one of them fed a
parser a string the **host** had written. The external audit of 2026-08-24 found
its critical and its highest-severity defects on the one surface none of them
touched: what a guest writes, and what the host then reads. A corpus that grows
from real findings is what stops the list of findings regrowing.

## The rule

**A fixture is a failing test before it is a fixed one.** Each file here lands
with a test that reproduces the defect it names, that test fails, and only then
does the fix follow. A fixture added after its fix is a fixture nobody has seen
fail, which is a fixture that proves nothing.

## What is here and what generates it

Textual inputs — frames, request bodies, path lists — are committed as they are.
Filesystem images are **generated** by `mkimages.go` when the tests run, because
a megabyte of ext4 per case is a poor thing to keep in a history and the
generator is the part a person needs to read. The generator is the fixture; the
image is its output.

`mke2fs` and `debugfs` are needed for the image cases. They are what
`kelyfos doctor` already requires for `--workspace`, so a machine that can run
the feature can run its hostile tests. When they are absent the image tests skip
— **except** when `KELYFOS_HOSTILE=required`, which makes a skip a failure. CI
sets it, so a job cannot pass by quietly running none of them.

## A note on `metadata_csum`

The crafted-dirent images are built with `-O ^metadata_csum`, and that is not a
shortcut around a defence. A guest holds the block device: it writes the
filesystem, so it computes the checksums, and a crafted dirent with a correct
checksum costs it nothing. Building the fixture without checksums produces a
*valid* image carrying the same hostile name, and tests the thing that actually
matters — whether the host trusts a name it was handed. A host that relied on
ext4 metadata integrity for its own safety would be relying on the attacker.
