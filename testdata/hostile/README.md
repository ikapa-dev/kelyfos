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

This file and the ledger beside it. Everything else is **generated when the
tests run**, by `internal/sandbox/hostile.go` for the filesystem images and by
the fixtures themselves for the frames, the requests and the paths.

That is a deliberate choice and not a shortcut. A megabyte of ext4 per case is a
poor thing to keep in a history, and it is the wrong artefact to review: what a
person needs to read is *how the attack is built* — that a crafted directory
entry is patched over a placeholder which reserved its room, and that `name_len`
moves with it so a shorter name needs no record after it to move. The generator
is the fixture. The image is its output, and it is rebuilt from scratch every
time so it cannot drift away from the code that explains it.

## Where the cases live

Beside the code they attack, because that is where somebody changing it will see
them:

| file | surface | findings |
| --- | --- | --- |
| `internal/sandbox/hostile_test.go` | the workspace block device, read back with `debugfs` | C-1, H-2 |
| `internal/sandbox/hostile_exec_test.go` | the exec channel, which has no host-side deadline | M-9 |
| `internal/sandbox/hostile_control_test.go` | the control channel, and what a guest's refusal prints | — |
| `supervisor/hostile_test.go` | `read_file` / `write_file`, run by an unconfined PID 1 | H-1 |
| `internal/team/hostile_test.go` | the broker's timeouts, the store, the refusal record | H-3, H-4, H-5 |
| `shim/hostile_test.go` | the one door another machine can knock on | H-6 |

Two of them do not correspond to the finding that prompted them, and both say so
in their own file. `hostile_exec_test.go` does not test "no total-output
ceiling", which was fixed before the audit was read; it tests the four ways a
stream that never ends makes the call never return. `hostile_control_test.go`
does not test "the host proceeds on a refusal", which it does not — that stub,
while it was being built, printed the guest's chosen bytes on the terminal.

A fixture for a defect that does not exist is worse than no fixture: it is a
test somebody will one day "fix" by looking for a bug that was never there.

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
