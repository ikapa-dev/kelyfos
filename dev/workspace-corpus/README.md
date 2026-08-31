# Workspace corpus — crafted ext4 images the write-back must survive (ST-3.3)

Each `.debugfs` file here is a debugfs command script that
`internal/sandbox`'s corpus test (`workspace_corpus_test.go`) applies to a
freshly-built ext4 image, reproducing a shape the independent audit flagged
or the write-back path has to defend against:

| script | the shape | what the extraction must do |
| --- | --- | --- |
| `xattrs-nuke.debugfs` | `security.*` xattrs on a file, the kind a hardened tool or a previous LSM labels with | extract the file's contents; never recreate the `security.*` namespace on the host (it needs privileges it should not use) |
| `whiteout.debugfs` | a char device `0:0` — the overlayfs whiteout shape | refuse the whole image (`ErrHostileImage`): a device node is not something to create in somebody's project |
| `nfd-and-colon.debugfs` | NFD-decomposed unicode names and `:` — names a macOS (APFS) or Windows target chokes on | extract byte-exact on Linux; the write-back target's quirks are the writer's problem, not the extractor's |
| `dir-hardlink.debugfs` | a hardlink whose second name is a directory — ext4 corruption via debugfs's own `ln` | list or extract refuses cleanly; no panic, no infinite walk |
| `short-image.debugfs` | nothing — the test truncates the image the script builds | the read fails cleanly (F17: a short dump is detectable, not silent) |

The images are built by the test with `mke2fs` + `debugfs -w -f <script>`;
the test skips when either is missing, so a machine without e2fsprogs still
runs every other test.
