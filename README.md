Rust Shred
==========

[![Build Status](https://travis-ci.org/doomrobo/rust-shred.svg?branch=master)](https://travis-ci.org/doomrobo/rust-shred)

A Rust implementation of the GNU coreutils `shred` utility for secure file
deletion. Was part of the Rust [coreutils](https://github.com/uutils/coreutils)
repo, but it appears that it is no longer maintained. `src/util.rs` was copied
from the original repo and modified. The file retains its original copyright.

```
Usage: shred [OPTION]... FILE...

Options:
    -j, --jobs JOBS     Number of files that can be shredded simultaneously;
                        default 1
    -n, --iterations N  Overwrite N times; default 3
    -s, --size FILESIZE Shred this many bytes (suffixes like K, M, G accepted)
    -u, --remove        Truncate and remove the file after overwriting (see
                        below)
    -v, --verbose       Show progress
    -x, --exact         Do not round file sizes up to the next full block;
                        this is the default for non-regular files
    -z, --zero          Add a final overwrite with zeros to hide shredding
        --help          Display this help and exit
        --version       Output version information and exit

Delete FILE(s) if --remove (-u) is specified.  The default is not to remove
the files because it is common to operate on device files like /dev/hda,
and those files usually should not be removed.
```
