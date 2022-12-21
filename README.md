# gpgme-rs

[![Build Status][build]][ci]
[![crates.io version][version]][crate]
[![LGPL-2.1 licensed][license]](./COPYING)
[![downloads][downloads]][crate]

[GPGME][upstream] bindings for Rust.

[Documentation][docs]

## Using

To use the crate, add it to your depedencies:
```sh
$ cargo add gpgme
```

### Requirements
These crates require the gpgme library (version 1.13 or later) and its development files to be
installed. The build script uses the [system-deps] crate to attempt to locate
them (or the registry on Windows).

On Debian/Ubuntu based systems:
```sh
$ sudo apt-get install libgpgme-dev
```

On Fedora/RHEL based systems:
```sh
$ sudo dnf install gpgme-devel
```

On MacOS systems:
```sh
$ brew install gnupg
```

On Windows systems, download and install the official [Gpg4win] installer. Only
the `i686-pc-windows-gnu` target is supported.

**NOTE**: These crates also depend on the gpg-error crate which has its own
[requirements](https://github.com/gpg-rs/libgpg-error).

## Examples
Some simple example programs based on those in the GPGME sources can be found
in [examples](./examples).

They can be run with cargo:
```shell
$ cargo run --example keylist --
keyid   : 89ABCDEF01234567
fpr     : 0123456789ABCDEF0123456789ABCDEF01234567
caps    : esc
flags   :
userid 0: Example <example@example.org>
valid  0: Unknown
```
## License
These crates are licensed under the [LGPL-2.1 license](./COPYING).

[crate]: https://crates.io/crates/gpgme
[ci]: https://github.com/gpg-rs/gpgme/actions?query=branch%3Amaster
[build]: https://img.shields.io/github/workflow/status/gpg-rs/gpgme/Continuous%20Integration?style=flat-square
[version]: https://img.shields.io/crates/v/gpgme?style=flat-square
[license]: https://img.shields.io/crates/l/gpgme?style=flat-square
[downloads]: https://img.shields.io/crates/d/gpgme?style=flat-square

[upstream]: https://www.gnupg.org/\(it\)/related_software/gpgme/index.html
[docs]: https://docs.rs/gpgme
[system-deps]: https://crates.io/crates/system-deps
[Gpg4win]: https://www.gpg4win.org/
