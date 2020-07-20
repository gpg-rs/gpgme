# gpgme-rs

[![Build Status][build]][ci]
[![crates.io version][version]][crate]
[![LGPL-2.1 licensed][license]](./COPYING)
[![downloads][downloads]][crate]

[GPGME][upstream] bindings for Rust.

[Documentation][docs]

## Building
These crates require the gpgme library and its development files (e.g.,
headers, gpgme-config) to be installed. The buildscript will attempt to detect
the necessary information using the `gpgme-config` script distributed with
gpgme. If for whatever reason this does not work, the required information can
also be specified using one or more environment variables:
- `GPGME_INCLUDE` specifies the path(s) where header files can be found.
- `GPGME_LIB_DIR` specifies the path(s) where library files (e.g., *.so, *.a,
  *.dll, etc.) can be found.
- `GPGME_LIBS` specifies the name(s) of all required libraries.
- `GPGME_STATIC` controls whether libraries are linked to statically or
  dynamically by default. Individual libraries can have their linkage
  overridden by prefixing their names with either `static=` or `dynamic=` in
  `GPGME_LIBS`.
- `GPGME_CONFIG` specifies the path to the `gpgme-config` script.

Each environment variable, with the exceptions of `GPGME_STATIC` and
`GPGME_CONFIG`, can take multiple values separated by the platform's path
separator.

**NOTE**: These crates also depend on the gpg-error crate which has its own
[requirements](https://github.com/gpg-rs/libgpg-error).

**NOTE**: Previous versions of these crates bundled the sources of the gpgme
library and attempted to build them via the buildscript. This is no longer
supported.

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

[crate]: https://crates.io/crates/gpgme
[ci]: https://travis-ci.org/gpg-rs/gpgme
[build]: https://img.shields.io/travis/gpg-rs/gpgme/master?style=flat-square
[version]: https://img.shields.io/crates/v/gpgme?style=flat-square
[license]: https://img.shields.io/crates/l/gpgme?style=flat-square
[downloads]: https://img.shields.io/crates/d/gpgme?style=flat-square

[upstream]: https://www.gnupg.org/\(it\)/related_software/gpgme/index.html
[docs]: https://docs.rs/gpgme
