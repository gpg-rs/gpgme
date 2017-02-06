# rust-gpgme

[![Build Status](https://travis-ci.org/johnschug/rust-gpgme.svg?branch=master)](https://travis-ci.org/johnschug/rust-gpgme)
[![LGPL-2.1 licensed](https://img.shields.io/badge/license-LGPL--2.1-blue.svg)](./COPYING)
[![crates.io](https://meritbadge.herokuapp.com/gpgme)](https://crates.io/crates/gpgme)

[GPGME][upstream] bindings for Rust.

[Documentation][docs]

## Requirements

The wrapper is usable with GPGME 1.2.0 or later. Some features may require
a more recent version.

By default, the gpgme-sys crate will attempt to build the latest version of the
library from source using autoconf and automake. An existing installation may
be specified using `GPGME_LIB_PATH`, `GPGME_LIBS` and `GPGME_STATIC`
(optional). Alternatively the path to the gpgme configuration program
(`gpgme-config`) may be specified using `GPGME_CONFIG`.

## Usage

Put this in your `Cargo.toml`:

```toml
[dependencies]
gpgme = "0.5"
```

And this in your crate root:

```rust
extern crate gpgme;
```

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

[upstream]: https://www.gnupg.org/\(it\)/related_software/gpgme/index.html
[docs]: http://johnschug.github.io/rust-gpgme
