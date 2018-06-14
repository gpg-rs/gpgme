# gpgme-rs

[![Build Status](https://travis-ci.org/gpg-rs/gpgme.svg?branch=master)](https://travis-ci.org/gpg-rs/gpgme)
[![LGPL-2.1 licensed](https://img.shields.io/crates/l/gpgme.svg)](./COPYING)
[![Crates.io](https://img.shields.io/crates/v/gpgme.svg)](https://crates.io/crates/gpgme)

[GPGME][upstream] bindings for Rust.

[Documentation][docs]

## Requirements

The wrapper is usable with GPGME 1.2.0 or later. Some features may require
a more recent version.

By default, the gpgme-sys crate will attempt to build the bundled version of
the library from source using autoconf, automake and various C build tools. The
`bundled` feature flag controls this functionality and can be disabled by using
`default-features = false` in dependent crates and/or overridden by setting the
environment variable `GPGME_USE_BUNDLED` to the empty string, `no`, `off`, or
`false` to disable or anything else to enable. An existing installation may be
specified using `GPGME_LIB_DIR`, `GPGME_LIBS`, `GPGME_STATIC` (optional) and
`GPGME_INCLUDE`. Alternatively the path to the gpgme configuration program
(`gpgme-config`) may be specified using `GPGME_CONFIG`.

## Usage

Put this in your `Cargo.toml`:

```toml
[dependencies]
gpgme = "0.8"
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
[docs]: https://docs.rs/gpgme
