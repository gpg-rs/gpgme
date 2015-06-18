# rust-gpgme

[![Build Status](https://travis-ci.org/johnschug/rust-gpgme.svg?branch=master)](https://travis-ci.org/johnschug/rust-gpgme)
[![LGPL-2.1 licensed](https://img.shields.io/badge/license-LGPL--2.1-blue.svg)](./COPYING)
[![crates.io](https://meritbadge.herokuapp.com/gpgme)](https://crates.io/crates/gpgme)

[GPGme](https://www.gnupg.org/\(it\)/related_software/gpgme/index.html) bindings for Rust.

[Documentation](http://johnschug.github.io/rust-gpgme)

## Requirements

The GPGme libraries are required to use this library.


## Usage

Put this in your `Cargo.toml`:

```toml
[dependencies]
gpgme = "*"
```

And this in your crate root:

```rust
extern crate gpgme;
```

## Examples

Some simple example programs based on those in the GPGme sources can be found in [examples](./examples).

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
