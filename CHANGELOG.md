# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Added
- Added `TryFrom` implementations for `Data` from common IO types
- Added new bindings for GPGMe 1.23

### Fixed
- Fixed soundness bug in `ContextWithCallbacks`
- Fixed soundness bugs related to raw pointer to reference to slice conversions

### Deprecated
- Deprecated `Data::from_fd` in favor of `Data::from_borrowed_fd` which uses the new safe raw-IO
  type (`BorrowedFd`)
- Deprecated `Data::from_{read,write,stream}` in favor of `Data::builder` and `DataBuilder` which
  reduces the number of functions needed to support all combinations of IO traits
- Deprecated the safety of `gpgme::set_flag`. This function is not thread safe and has
  similar safety issues to  [`std::env::set_var`](https://doc.rust-lang.org/stable/std/env/fn.set_var.html)

### Other
- Added install instructions for required dependencies on Windows via `winget`
- Fixed install instructions for apt base distributions (#43)
- Removed redundant global context engine lock
