## v0.11.1 (2024-XX-XX)
- Added install instructions for required dependencies on Windows via `winget`
- Added `TryFrom` implementations for `Data` from common IO types
- Updated bindings for GPGMe 1.23
- Removed redundant global context engine lock
- Deprecated `Data::from_fd` in favor of `Data::from_borrowed_fd` which uses the new safe raw-IO
  type (`BorrowedFd`)
- Deprecated `Data::from_{read,write,stream}` in favor of `Data::builder` and `DataBuilder` which
  reduces number of functions needed to support all combinations of IO traits
- Fixed soundness bug in `ContextWithCallbacks`
- Fixed soundness bugs related to raw pointer to reference to slice conversions
