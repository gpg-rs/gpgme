#!/bin/sh
set -ex
curl -sL "https://ftp.gnu.org/gnu/gettext/gettext-${1}.tar.gz" -o "gettext-${1}.tar.gz"
tar -xf "gettext-${1}.tar.gz"
cd "gettext-${1}"
./configure --without-emacs --disable-java --disable-csharp --disable-c++ --enable-fast-install --prefix="${HOME}/.local" >/dev/null
make -j2 install >/dev/null
export PATH=${HOME}/.local/bin:$PATH
export LD_LIBRARY_PATH=${HOME}/.local/lib:$LD_LIBRARY_PATH
