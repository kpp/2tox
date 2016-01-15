#!/bin/bash

pip install --user cpp-coveralls

DEPS="$HOME/deps/"
export DEPS_PREFIX_PATH="$DEPS/usr"
mkdir "$DEPS"
mkdir "DEPS_PREFIX_PATH"

wget https://github.com/jedisct1/libsodium/archive/1.0.0.tar.gz -O $DEPS/libsodium-1.0.0.tar.gz
tar xzvf  $DEPS/libsodium-1.0.0.tar.gz  -C $DEPS
(cd $DEPS/libsodium-1.0.0/; ./autogen.sh; ./configure --prefix=${DEPS_PREFIX_PATH})
make -j4 -C $DEPS/libsodium-1.0.0
make install -C $DEPS/libsodium-1.0.0
