#!/usr/bin/env bash

set -e

CONFIG="${1:-Debug}"

case "$CONFIG" in
    Debug)
        CXXFLAGS="-g -O0 -DDEBUG"
        OUTDIR="bin/Debug-Linux-x64"
        ;;
    Release)
        CXXFLAGS="-O2 -DNDEBUG -flto"
        OUTDIR="bin/Release-Linux-x64"
        ;;
    *)
        echo "Usage: $0 [Debug|Release]"
        exit 1
        ;;
esac

mkdir -p "$OUTDIR"

clang++ \
    $(llvm-config --cxxflags --ldflags --system-libs --libs all) \
    -std=c++20 \
    -fPIC \
    -fexceptions \
    $CXXFLAGS \
    -Isrc \
    -Isrc/vendor \
    src/main.cpp \
    -o "$OUTDIR/floof"