#!/bin/bash

set -ex

ROOT_DIR=$(dirname $(dirname $(realpath $BASH_SOURCE)))
BUILD_DIR=$ROOT_DIR/build
RELEASE_DIR=$ROOT_DIR/build/release

pack_systemd_service() {
    # Copy binaries to release directory
    cp -r $BUILD_DIR/{xdpassd,xdpass} $RELEASE_DIR/

    # Copy systemd service to release directory
    mkdir -p $RELEASE_DIR/systemd
    cp -r $ROOT_DIR/systemd/xdpassd.service $RELEASE_DIR/systemd/

    # Copy install script to release directory
    cp -r $ROOT_DIR/scripts/install.sh $RELEASE_DIR/

    # Create tarball
    tar -zcf $BUILD_DIR/xdpass.tar.gz -C $RELEASE_DIR/ .
}

pack() {
    # Build
    $ROOT_DIR/scripts/build.sh

    # Create release directory
    rm -rf $RELEASE_DIR
    mkdir -p $RELEASE_DIR

    # Pack
    pack_systemd_service

    # Clean up
    rm -rf $RELEASE_DIR
}

pack
