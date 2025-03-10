#!/bin/bash

set -ex

ROOT_DIR=$(dirname $(realpath $BASH_SOURCE))

# Install binaries
sudo install -m 755 $ROOT_DIR/xdpass /usr/local/bin/
sudo install -m 755 $ROOT_DIR/xdpassd /usr/local/bin/

# Install systemd service
sudo install -m 644 $ROOT_DIR/systemd/xdpassd.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable xdpassd
sudo systemctl start xdpassd
