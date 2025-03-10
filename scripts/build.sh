#!/bin/bash

set -ex

ROOT_DIR=$(dirname $(dirname $(realpath $BASH_SOURCE)))
BUILD_DIR=$ROOT_DIR/build

# Set build info
VERSION=${GITHUB_REF#refs/tags/v}
if [ -z "$VERSION" ]; then
    VERSION="unknown"
fi
export VERSION
export COMMIT=$(git rev-parse --short HEAD)
export DATE=$(date +%Y-%m-%d)

# Set build flags
export CGO_ENABLED=0
export GOOS=linux
export GOARCH=amd64

# Build binaries
go build -ldflags "-X github.com/zxhio/xdpass/pkg/builder.Version=$VERSION \
        -X github.com/zxhio/xdpass/pkg/builder.Commit=$COMMIT \
    -X github.com/zxhio/xdpass/pkg/builder.Date=$DATE" \
    -o $BUILD_DIR/xdpass $ROOT_DIR/cmd/xdpass/main.go

go build -ldflags "-X github.com/zxhio/xdpass/pkg/builder.Version=$VERSION \
    -X github.com/zxhio/xdpass/pkg/builder.Commit=$COMMIT \
    -X github.com/zxhio/xdpass/pkg/builder.Date=$DATE" \
    -o $BUILD_DIR/xdpassd $ROOT_DIR/cmd/xdpassd/main.go
