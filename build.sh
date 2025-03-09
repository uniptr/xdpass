#!/bin/bash

set -ex

VERSION=${GITHUB_REF#refs/tags/v}

if [ -z "$VERSION" ]; then
    VERSION="unknown"
fi

export VERSION
export COMMIT=$(git rev-parse --short HEAD)
export DATE=$(date +%Y-%m-%d)

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-X github.com/zxhio/xdpass/pkg/builder.Version=$VERSION \
    -X github.com/zxhio/xdpass/pkg/builder.Commit=$COMMIT \
    -X github.com/zxhio/xdpass/pkg/builder.Date=$DATE" \
    -o xdpass ./cmd/xdpass/main.go

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-X github.com/zxhio/xdpass/pkg/builder.Version=$VERSION \
    -X github.com/zxhio/xdpass/pkg/builder.Commit=$COMMIT \
    -X github.com/zxhio/xdpass/pkg/builder.Date=$DATE" \
    -o xdpassd ./cmd/xdpassd/main.go
