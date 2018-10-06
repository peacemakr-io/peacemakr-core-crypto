#!/usr/bin/env bash

set -e

docker build -t crypto-doc-server . -f docker/docs.Dockerfile
docker run --rm -it -p 3000:3000 crypto-doc-server
