#!/usr/bin/env bash

set -e

docker build -t crypto-docs . -f docker/docs.Dockerfile
docker run -v docs:/opt/docs crypto-docs sh -c "exit 0"
