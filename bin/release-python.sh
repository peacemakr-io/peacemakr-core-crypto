#!/usr/bin/env bash

set -ex

function usage {
    echo "Usage: ./release-python.sh [release/local] [path/to/install/dir] [release]"
    echo "for example, ./release-python.sh local /path/to/project/venv/lib/python3.7/site-packages release (installs release build into venv)"
    echo "for example, ./release-python.sh local none release (installs release build into machine python env)"
    echo "for example, ./release-python.sh release (builds docker)"
}

if [[ "${1}" == "local" ]]; then

  if [[ "$#" -gt 3 || "$#" -lt 1 ]]; then
      echo "Illegal use"
      usage
      exit 1
  fi

  CMAKE_BUILD_TYPE=DEBUG
  if [[ "${3}" == "release" ]]; then
      CMAKE_BUILD_TYPE=RELEASE
  fi

  PYTHON_INSTALL="-DPYTHON_INSTALL_DIR=${2}"
  if [[ "${2}" == "none" ]]; then
    PYTHON_INSTALL=""
  fi

  pushd ..
  mkdir -p build && cd build
  cmake .. -DOPENSSL_ROOT_DIR=/usr/local/opt/openssl@1.1 -DPEACEMAKR_BUILD_PYTHON=ON \
           -DASAN=OFF -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE} ${PYTHON_INSTALL}
  make check install
  cd .. && rm -rf build
  popd

else

  if [[ "$#" -gt 1 ]]; then
      echo "Illegal use"
      usage
      exit 1
  fi

  BUILD_ARG="CMAKE_BUILD_TYPE=DEBUG"

  if [[ "${1}" == "release" ]]; then
      BUILD_ARG="CMAKE_BUILD_TYPE=RELEASE"
  fi

  pushd ..
  docker build -t corecrypto-python:latest . -f docker/python.Dockerfile --build-arg=${BUILD_ARG}
  popd || true
fi
