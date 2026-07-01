#!/bin/sh
set -e

retry() {
  for i in $(seq 1 10); do
    if "${@}"; then
      return 0
    else
      sleep "${i}"
    fi
  done
  "${@}"
}

if [ -z "${CAPSUDO_TAG_NAME}" ]; then
  echo "CAPSUDO_TAG_NAME env is missing"
  exit 1
fi

cd target/assets

retry gh release upload "${CAPSUDO_TAG_NAME}" --clobber ./*
