#!/bin/sh
set -eu

echo "PID:$$"
sleep 300 &
descendant=$!
echo "DESC:${descendant}"
echo "INITIAL:$(stty size)"
echo "READY"

while IFS= read -r command; do
  case "${command}" in
    size) echo "RESIZED:$(stty size)" ;;
    exit) exit 0 ;;
  esac
done
