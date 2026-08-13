#!/usr/bin/env bash
set -euo pipefail

IMAGE="${1:-symcc}"

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
	printf 'ASSERT FAIL: 缺少镜像 %s，请先执行 docker build -t %s .\n' \
		"$IMAGE" "$IMAGE" >&2
	exit 125
fi
docker run --rm "$IMAGE" bash -lc '
  rm -rf /tmp/output/*
  sym++ -o /tmp/sample /home/ubuntu/sample.cpp
  echo test | /tmp/sample >/dev/null 2>&1
  grep -R -n -x "root" /tmp/output >/dev/null
'

echo "PASS: sym++ generated a testcase containing root"
