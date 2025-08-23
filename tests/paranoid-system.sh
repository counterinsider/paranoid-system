#!/bin/bash
#
# This is paranoid-system integration test
#
# Production build binaries testing requires properly configured system with TPM and IMA support
# so using simple shell script
#
# This test assumes, there are already installed paranoid-system binaries in PATH

set -e

echo "[*] Begin paranoid-system integration testing ..."

echo "[*] Launching server ..."

paranoid-srv --user user --port 1443 --log-level trace & srv_pid=$!

sleep 3

kill -0 "$srv_pid" || exit 1

trap "kill $srv_pid" TERM INT EXIT 

echo "[*] Cleaning up ..."
paranoid-boot --log-level trace cleanup

echo "[*] Enrolling client ..."
paranoid-boot --log-level trace --attest-remote --server-url "https://127.0.0.1:1443" --server-insecure enroll

echo "[*] Pushing integrity baseline ..."
paranoid-boot --log-level trace --attest-remote --server-url "https://127.0.0.1:1443" --server-insecure fix

echo "[*] Attesting ..."
paranoid-boot --log-level trace --attest-remote --server-url "https://127.0.0.1:1443" --server-insecure attest

exit 0
