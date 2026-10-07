#!/usr/bin/env bash
set -euo pipefail
cmake -S cpp -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
printf '\nBuilt: %s\n' "$(pwd)/build/mera_core"
