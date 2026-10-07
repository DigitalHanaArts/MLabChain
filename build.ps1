$ErrorActionPreference = 'Stop'
cmake -S cpp -B build
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
Write-Host "Built: $PWD\build\Release\mera_core.exe"
