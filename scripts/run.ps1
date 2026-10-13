param(
    [ValidateSet('build','extract','slice','detect','verify','fuzz','test','all')]
    [string]$Stage = 'all'
)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
docker image inspect protocolguard:llvm14 *> $null
if ($LASTEXITCODE -ne 0) {
    docker build -t protocolguard:llvm14 $projectRoot
    if ($LASTEXITCODE -ne 0) { throw 'Docker image build failed' }
}
docker run --rm --mount "type=bind,source=$projectRoot,target=/workspace" protocolguard:llvm14 bash scripts/run.sh $Stage
if ($LASTEXITCODE -ne 0) { throw "ProtocolGuard stage $Stage failed; see output/logs" }
