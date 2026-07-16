[CmdletBinding()]
param(
    [ValidateSet('Release', 'Debug')]
    [string]$Configuration = 'Release',

    [switch]$SkipValidation
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$project = Join-Path $root 'src\AgentOS\AgentOS.csproj'
$output = Join-Path $root 'artifacts\win-x64'

dotnet publish $project -c $Configuration -r win-x64 --self-contained true `
    -p:PublishSingleFile=true `
    -p:IncludeNativeLibrariesForSelfExtract=true `
    -o $output
if ($LASTEXITCODE -ne 0) {
    throw "dotnet publish failed with exit code $LASTEXITCODE"
}

$artifact = Join-Path $output 'agentos.exe'
if (-not $SkipValidation) {
    & (Join-Path $PSScriptRoot 'validate-windows.ps1') -ArtifactPath $artifact
}

Write-Host "Published: $artifact"
