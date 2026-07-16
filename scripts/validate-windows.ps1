[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ArtifactPath,

    [string]$ReportDirectory = (Join-Path $PSScriptRoot '..\artifacts\validation')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$artifact = [System.IO.Path]::GetFullPath($ArtifactPath)
$reportDirectory = [System.IO.Path]::GetFullPath($ReportDirectory)
if (-not (Test-Path -LiteralPath $artifact -PathType Leaf)) {
    throw "Windows artifact not found: $artifact"
}

New-Item -ItemType Directory -Path $reportDirectory -Force | Out-Null
$transcriptPath = Join-Path $reportDirectory 'self-test.txt'
$started = [DateTimeOffset]::UtcNow

& $artifact self-test 2>&1 | Tee-Object -FilePath $transcriptPath
if ($LASTEXITCODE -ne 0) {
    throw "AgentOS self-test failed with exit code $LASTEXITCODE. See $transcriptPath"
}

$signature = Get-AuthenticodeSignature -LiteralPath $artifact
$report = [ordered]@{
    schemaVersion = 1
    timestampUtc = [DateTimeOffset]::UtcNow.ToString('O')
    durationSeconds = [Math]::Round(([DateTimeOffset]::UtcNow - $started).TotalSeconds, 3)
    artifact = $artifact
    sha256 = (Get-FileHash -LiteralPath $artifact -Algorithm SHA256).Hash
    signatureStatus = $signature.Status.ToString()
    operatingSystem = [System.Environment]::OSVersion.VersionString
    powershell = $PSVersionTable.PSVersion.ToString()
    selfTestExitCode = 0
    transcript = $transcriptPath
}
$report | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $reportDirectory 'report.json') -Encoding utf8
Write-Host "Validation passed. Report: $(Join-Path $reportDirectory 'report.json')"
