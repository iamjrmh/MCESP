param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Get", "Set")]
    [string]$Mode,

    [Parameter(Mandatory = $true)]
    [string]$Path,

    [string]$ReleasePath,
    [string]$NewVersion
)

$ErrorActionPreference = "Stop"

if ($Mode -eq "Get") {
    $content = Get-Content -Raw -Path $Path
    $match = [regex]::Match($content, 'VERSION = "(\d+\.\d+\.\d+)"')
    if (-not $match.Success) {
        exit 1
    }
    Write-Output $match.Groups[1].Value
    exit 0
}

# Mode -eq "Set"
$utf8NoBom = New-Object System.Text.UTF8Encoding $false

$content = Get-Content -Raw -Path $Path
$newContent = $content -replace 'VERSION = "\d+\.\d+\.\d+"', "VERSION = `"$NewVersion`""
[System.IO.File]::WriteAllText($Path, $newContent, $utf8NoBom)

if ($ReleasePath -and (Test-Path $ReleasePath)) {
    $releaseContent = Get-Content -Raw -Path $ReleasePath
    $releaseNewContent = $releaseContent -replace '# MCESP v\d+\.\d+\.\d+', "# MCESP v$NewVersion"
    [System.IO.File]::WriteAllText($ReleasePath, $releaseNewContent, $utf8NoBom)
    Write-Output "release_updated"
}
