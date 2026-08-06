<#
.SYNOPSIS
Install the sbx-warden server and/or the sbx client from the latest GitHub release.

.DESCRIPTION
The server (sbx-warden) runs on your host; the client (sbx) belongs inside a
sandbox. Both are installed by default.

Piping to iex cannot pass parameters, so the environment variables below are
honoured as well:

  SBX_WARDEN_COMPONENTS    both (default), client or server
  SBX_WARDEN_VERSION       release to install, e.g. v0.1.0
  SBX_WARDEN_INSTALL_DIR   installation directory

.EXAMPLE
irm https://raw.githubusercontent.com/cdupuis/sbx-warden/main/install.ps1 | iex

.EXAMPLE
$env:SBX_WARDEN_COMPONENTS = 'server'
irm https://raw.githubusercontent.com/cdupuis/sbx-warden/main/install.ps1 | iex
#>
[CmdletBinding()]
param(
    [switch]$Client,
    [switch]$Server,
    [string]$Version,
    [string]$Dir,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repo = 'cdupuis/sbx-warden'
$api = "https://api.github.com/repos/$repo"
$downloads = "https://github.com/$repo/releases/download"

# Windows PowerShell 5.1 still negotiates TLS 1.0 by default.
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
} catch {
    Write-Verbose 'could not raise the TLS version; continuing'
}

function Get-Components {
    if ($Client -and -not $Server) { return 'client' }
    if ($Server -and -not $Client) { return 'server' }
    if ($Client -and $Server) { return 'both' }
    if ($env:SBX_WARDEN_COMPONENTS) {
        $requested = $env:SBX_WARDEN_COMPONENTS.ToLowerInvariant()
        if ($requested -notin @('both', 'client', 'server')) {
            throw "SBX_WARDEN_COMPONENTS must be both, client or server, got: $requested"
        }
        return $requested
    }
    return 'both'
}

function Get-Architecture {
    switch ($env:PROCESSOR_ARCHITECTURE) {
        'AMD64' { return 'amd64' }
        'ARM64' { return 'arm64' }
        default { throw "unsupported architecture: $env:PROCESSOR_ARCHITECTURE" }
    }
}

function Get-ReleaseTag {
    $requested = if ($Version) { $Version } else { $env:SBX_WARDEN_VERSION }
    if ($requested) {
        if ($requested.StartsWith('v')) { return $requested }
        return "v$requested"
    }
    try {
        $release = Invoke-RestMethod -Uri "$api/releases/latest" -UseBasicParsing
    } catch {
        throw "could not query the latest release of ${repo}: $($_.Exception.Message)"
    }
    if (-not $release.tag_name) { throw "could not determine the latest release tag of $repo" }
    return $release.tag_name
}

function Get-InstallDirectory {
    $target = if ($Dir) { $Dir } elseif ($env:SBX_WARDEN_INSTALL_DIR) { $env:SBX_WARDEN_INSTALL_DIR }
    else { Join-Path $env:LOCALAPPDATA 'sbx-warden\bin' }
    if (-not (Test-Path -LiteralPath $target)) {
        New-Item -ItemType Directory -Path $target -Force | Out-Null
    }
    return (Resolve-Path -LiteralPath $target).Path
}

# Test-OurClient reports whether a path holds an sbx-warden client rather than the
# real Docker Sandboxes CLI, so an upgrade can be told apart from a collision.
function Test-OurClient {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $false }
    try {
        $previous = $env:SBX_WARDEN_PRINT_VERSION
        $env:SBX_WARDEN_PRINT_VERSION = '1'
        $output = & $Path 2>$null | Select-Object -First 1
        return ($output -like 'sbx-warden client *')
    } catch {
        return $false
    } finally {
        $env:SBX_WARDEN_PRINT_VERSION = $previous
    }
}

function Get-Archive {
    param([string]$Name, [string]$Tag, [string]$TempDir, [string]$ChecksumFile)

    $archivePath = Join-Path $TempDir $Name
    Write-Host "downloading $Name"
    try {
        Invoke-WebRequest -Uri "$downloads/$Tag/$Name" -OutFile $archivePath -UseBasicParsing
    } catch {
        throw "could not download $downloads/$Tag/${Name}: $($_.Exception.Message)"
    }

    $expected = $null
    foreach ($line in Get-Content -LiteralPath $ChecksumFile) {
        $fields = $line -split '\s+', 2
        if ($fields.Count -eq 2 -and $fields[1].Trim() -eq $Name) {
            $expected = $fields[0].Trim()
            break
        }
    }
    if (-not $expected) { throw "$Name is not listed in checksums.txt for $Tag" }

    $actual = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash
    if ($actual -ne $expected.ToUpperInvariant()) {
        throw "checksum mismatch for ${Name}: expected $expected, got $actual"
    }

    $extractDir = Join-Path $TempDir ([IO.Path]::GetFileNameWithoutExtension($Name))
    Expand-Archive -LiteralPath $archivePath -DestinationPath $extractDir -Force
    return $extractDir
}

function Install-Binary {
    param([string]$SourceDir, [string]$Name, [string]$Destination)

    $source = Join-Path $SourceDir $Name
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
        throw "$Name missing from the release archive"
    }
    $target = Join-Path $Destination $Name
    try {
        Copy-Item -LiteralPath $source -Destination $target -Force
    } catch {
        throw "could not write ${target}: $($_.Exception.Message). Stop any running sbx-warden and retry."
    }
    Write-Host "installed $target"
}

function Add-ToUserPath {
    param([string]$Directory)

    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    $entries = @()
    if ($userPath) { $entries = $userPath -split ';' | Where-Object { $_ } }
    if ($entries -contains $Directory) { return }

    $updated = (($entries + $Directory) -join ';')
    [Environment]::SetEnvironmentVariable('Path', $updated, 'User')
    $env:Path = "$env:Path;$Directory"
    Write-Host "added $Directory to your user PATH; open a new terminal for it to take effect"
}

$components = Get-Components
$arch = Get-Architecture
$tag = Get-ReleaseTag
$releaseVersion = $tag.TrimStart('v')
$installDir = Get-InstallDirectory

$tempDir = Join-Path ([IO.Path]::GetTempPath()) ("sbx-warden-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tempDir -Force | Out-Null

$installedServer = $false
$installedClient = $false

try {
    Write-Host "sbx-warden $tag for windows/$arch into $installDir"

    $checksumFile = Join-Path $tempDir 'checksums.txt'
    try {
        Invoke-WebRequest -Uri "$downloads/$tag/checksums.txt" -OutFile $checksumFile -UseBasicParsing
    } catch {
        throw "could not download checksums for ${tag}: $($_.Exception.Message)"
    }

    if ($components -in @('both', 'server')) {
        $extracted = Get-Archive -Name "sbx-warden_${releaseVersion}_windows_${arch}.zip" `
            -Tag $tag -TempDir $tempDir -ChecksumFile $checksumFile
        Install-Binary -SourceDir $extracted -Name 'sbx-warden.exe' -Destination $installDir
        $installedServer = $true
    }

    if ($components -in @('both', 'client')) {
        $target = Join-Path $installDir 'sbx.exe'
        $skipClient = $false

        if ((Test-Path -LiteralPath $target) -and -not (Test-OurClient -Path $target)) {
            if ($Force) {
                Write-Warning "replacing $target, which is not an sbx-warden client"
            } elseif ($components -eq 'client') {
                throw "$target exists and is not an sbx-warden client; pass -Force to replace it or -Dir to install elsewhere"
            } else {
                Write-Warning "skipping the client: $target exists and is not an sbx-warden client"
                Write-Warning 'the client is only needed inside a sandbox; install it there, or pass -Force'
                $skipClient = $true
            }
        }

        if (-not $skipClient) {
            $extracted = Get-Archive -Name "sbx-client_${releaseVersion}_windows_${arch}.zip" `
                -Tag $tag -TempDir $tempDir -ChecksumFile $checksumFile
            Install-Binary -SourceDir $extracted -Name 'sbx.exe' -Destination $installDir
            $installedClient = $true

            # A different sbx earlier in PATH wins, so the client would never run.
            $shadowed = Get-Command sbx -ErrorAction SilentlyContinue
            if ($shadowed -and $shadowed.Source -ne $target) {
                Write-Warning "$($shadowed.Source) comes first in PATH, so $target will not be used"
            }
        }
    }

    Add-ToUserPath -Directory $installDir

    Write-Host ''
    if ($installedServer) {
        Write-Host 'Start the server on your host:'
        Write-Host '  sbx-warden --addr 127.0.0.1:7391'
        Write-Host ''
        Write-Host 'Then grant a sandbox and allow the port for it:'
        Write-Host '  sbx-warden grant SANDBOX'
        Write-Host '  sbx policy allow network localhost:7391 --sandbox SANDBOX'
    }
    if ($installedClient) {
        Write-Host ''
        Write-Host 'Point the client at the host from inside a sandbox:'
        Write-Host '  $env:SBX_WARDEN_ADDR = "host.docker.internal:7391"'
        Write-Host ''
        Write-Host 'SBX_WARDEN_TOKEN is set by "sbx-warden grant" on the host; the sandbox'
        Write-Host 'has to be granted before it is created.'
    }
} finally {
    if (Test-Path -LiteralPath $tempDir) {
        Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}
