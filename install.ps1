# install.ps1 - one-line installer for DontStarveLuaJIT2 (Windows x64).
#
#   irm https://raw.githubusercontent.com/fesily/DontStarveLuaJIT2/master/install.ps1 | iex
#
# Piped runs cannot take parameters - configure through environment variables:
#   $env:DSJ_CHANNEL    = 'auto' | 'release' | 'preview'   (default auto = newest)
#   $env:DSJ_GAME_DIR   = 'D:\Steam\steamapps\common\Don''t Starve Together'
#   $env:DSJ_MOD_FOLDER = 'DontStarveLuaJit2'
#   $env:DSJ_REPO       = 'fesily/DontStarveLuaJIT2'
# When run as a file the same options are available as -Channel/-GameDir/
# -ModFolder/-Repo.
#
# What it does:
#   1. picks a GitHub release (auto = newest of release/preview)
#   2. downloads windows_Mod.zip from that release
#   3. locates the game through Steam (registry SteamPath/InstallPath +
#      libraryfolders.vdf + appmanifest_322330.acf, mirroring tools/steam_env.py)
#   4. stages the package under <game>\mods\<mod-folder>
#   5. runs the packaged install.bat (Winmm shell -> game bin64, real Injector
#      stays in the mod, marker + stale-copy cleanup) and reports the result
#
# Everything runs inside one script block so a piped `iex` does not leak
# variables/functions into the caller's session; `exit` is never used.

$DsjScriptArgs = $args
& {
    param($DsjScriptArgs)

    $ErrorActionPreference = 'Stop'
    try {
        [Net.ServicePointManager]::SecurityProtocol =
            [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    } catch { }

    $Repo       = if ($env:DSJ_REPO)       { $env:DSJ_REPO }       else { 'fesily/DontStarveLuaJIT2' }
    $Channel    = if ($env:DSJ_CHANNEL)    { $env:DSJ_CHANNEL }    else { 'auto' }
    $GameDirEnv = if ($env:DSJ_GAME_DIR)   { $env:DSJ_GAME_DIR }   else { '' }
    $ModFolder  = if ($env:DSJ_MOD_FOLDER) { $env:DSJ_MOD_FOLDER } else { 'DontStarveLuaJit2' }
    $AppId      = '322330'
    $GameName   = "Don't Starve Together"

    function Write-Log($msg) { Write-Host "[install] $msg" }
    function Write-Warn($msg) { Write-Host "[install] WARNING: $msg" -ForegroundColor Yellow }

    # --- tiny argument parser (only when the script runs as a file) ---------
    try {
        if ($DsjScriptArgs -and $DsjScriptArgs.Count -gt 0) {
            for ($i = 0; $i -lt $DsjScriptArgs.Count; $i++) {
                $a = [string]$DsjScriptArgs[$i]
                $v = if ($i + 1 -lt $DsjScriptArgs.Count) { [string]$DsjScriptArgs[$i + 1] } else { $null }
                $inline = $null
                if ($a -match '^-(channel|gamedir|modfolder|repo)=(.*)$') { $a = "-$($Matches[1])"; $inline = $Matches[2] }
                if ($inline) { $v = $inline; $i-- }
                switch -Regex ($a) {
                    '^-(channel)$'  { $Channel = $v; $i++ }
                    '^-(gamedir)$'  { $GameDirEnv = $v; $i++ }
                    '^-(modfolder)$' { $ModFolder = $v; $i++ }
                    '^-(repo)$'     { $Repo = $v; $i++ }
                    default         { throw "unknown argument: $a (use -Channel/-GameDir/-ModFolder/-Repo)" }
                }
            }
        }
        if ($Channel -notin @('auto', 'release', 'preview')) {
            throw "-Channel/`$env:DSJ_CHANNEL must be auto|release|preview (got '$Channel')"
        }
    } catch {
        Write-Host "[install] ERROR: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    function Get-RestJson($uri) {
        Invoke-RestMethod -Uri $uri -Headers @{ 'User-Agent' = 'dsj-install' }
    }

    function Save-WebFile($uri, $outFile) {
        $iwr = @{ Uri = $uri; OutFile = $outFile; Headers = @{ 'User-Agent' = 'dsj-install' } }
        if ($PSVersionTable.PSVersion.Major -lt 6) { $iwr['UseBasicParsing'] = $true }
        Invoke-WebRequest @iwr | Out-Null
    }

    # --- release selection --------------------------------------------------
    function Select-Release($releases, $channel) {
        if (-not $releases -or $releases.Count -eq 0) { throw 'no releases returned by the GitHub API' }
        $sorted = @($releases) | Sort-Object -Property published_at -Descending
        if ($channel -eq 'auto') { return $sorted | Select-Object -First 1 }
        $wantPre = ($channel -eq 'preview')
        $match = $sorted | Where-Object { [bool]$_.prerelease -eq $wantPre } | Select-Object -First 1
        if (-not $match) { throw "no $channel release found" }
        return $match
    }

    # --- Steam game discovery (mirrors tools/steam_env.py) ------------------
    function Get-SteamRoots {
        $roots = New-Object System.Collections.Generic.List[string]
        foreach ($key in @('STEAM_DIR', 'STEAMROOT', 'STEAM_PATH')) {
            $v = [Environment]::GetEnvironmentVariable($key)
            if ($v) { [void]$roots.Add($v) }
        }
        $regLocations = @(
            @('HKCU:\Software\Valve\Steam', 'SteamPath'),
            @('HKLM:\Software\Valve\Steam', 'InstallPath'),
            @('HKLM:\Software\WOW6432Node\Valve\Steam', 'InstallPath')
        )
        foreach ($loc in $regLocations) {
            try {
                $v = (Get-ItemProperty -Path $loc[0] -Name $loc[1] -ErrorAction Stop).($loc[1])
                if ($v) { [void]$roots.Add([string]$v) }
            } catch { }
        }
        foreach ($pf in @("${env:ProgramFiles(x86)}", $env:ProgramFiles)) {
            if ($pf) { [void]$roots.Add((Join-Path $pf 'Steam')) }
        }
        [void]$roots.Add('C:\Steam')
        $seen = @{}
        foreach ($r in $roots) {
            $trimmed = $r.TrimEnd('\')
            $k = $trimmed.ToLowerInvariant()
            if (-not $seen.ContainsKey($k)) { $seen[$k] = $true; $trimmed }
        }
    }

    function Unescape-VdfPath($s) { $s -replace '\\\\', '\' -replace '\\"', '"' }

    function Get-SteamLibraries($root) {
        $libs = New-Object System.Collections.Generic.List[string]
        [void]$libs.Add($root)
        $vdf = Join-Path $root 'steamapps\libraryfolders.vdf'
        if (Test-Path -LiteralPath $vdf) {
            $text = Get-Content -LiteralPath $vdf -Raw
            foreach ($m in [regex]::Matches($text, '"path"\s*"([^"]+)"')) {
                [void]$libs.Add((Unescape-VdfPath $m.Groups[1].Value))
            }
            # older format: "1" "D:\\Games"
            foreach ($m in [regex]::Matches($text, '(?m)^\s*"\d+"\s*"([^"]+)"')) {
                [void]$libs.Add((Unescape-VdfPath $m.Groups[1].Value))
            }
        }
        $seen = @{}
        foreach ($l in $libs) {
            $trimmed = $l.TrimEnd('\')
            $k = $trimmed.ToLowerInvariant()
            if (-not $seen.ContainsKey($k)) { $seen[$k] = $true; $trimmed }
        }
    }

    function Find-GameDir {
        foreach ($root in Get-SteamRoots) {
            if (-not (Test-Path -LiteralPath (Join-Path $root 'steamapps'))) { continue }
            foreach ($lib in Get-SteamLibraries $root) {
                $manifest = Join-Path $lib "steamapps\appmanifest_$AppId.acf"
                if (Test-Path -LiteralPath $manifest) {
                    $text = Get-Content -LiteralPath $manifest -Raw
                    $m = [regex]::Match($text, '"installdir"\s*"([^"]+)"')
                    if ($m.Success) {
                        $cand = Join-Path $lib ("steamapps\common\" + (Unescape-VdfPath $m.Groups[1].Value))
                        if (Test-Path -LiteralPath (Join-Path $cand 'bin64')) { return $cand }
                    }
                }
            }
            $fallback = Join-Path $root "steamapps\common\$GameName"
            if (Test-Path -LiteralPath (Join-Path $fallback 'bin64')) { return $fallback }
        }
        return $null
    }

    # --- install -------------------------------------------------------------
    function Invoke-DsjInstall {
        Write-Log "repository: $Repo   channel: $Channel"

        Write-Log 'resolving the latest release ...'
        $releases = Get-RestJson "https://api.github.com/repos/$Repo/releases?per_page=30"
        $release = Select-Release $releases $Channel
        $asset = $release.assets | Where-Object { $_.name -like 'windows_Mod.zip' } | Select-Object -First 1
        if (-not $asset) {
            $asset = $release.assets | Where-Object { $_.name -like '*windows*_Mod.zip' } | Select-Object -First 1
        }
        if (-not $asset) { throw "release $($release.tag_name) has no windows_Mod.zip asset" }
        Write-Log "selected: $($release.tag_name) ($($asset.name))"

        if ($GameDirEnv) {
            $game = $GameDirEnv.TrimEnd('\')
            Write-Log "game dir (override): $game"
        } else {
            Write-Log 'looking for the game through Steam ...'
            $game = Find-GameDir
            if (-not $game) { throw "Don't Starve Together not found; set `$env:DSJ_GAME_DIR (or -GameDir) to the game root" }
            Write-Log "game dir: $game"
        }
        if (-not (Test-Path -LiteralPath (Join-Path $game 'bin64'))) {
            Write-Warn "$game\bin64 is missing - is this the right game root?"
        }
        $modsDir = Join-Path $game 'mods'
        if (-not (Test-Path -LiteralPath $modsDir)) { throw "$modsDir not found - unexpected game layout" }
        if ($ModFolder -match '[\\/]' -or $ModFolder -eq '..' -or $ModFolder -eq '.') {
            throw "mod folder must be a plain name (got '$ModFolder')"
        }
        $modDir = Join-Path $modsDir $ModFolder
        if ((Test-Path -LiteralPath $modDir) -and -not (Test-Path -LiteralPath (Join-Path $modDir 'modinfo.lua'))) {
            throw "'$modDir' exists but does not look like this mod; remove it or pass -ModFolder"
        }

        $tmp = Join-Path ([IO.Path]::GetTempPath()) ("dsj-install-" + [Guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $tmp -Force | Out-Null
        $zip = Join-Path $tmp $asset.name
        $pkg = Join-Path $tmp 'pkg'
        try {
            Write-Log "downloading $($asset.name) ..."
            Save-WebFile $asset.browser_download_url $zip

            Write-Log 'unpacking ...'
            New-Item -ItemType Directory -Path $pkg -Force | Out-Null
            try {
                Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
                [System.IO.Compression.ZipFile]::ExtractToDirectory($zip, $pkg)
            } catch {
                Expand-Archive -LiteralPath $zip -DestinationPath $pkg -Force
            }

            $src = Join-Path $pkg 'Mod'
            if (-not (Test-Path -LiteralPath (Join-Path $src 'modinfo.lua'))) {
                $manifest = Get-ChildItem -LiteralPath $pkg -Recurse -Depth 2 -Filter 'modinfo.lua' -File | Select-Object -First 1
                if (-not $manifest) { throw "modinfo.lua not found inside $($asset.name)" }
                $src = $manifest.DirectoryName
            }

            Write-Log "staging package -> $modDir"
            if (Test-Path -LiteralPath $modDir) { Remove-Item -LiteralPath $modDir -Recurse -Force }
            New-Item -ItemType Directory -Path $modDir -Force | Out-Null
            Get-ChildItem -LiteralPath $src -Force | Copy-Item -Destination $modDir -Recurse -Force
            if (-not (Test-Path -LiteralPath (Join-Path $modDir 'modmain.lua'))) {
                throw 'staged package is incomplete (modmain.lua missing)'
            }

            Write-Log 'running the packaged installer (deploys the Winmm shell + writes the marker) ...'
            Push-Location $modDir
            try {
                # No 2>&1 here: redirecting native stderr makes PowerShell turn
                # install.bat's `timeout` complaint into a terminating error under
                # $ErrorActionPreference 'Stop'. Leave stderr on the console.
                $prevEap = $ErrorActionPreference
                $ErrorActionPreference = 'Continue'
                try { & cmd.exe /c install.bat } finally { $ErrorActionPreference = $prevEap }
            } finally { Pop-Location }
        } finally {
            Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
        }

        # --- summary (same shape as install_linux.sh's [CHECK]) ---
        $checks = @(
            @{ name = 'shell '; path = (Join-Path $game 'bin64\Winmm.dll') },
            @{ name = 'module'; path = (Join-Path $modDir 'Injector.dll') },
            @{ name = 'marker'; path = (Join-Path $game 'data\unsafedata\ds_luajit_injector.path') }
        )
        $fail = $false
        foreach ($c in $checks) {
            if (Test-Path -LiteralPath $c.path) {
                Write-Log ("CHECK {0}: {1} ({2} bytes)" -f $c.name, $c.path, (Get-Item -LiteralPath $c.path).Length)
            } else {
                Write-Log ("CHECK {0}: {1} MISSING" -f $c.name, $c.path)
                $fail = $true
            }
        }
        $real = Join-Path $modDir 'Injector.dll'
        $marker = Join-Path $game 'data\unsafedata\ds_luajit_injector.path'
        if ((Test-Path -LiteralPath $real) -and (Test-Path -LiteralPath $marker)) {
            $target = (Get-Content -LiteralPath $marker -Raw).Trim()
            if ($target -and -not (Test-Path -LiteralPath $target)) {
                Write-Warn "marker points at '$target', which does not exist"
                $fail = $true
            }
        }

        Write-Log "done: $($release.tag_name) installed in $modDir"
        if ($fail) { Write-Warn 'the self-check found problems above - see the boot log after launching the game' }
        Write-Log "next: enable 'DontStarveLuaJit2' in the in-game mod list; the version label"
        Write-Log '      bottom-right shows a (LuaJIT) suffix once the injector is active.'
        Write-Log "      Boot diagnostics: $game\data\unsafedata\ds_luajit_boot.log"
    }

    try {
        Invoke-DsjInstall
    } catch {
        Write-Host "[install] ERROR: $($_.Exception.Message)" -ForegroundColor Red
    }
} $DsjScriptArgs
