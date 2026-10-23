# install.ps1 - one-line installer for DontStarveLuaJIT2 (Windows x64).
#
#   irm https://raw.githubusercontent.com/fesily/DontStarveLuaJIT2/master/install.ps1 | iex
#
# Piped runs cannot take parameters - configure through environment variables:
#   $env:DSJ_CHANNEL    = 'auto' | 'release' | 'preview'   (default auto = newest)
#   $env:DSJ_GAME_DIR   = 'D:\Steam\steamapps\common\Don''t Starve Together'
#   $env:DSJ_MOD_FOLDER = 'DontStarveLuaJit2'   (only used when the Workshop
#                                              content folder is absent)
#   $env:DSJ_REPO       = 'fesily/DontStarveLuaJIT2'
#   $env:DSJ_ALLOW_KILL = '1'   (force-close a running game without asking;
#                                the piped form cannot answer the prompt)
# When run as a file the same options are available as -Channel/-GameDir/
# -ModFolder/-Repo/-AllowKill.
#
# Messages follow the Windows UI language: Chinese for zh*, English otherwise.
#
# What it does:
#   1. picks a GitHub release (auto = newest of release/preview)
#   2. downloads windows_Mod.zip from that release
#   3. locates the game through Steam (registry SteamPath/InstallPath +
#      libraryfolders.vdf + appmanifest_322330.acf, mirroring tools/steam_env.py)
#   4. stages the package under <steamapps>\workshop\content\322330\3444078585
#      when that library already holds Workshop content for the game, else
#      under <game>\mods\<mod-folder>
#   5. if the client or a dedicated server is still running, asks before
#      force-closing it (the mod DLLs stay mapped otherwise) and aborts the
#      whole install when that is not confirmed
#   6. runs the packaged install.bat (Winmm shell -> game bin64, real Injector
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
    $AllowKill  = ($env:DSJ_ALLOW_KILL -match '(?i)^(1|true|yes|y)$')
    $AppId        = '322330'
    $WorkshopItem = '3444078585'
    $GameName     = "Don't Starve Together"

    # Output language follows the Windows UI language of this session: zh* ->
    # Chinese, anything else -> English. This file stays pure ASCII on purpose:
    # PowerShell 5.1 parses a BOM-less .ps1 as ANSI (which mangles CJK literals)
    # while `irm | iex` breaks on a BOM, so no in-file encoding can carry the
    # Chinese text - it lives in install.zh.json instead and is fetched only for
    # zh*. A failed fetch or an incomplete table keeps the English messages.
    $En = @{
        'prefix.error'      = 'ERROR:'
        'prefix.warn'       = 'WARNING:'
        'arg.unknown'       = 'unknown argument: {0} (use -Channel/-GameDir/-ModFolder/-Repo/-AllowKill)'
        'arg.allowkill'     = '-AllowKill does not take a value (got ''{0}'')'
        'channel.bad'       = '-Channel/$env:DSJ_CHANNEL must be auto|release|preview (got ''{0}'')'
        'repo.line'         = 'repository: {0}   channel: {1}'
        'release.resolve'   = 'resolving the latest release ...'
        'release.none'      = 'no releases returned by the GitHub API'
        'release.nochannel' = 'no {0} release found'
        'release.selected'  = 'selected: {0} ({1})'
        'release.noasset'   = 'release {0} has no windows_Mod.zip asset'
        'game.override'     = 'game dir (override): {0}'
        'game.search'       = 'looking for the game through Steam ...'
        'game.notfound'     = 'Don''t Starve Together not found; set $env:DSJ_GAME_DIR (or -GameDir) to the game root'
        'game.found'        = 'game dir: {0}'
        'game.bin64'        = '{0}\bin64 is missing - is this the right game root?'
        'target.workshop'   = 'target (workshop): {0}'
        'target.local'      = 'target (local mod): {0}'
        'mods.missing'      = '{0} not found - unexpected game layout'
        'modfolder.bad'     = 'mod folder must be a plain name (got ''{0}'')'
        'target.foreign'    = '''{0}'' exists but does not look like this mod; {1}'
        'hint.workshop'     = 'remove it and re-run'
        'hint.local'        = 'remove it or pass -ModFolder'
        'proc.running'      = 'still running: {0}'
        'proc.mapped'       = 'a running game keeps the mod DLLs mapped, so they cannot be replaced'
        'proc.prompt'       = 'force-close those processes and continue? [y/N]'
        'proc.allow'        = '-AllowKill / $env:DSJ_ALLOW_KILL given - force-closing without asking'
        'proc.killing'      = 'killing {0} (pid {1}) ...'
        'proc.killfail'     = 'cannot kill pid {0}: {1}'
        'proc.left'         = 'still running after the kill: {0}'
        'proc.aborted'      = 'aborted: the game was left running (force-close not confirmed)'
        'download'          = 'downloading {0} ...'
        'unpack'            = 'unpacking ...'
        'staging'           = 'staging package -> {0}'
        'modinfo.missing'   = 'modinfo.lua not found inside {0}'
        'staged.incomplete' = 'staged package is incomplete (modmain.lua missing)'
        'run.bat'           = 'running the packaged installer (deploys the Winmm shell; the marker is written by the shell at boot) ...'
        'check.ok'          = 'CHECK {0}: {1} ({2} bytes)'
        'check.missing'     = 'CHECK {0}: {1} MISSING'
        'marker.dangling'   = 'marker points at ''{0}'', which does not exist'
        'done'              = 'done: {0} installed in {1}'
        'selfcheck'         = 'the self-check found problems above - see the boot log after launching the game'
        'next.enable'       = 'next: enable {0} in the in-game mod list; the version label'
        'next.suffix'       = '      bottom-right shows a (LuaJIT) suffix once the injector is active.'
        'next.bootlog'      = '      Boot diagnostics: {0}'
        'name.workshop'     = 'the Workshop item'
    }

    $Lang = 'en'
    try {
        if ([System.Globalization.CultureInfo]::CurrentUICulture.TwoLetterISOLanguageName -eq 'zh') { $Lang = 'zh' }
    } catch { }
    $Messages = $En
    if ($Lang -eq 'zh') {
        try {
            $zh = Invoke-RestMethod -Uri "https://raw.githubusercontent.com/$Repo/master/install.zh.json" `
                -Headers @{ 'User-Agent' = 'dsj-install' }
            $table = @{}
            foreach ($p in $zh.PSObject.Properties) { $table[$p.Name] = [string]$p.Value }
            # Accept the translation only when it covers every English key.
            if (@($En.Keys | Where-Object { -not $table.ContainsKey($_) }).Count -eq 0) { $Messages = $table }
        } catch { }
    }

    function Msg($key, $fmt = $null) {
        $text = if ($Messages.ContainsKey($key)) { $Messages[$key] } else { $key }
        if ($null -eq $fmt) { return $text }
        return ($text -f $fmt)
    }

    function Write-Log($msg) { Write-Host "[install] $msg" }
    function Write-Warn($msg) { Write-Host "[install] $(Msg 'prefix.warn') $msg" -ForegroundColor Yellow }
    function Write-Err($msg) { Write-Host "[install] $(Msg 'prefix.error') $msg" -ForegroundColor Red }

    # --- tiny argument parser (only when the script runs as a file) ---------
    try {
        if ($DsjScriptArgs -and $DsjScriptArgs.Count -gt 0) {
            for ($i = 0; $i -lt $DsjScriptArgs.Count; $i++) {
                $a = [string]$DsjScriptArgs[$i]
                if ($a -match '^-allowkill(=(.*))?$') {
                    if ($Matches[2] -and $Matches[2] -notmatch '(?i)^(1|true|yes|y)$') {
                        throw (Msg 'arg.allowkill' $a)
                    }
                    $AllowKill = $true
                    continue
                }
                $v = if ($i + 1 -lt $DsjScriptArgs.Count) { [string]$DsjScriptArgs[$i + 1] } else { $null }
                $inline = $null
                if ($a -match '^-(channel|gamedir|modfolder|repo)=(.*)$') { $a = "-$($Matches[1])"; $inline = $Matches[2] }
                if ($inline) { $v = $inline; $i-- }
                switch -Regex ($a) {
                    '^-(channel)$'  { $Channel = $v; $i++ }
                    '^-(gamedir)$'  { $GameDirEnv = $v; $i++ }
                    '^-(modfolder)$' { $ModFolder = $v; $i++ }
                    '^-(repo)$'     { $Repo = $v; $i++ }
                    default         { throw (Msg 'arg.unknown' $a) }
                }
            }
        }
        if ($Channel -notin @('auto', 'release', 'preview')) {
            throw (Msg 'channel.bad' $Channel)
        }
    } catch {
        Write-Err $_.Exception.Message
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
        if (-not $releases -or $releases.Count -eq 0) { throw (Msg 'release.none') }
        $sorted = @($releases) | Sort-Object -Property published_at -Descending
        if ($channel -eq 'auto') { return $sorted | Select-Object -First 1 }
        $wantPre = ($channel -eq 'preview')
        $match = $sorted | Where-Object { [bool]$_.prerelease -eq $wantPre } | Select-Object -First 1
        if (-not $match) { throw (Msg 'release.nochannel' $channel) }
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

    # Steam keeps Workshop content per library: <library>\steamapps\workshop\
    # content\<appid>\<item> - the base the injector derives from the exe
    # (exe/../../.. + workshop/content/322330). <game> is
    # <library>\steamapps\common\<installdir>, so steamapps sits two levels up.
    # Returns $null when this library has no Workshop content for the game.
    function Find-WorkshopItemDir($game) {
        $steamapps = Split-Path -Parent (Split-Path -Parent $game)
        if (-not $steamapps) { return $null }
        $content = Join-Path $steamapps "workshop\content\$AppId"
        if (-not (Test-Path -LiteralPath $content)) { return $null }
        return (Join-Path $content $WorkshopItem)
    }

    # --- running-game consent gate -------------------------------------------
    # Staging below deletes and replaces $modDir, whose DLLs a running client /
    # dedicated server keeps mapped, so those processes have to go first. Same
    # image-name list install.bat force-kills. Killing is never implicit:
    # without a typed "y" the install aborts before anything is touched.
    $GameProcessNames = @(
        'dontstarve_steam_x64',
        'dontstarve_dedicated_server_nullrenderer_x64'
    )

    function Get-RunningGameProcess {
        @($GameProcessNames | ForEach-Object { Get-Process -Name $_ -ErrorAction SilentlyContinue })
    }

    function Assert-NoRunningGame {
        $running = Get-RunningGameProcess
        if (-not $running) { return }
        $list = ($running | ForEach-Object { "$($_.ProcessName) (pid $($_.Id))" }) -join ', '
        Write-Warn (Msg 'proc.running' $list)
        Write-Warn (Msg 'proc.mapped')
        $confirmed = $false
        if ($AllowKill) {
            $confirmed = $true
            Write-Log (Msg 'proc.allow')
        } else {
            $answer = $null
            try { $answer = Read-Host "[install] $(Msg 'proc.prompt')" } catch { $answer = $null }
            $confirmed = ("$answer".Trim() -match '(?i)^y(es)?$')
        }
        if (-not $confirmed) { throw (Msg 'proc.aborted') }
        foreach ($p in $running) {
            Write-Log (Msg 'proc.killing' $p.ProcessName, $p.Id)
            try { Stop-Process -Id $p.Id -Force -ErrorAction Stop }
            catch { Write-Warn (Msg 'proc.killfail' $p.Id, $_.Exception.Message) }
        }
        for ($i = 0; $i -lt 40 -and (Get-RunningGameProcess).Count -gt 0; $i++) { Start-Sleep -Milliseconds 250 }
        $left = Get-RunningGameProcess
        if ($left) {
            throw (Msg 'proc.left' (($left | ForEach-Object { $_.ProcessName }) -join ', '))
        }
    }

    # --- install -------------------------------------------------------------
    function Invoke-DsjInstall {
        Write-Log (Msg 'repo.line' $Repo, $Channel)

        Write-Log (Msg 'release.resolve')
        $releases = Get-RestJson "https://api.github.com/repos/$Repo/releases?per_page=30"
        $release = Select-Release $releases $Channel
        $asset = $release.assets | Where-Object { $_.name -like 'windows_Mod.zip' } | Select-Object -First 1
        if (-not $asset) {
            $asset = $release.assets | Where-Object { $_.name -like '*windows*_Mod.zip' } | Select-Object -First 1
        }
        if (-not $asset) { throw (Msg 'release.noasset' $release.tag_name) }
        Write-Log (Msg 'release.selected' $release.tag_name, $asset.name)

        if ($GameDirEnv) {
            $game = $GameDirEnv.TrimEnd('\')
            Write-Log (Msg 'game.override' $game)
        } else {
            Write-Log (Msg 'game.search')
            $game = Find-GameDir
            if (-not $game) { throw (Msg 'game.notfound') }
            Write-Log (Msg 'game.found' $game)
        }
        if (-not (Test-Path -LiteralPath (Join-Path $game 'bin64'))) {
            Write-Warn (Msg 'game.bin64' $game)
        }
        # Workshop first: when the game's library holds Workshop content, the
        # item folder is what the game actually loads for subscribers, and
        # install.bat's "workshop\content\322330" branch resolves the shell
        # destination from that same library. Falling back to
        # <game>\mods\<folder> only for non-Steam / Workshop-less libraries.
        $modDir = Find-WorkshopItemDir $game
        if ($modDir) {
            $modName = Msg 'name.workshop'
            $hint = Msg 'hint.workshop'
            Write-Log (Msg 'target.workshop' $modDir)
        } else {
            $modsDir = Join-Path $game 'mods'
            if (-not (Test-Path -LiteralPath $modsDir)) { throw (Msg 'mods.missing' $modsDir) }
            if ($ModFolder -match '[\\/]' -or $ModFolder -eq '..' -or $ModFolder -eq '.') {
                throw (Msg 'modfolder.bad' $ModFolder)
            }
            $modDir = Join-Path $modsDir $ModFolder
            $modName = "'$ModFolder'"
            $hint = Msg 'hint.local'
            Write-Log (Msg 'target.local' $modDir)
        }
        if ((Test-Path -LiteralPath $modDir) -and -not (Test-Path -LiteralPath (Join-Path $modDir 'modinfo.lua'))) {
            throw (Msg 'target.foreign' $modDir, $hint)
        }

        # Nothing above this line changed the disk; ask before the first write.
        Assert-NoRunningGame

        $tmp = Join-Path ([IO.Path]::GetTempPath()) ("dsj-install-" + [Guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $tmp -Force | Out-Null
        $zip = Join-Path $tmp $asset.name
        $pkg = Join-Path $tmp 'pkg'
        try {
            Write-Log (Msg 'download' $asset.name)
            Save-WebFile $asset.browser_download_url $zip

            Write-Log (Msg 'unpack')
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
                if (-not $manifest) { throw (Msg 'modinfo.missing' $asset.name) }
                $src = $manifest.DirectoryName
            }

            Write-Log (Msg 'staging' $modDir)
            if (Test-Path -LiteralPath $modDir) { Remove-Item -LiteralPath $modDir -Recurse -Force }
            New-Item -ItemType Directory -Path $modDir -Force | Out-Null
            Get-ChildItem -LiteralPath $src -Force | Copy-Item -Destination $modDir -Recurse -Force
            if (-not (Test-Path -LiteralPath (Join-Path $modDir 'modmain.lua'))) {
                throw (Msg 'staged.incomplete')
            }

            Write-Log (Msg 'run.bat')
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
                Write-Log (Msg 'check.ok' $c.name, $c.path, (Get-Item -LiteralPath $c.path).Length)
            } else {
                Write-Log (Msg 'check.missing' $c.name, $c.path)
                $fail = $true
            }
        }
        $real = Join-Path $modDir 'Injector.dll'
        $marker = Join-Path $game 'data\unsafedata\ds_luajit_injector.path'
        if ((Test-Path -LiteralPath $real) -and (Test-Path -LiteralPath $marker)) {
            $target = (Get-Content -LiteralPath $marker -Raw).Trim()
            if ($target -and -not (Test-Path -LiteralPath $target)) {
                Write-Warn (Msg 'marker.dangling' $target)
                $fail = $true
            }
        }

        Write-Log (Msg 'done' $release.tag_name, $modDir)
        if ($fail) { Write-Warn (Msg 'selfcheck') }
        Write-Log (Msg 'next.enable' $modName)
        Write-Log (Msg 'next.suffix')
        Write-Log (Msg 'next.bootlog' (Join-Path $game 'data\unsafedata\ds_luajit_boot.log'))
    }

    try {
        Invoke-DsjInstall
    } catch {
        Write-Err $_.Exception.Message
    }
} $DsjScriptArgs
