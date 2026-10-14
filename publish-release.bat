@echo off
setlocal EnableExtensions
chcp 65001 >nul
set "WINSETUP_PUBLISH_SCRIPT=%~f0"
powershell.exe -NoProfile -Command "$source=[IO.File]::ReadAllText($env:WINSETUP_PUBLISH_SCRIPT); & ([scriptblock]::Create(($source -split '(?m)^# POWERSHELL\r?$',2)[1]))"
set "PUBLISH_EXIT=%ERRORLEVEL%"
if /i not "%~1"=="nopause" pause
exit /b %PUBLISH_EXIT%
# POWERSHELL
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetDirectoryName($env:WINSETUP_PUBLISH_SCRIPT)
Set-Location -LiteralPath $root
$OutputEncoding=[Text.UTF8Encoding]::new($false)
[Console]::InputEncoding=[Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$headers=@{};$credential=@{};$lines=$null
function Github([string]$Method,[string]$Uri,[object]$Body=$null) {
    try {
        if($null -eq $Body){return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers -TimeoutSec 60}
        $json=ConvertTo-Json -InputObject $Body -Depth 8
        return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers -ContentType 'application/json; charset=utf-8' -Body ([Text.Encoding]::UTF8.GetBytes($json)) -TimeoutSec 60
    }catch{throw ('GitHub API: HTTP '+[int]$_.Exception.Response.StatusCode+'; проверьте права доступа и состояние репозитория.')}
}
function Save-Json([string]$Path,[object]$Value){[IO.File]::WriteAllText((Join-Path $root $Path),((ConvertTo-Json -InputObject $Value -Depth 30)+"`n"),[Text.UTF8Encoding]::new($false))}
try {
    foreach($tool in @('git','cargo','npm.cmd')){if(-not (Get-Command $tool -ErrorAction SilentlyContinue)){throw "Не найден $tool. Установите инструменты сборки из README."}}
    $version=(Get-Content -LiteralPath 'src-tauri/tauri.conf.json' -Raw|ConvertFrom-Json).version
    if($version -notmatch '^\d+\.\d+\.\d+$'){throw 'Задайте версию X.Y.Z в src-tauri/tauri.conf.json'}
    $tag='v'+$version
    $env:GIT_TERMINAL_PROMPT='0';$env:GCM_INTERACTIVE='Never'
    $credentialStart=[Diagnostics.ProcessStartInfo]::new()
    $credentialStart.FileName=(Get-Command git.exe).Source
    $credentialStart.Arguments='credential fill'
    $credentialStart.UseShellExecute=$false;$credentialStart.CreateNoWindow=$true
    $credentialStart.RedirectStandardInput=$true;$credentialStart.RedirectStandardOutput=$true
    $credentialProcess=[Diagnostics.Process]::new();$credentialProcess.StartInfo=$credentialStart
    try {
        [void]$credentialProcess.Start()
        $credentialProcess.StandardInput.Write('protocol=https'+[char]10+'host=github.com'+[char]10+[char]10)
        $credentialProcess.StandardInput.Close()
        $lines=$credentialProcess.StandardOutput.ReadToEnd() -split '\r?\n'
        $credentialProcess.WaitForExit()
        if($credentialProcess.ExitCode -ne 0){throw 'Нет авторизации GitHub. Выполните git push и войдите через Git Credential Manager.'}
    }finally{$credentialProcess.Dispose()}
    foreach($line in $lines){if($line -match '^([^=]+)=(.*)$'){$credential[$matches[1]]=$matches[2]}}
    if(-not $credential.password){throw 'Git Credential Manager не вернул авторизацию GitHub'}
    $headers=@{Authorization=('Bearer '+$credential.password);Accept='application/vnd.github+json';'X-GitHub-Api-Version'='2022-11-28';'User-Agent'='WinSetup-Publisher'}
    $base='https://api.github.com/repos/TheMorgxx/WinSetup.exe'
    $existing=$null
    try {$existing=Invoke-RestMethod -Uri ($base+'/releases/tags/'+$tag) -Headers $headers -TimeoutSec 60}
    catch {if([int]$_.Exception.Response.StatusCode -ne 404){throw ('Не удалось проверить релиз: HTTP '+[int]$_.Exception.Response.StatusCode)}}
    if($existing -and -not $existing.draft){
        $head=(& git rev-parse --verify --quiet HEAD)
        if($LASTEXITCODE -eq 0 -and $existing.target_commitish -eq $head -and -not @(& git status --porcelain).Count -and @($existing.assets|Where-Object {$_.name -eq 'WinSetup.exe' -and $_.state -eq 'uploaded'}).Count -eq 1){
            Write-Host ('Эта версия уже опубликована: '+$existing.html_url);exit 0
        }
        throw "Релиз $tag уже опубликован. Для новой сборки увеличьте version в src-tauri/tauri.conf.json; опубликованные EXE не перезаписываются."
    }
    # tauri.conf.json — единственное место, где пользователь задаёт новую версию.
    $cargoPath=Join-Path $root 'src-tauri/Cargo.toml';$cargoText=[IO.File]::ReadAllText($cargoPath)
    $pattern='(?s)(\[package\].*?\bversion\s*=\s*")[^"]+("[\r\n])'
    if(-not [regex]::IsMatch($cargoText,$pattern)){throw 'Не найдена версия package в Cargo.toml'}
    $cargoText=([regex]$pattern).Replace($cargoText,{param($m)$m.Groups[1].Value+$version+$m.Groups[2].Value},1)
    [IO.File]::WriteAllText($cargoPath,$cargoText,[Text.UTF8Encoding]::new($false))
    # Windows PowerShell 5.1 не читает JSON с пустым ключом packages[""] через ConvertFrom-Json.
    # Меняем только версии корневого пакета, сохраняя версии зависимостей.
    foreach($jsonPath in @('package.json','package-lock.json')){
        $full=Join-Path $root $jsonPath;$jsonText=[IO.File]::ReadAllText($full)
        $versionPattern=[regex]'("name"\s*:\s*"winsetup-ui"\s*,\s*"version"\s*:\s*")[^"]+(")'
        $expected=if($jsonPath -eq 'package-lock.json'){2}else{1}
        if($versionPattern.Matches($jsonText).Count -ne $expected){throw "Не найдены версии корневого пакета в $jsonPath"}
        $jsonText=$versionPattern.Replace($jsonText,{param($m)$m.Groups[1].Value+$version+$m.Groups[2].Value})
        [IO.File]::WriteAllText($full,$jsonText,[Text.UTF8Encoding]::new($false))
    }
    & npm.cmd run test:ui;if($LASTEXITCODE -ne 0){throw 'Тесты интерфейса не прошли'}
    & npm.cmd run build;if($LASTEXITCODE -ne 0){throw 'Сборка интерфейса не прошла'}
    & cargo check --manifest-path src-tauri/Cargo.toml;if($LASTEXITCODE -ne 0){throw 'cargo check не прошёл'}
    & cargo test --lib --manifest-path src-tauri/Cargo.toml;if($LASTEXITCODE -ne 0){throw 'Unit-тесты не прошли'}
    & cargo build --release --bin winsetup --manifest-path src-tauri/Cargo.toml;if($LASTEXITCODE -ne 0){throw 'Сборка EXE не прошла'}
    $exe=Join-Path $root 'src-tauri/target/release/winsetup.exe'
    $binary=Get-Item -LiteralPath $exe
    $hasher=[Security.Cryptography.SHA256]::Create();$stream=[IO.File]::OpenRead($exe)
    try {$sha=[BitConverter]::ToString($hasher.ComputeHash($stream)).Replace('-','').ToLowerInvariant()}
    finally {$stream.Dispose();$hasher.Dispose()}
    if($binary.Length -eq 0){throw 'Собран пустой EXE'}
    $destination=Join-Path $root 'release';[void][IO.Directory]::CreateDirectory($destination)
    Copy-Item -LiteralPath $exe -Destination (Join-Path $destination 'WinSetup.exe') -Force
    # Этот вызов публикует только исходники из разрешённого списка. Приложение не запускается.
    & (Join-Path $root 'publish-files.bat') nopause
    if($LASTEXITCODE -ne 0){throw 'Исходники не опубликованы; релиз не создаётся'}
    $commit=(& git rev-parse HEAD).Trim();if($LASTEXITCODE -ne 0){throw 'Не определён коммит сборки'}
    $remoteTags=@(& git ls-remote origin "refs/tags/$tag" "refs/tags/$tag^{}")
    if($LASTEXITCODE -ne 0){throw 'Не удалось проверить тег релиза'}
    $tagTarget=$null
    foreach($entry in $remoteTags){$parts=$entry -split '\s+';if(-not $tagTarget -or $parts[1].EndsWith('^{}')){$tagTarget=$parts[0]}}
    if($tagTarget -and $tagTarget -ne $commit){throw 'Тег этой версии уже относится к другому коммиту. Увеличьте версию.'}
    if($existing -and $existing.target_commitish -ne $commit){throw 'Черновик этого тега относится к другому коммиту. Используйте новую версию.'}
    $body="Готовая сборка WinSetup $version для Windows x64.`n`nСкачайте WinSetup.exe из Assets и поместите в отдельную папку. Отсутствующий winsetup.toml создаётся автоматически. Подготовка среды проверяет winget и предлагает установку официальных пакетов Microsoft только после подтверждения.`n`nИсходники: $commit`nSHA-256 WinSetup.exe: $sha`n`nСборка и unit-тесты пройдены. Приложение, скачивание пакетов и установка winget при публикации не запускались. Подробности: bootstrap-report.md и reliability-report.md в исходниках."
    if($existing){$release=$existing}else{$release=Github 'Post' ($base+'/releases') @{tag_name=$tag;target_commitish=$commit;name=('WinSetup '+$version);body=$body;draft=$true;prerelease=$false}}
    Write-Host ('Черновик релиза: '+$release.id)
    $asset=@($release.assets|Where-Object {$_.name -eq 'WinSetup.exe'})
    if($asset.Count -gt 0){
        if($asset.Count -ne 1 -or $asset[0].size -ne $binary.Length -or $asset[0].digest -ne ('sha256:'+$sha)){throw 'В черновике уже есть другой EXE. Он не заменён; создайте новую версию.'}
    }else{
        $upload=$release.upload_url.Split('{')[0]+'?name=WinSetup.exe'
        if(([Uri]$upload).Host -ne 'uploads.github.com'){throw 'Неожиданный адрес загрузки GitHub'}
        try {$asset=@(Invoke-RestMethod -Method Post -Uri $upload -Headers $headers -ContentType 'application/octet-stream' -InFile $exe -TimeoutSec 180)}
        catch {throw ('Не удалось загрузить EXE: HTTP '+[int]$_.Exception.Response.StatusCode+'. Черновик сохранён; повторите батку.')}
        if($asset[0].size -ne $binary.Length -or $asset[0].state -ne 'uploaded' -or $asset[0].digest -ne ('sha256:'+$sha)){throw 'GitHub не подтвердил размер и SHA-256 EXE; релиз оставлен черновиком'}
    }
    $published=Github 'Patch' $release.url @{draft=$false;make_latest='true';body=$body}
    $verified=Github 'Get' ($base+'/releases/tags/'+$tag)
    $asset=@($verified.assets|Where-Object {$_.name -eq 'WinSetup.exe'})
    if($verified.draft -or $asset.Count -ne 1 -or $asset[0].digest -ne ('sha256:'+$sha)){throw 'Проверка опубликованного релиза не пройдена'}
    Write-Host ('Готово: '+$verified.html_url)
    Write-Host ('Скачать EXE: '+$asset[0].browser_download_url)
    Write-Host ('SHA-256: '+$sha)
    exit 0
}catch{Write-Host ('ОШИБКА: '+$_.Exception.Message) -ForegroundColor Red;exit 1}
finally{$headers.Clear();$credential.Clear();$lines=$null}