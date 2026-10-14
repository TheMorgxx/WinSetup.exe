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
function Invoke-GitChecked([string[]]$Arguments) {
    $output=@(& git.exe @Arguments)
    if($LASTEXITCODE -ne 0){throw ('Команда git не выполнена: '+($Arguments -join ' '))}
    return $output
}
function Check-Paths([string[]]$Paths) {
    foreach($path in $Paths){
        if($path -match '(^|/)(node_modules|target|gen|release|snapshots|logs|runs)/|(^|/)winsetup\.toml(?:\.|$)|\.(zip|bak|wsvault|pfx|p12|pem|key)$|(^|/)\.env(?:\.|$)') {
            throw "В истории или индексе есть локальный/закрытый файл: $path. Публикация остановлена."
        }
    }
}
try {
    if(-not (Get-Command git -ErrorAction SilentlyContinue)){throw 'Установите Git for Windows и войдите в GitHub через Git Credential Manager.'}
    $remote=(@(Invoke-GitChecked @('remote','get-url','origin')) -join '').Trim()
    if($remote -notmatch '^https://github\.com/TheMorgxx/WinSetup\.exe(?:\.git)?/?$'){throw 'origin должен указывать на https://github.com/TheMorgxx/WinSetup.exe'}
    Invoke-GitChecked @('fetch','origin','main') | Out-Host
    $branch=(@(Invoke-GitChecked @('branch','--show-current')) -join '').Trim()
    if($branch -ne 'main'){throw 'Переключитесь на main перед публикацией. Ветки автоматически не заменяются.'}
    & git.exe rev-parse --verify --quiet HEAD > $null
    if($LASTEXITCODE -ne 0){
        # Восстановить связь с существующим GitHub, не заменяя файлы на диске.
        Invoke-GitChecked @('reset','--mixed','origin/main') | Out-Host
        Invoke-GitChecked @('branch','--set-upstream-to=origin/main','main') | Out-Host
    }
    & git.exe merge-base --is-ancestor origin/main HEAD
    if($LASTEXITCODE -ne 0){throw 'Удалённая main содержит новые коммиты. Сначала согласуйте изменения; force push не используется.'}
    foreach($commit in @(Invoke-GitChecked @('rev-list','origin/main..HEAD'))){Check-Paths @(Invoke-GitChecked @('ls-tree','-r','--name-only',$commit))}
    $allowed=@('.gitignore','README.md','build-ui.cjs','build.bat','publish-files.bat','publish-release.bat','package.json','package-lock.json','tsconfig.json','winsetup.example.toml','ui','dist','src-tauri/src','src-tauri/icons','src-tauri/Cargo.toml','src-tauri/Cargo.lock','src-tauri/app.manifest','src-tauri/build.rs','src-tauri/tauri.conf.json','BOOTSTRAP_PROGRESS.md','bootstrap-report.md')
    $paths=@($allowed | Where-Object {(Test-Path -LiteralPath $_) -or @(& git.exe ls-files -- $_).Count -gt 0})
    # Не включать случайно уже подготовленные пользователем файлы вне списка.
    foreach($staged in @(Invoke-GitChecked @('diff','--cached','--name-only'))){
        if(-not @($allowed|Where-Object {$staged -eq $_ -or $staged.StartsWith($_+'/')}).Count){throw "В индексе есть посторонний файл: $staged. Снимите его со staging перед публикацией."}
    }
    Invoke-GitChecked (@('add','-A','--')+$paths) | Out-Host
    $tracked=@(Invoke-GitChecked @('ls-files'));Check-Paths $tracked
    foreach($path in $tracked){
        if((Test-Path -LiteralPath $path -PathType Leaf) -and (Get-Item -LiteralPath $path).Length -gt 20MB){throw "Слишком большой файл для публикации исходников: $path"}
    }
    # Выводится только имя файла, никогда найденный секрет.
    $secretPatterns=@('ghp_[A-Za-z0-9]{30,}','github_pat_[A-Za-z0-9_]{40,}','sk-proj-[A-Za-z0-9_-]{30,}','-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----')
    foreach($path in $tracked|Where-Object {$_ -match '\.(rs|ts|js|cjs|json|toml|md|bat|txt|yml|yaml)$'}){
        if((Test-Path -LiteralPath $path) -and (Select-String -LiteralPath $path -Pattern $secretPatterns -Quiet)){throw "Обнаружен возможный секрет в $path; отправка остановлена."}
    }
    & git.exe diff --cached --quiet
    if($LASTEXITCODE -eq 1){
        $version=(Get-Content -LiteralPath 'src-tauri/tauri.conf.json' -Raw|ConvertFrom-Json).version
        Invoke-GitChecked @('commit','-m',("Update WinSetup sources to v"+$version)) | Out-Host
    }elseif($LASTEXITCODE -ne 0){throw 'Не удалось проверить подготовленные изменения'}
    Invoke-GitChecked @('push','-u','origin','main') | Out-Host
    $head=(@(Invoke-GitChecked @('rev-parse','HEAD')) -join '').Trim()
    $remoteHead=(@(Invoke-GitChecked @('ls-remote','origin','refs/heads/main')) -join '') -split '\s+'
    if($remoteHead[0] -ne $head){throw 'GitHub не подтвердил отправленный коммит'}
    Write-Host "Готово: https://github.com/TheMorgxx/WinSetup.exe/commit/$head"
    exit 0
}catch{Write-Host ('ОШИБКА: '+$_.Exception.Message) -ForegroundColor Red;exit 1}