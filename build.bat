@echo off
setlocal EnableExtensions
chcp 65001 >nul
cd /d "%~dp0"

echo ==========================================
echo   WinSetup - автоматическая сборка
echo ==========================================
echo.

rem ---------- 1. Проверка инструментов ----------
where node >nul 2>nul
if errorlevel 1 (
    echo [ОШИБКА] Node.js не найден. Установи: https://nodejs.org
    goto :fail
)
where npm >nul 2>nul
if errorlevel 1 (
    echo [ОШИБКА] npm не найден. Переустанови Node.js.
    goto :fail
)
where cargo >nul 2>nul
if errorlevel 1 (
    echo [ОШИБКА] Rust ^(cargo^) не найден. Установи: https://rustup.rs
    echo          Нужна MSVC-цепочка: rustup default stable-x86_64-pc-windows-msvc
    echo          и Visual Studio Build Tools с "Разработка классических приложений на C++".
    goto :fail
)

rem ---------- 2. Зависимости фронтенда ----------
if not exist "node_modules\typescript\" (
    echo [1/4] Установка npm-зависимостей...
    call npm install
    if errorlevel 1 goto :fail
) else (
    echo [1/4] npm-зависимости уже установлены.
)

rem ---------- 3. Сборка UI (tsc + копирование в dist) ----------
echo.
echo [2/4] Сборка UI ^(TypeScript -^> dist^)...
if not exist "dist\" mkdir dist
call npm run build
if errorlevel 1 goto :fail

rem ---------- 4. Сборка Rust-приложения ----------
echo.
echo [3/4] Сборка Rust ^(cargo build --release^)... это может занять несколько минут.
pushd src-tauri
cargo build --release --bin winsetup
set "CARGO_RC=%errorlevel%"
popd
if not "%CARGO_RC%"=="0" goto :fail

rem ---------- 5. Выкладка результата ----------
echo.
echo [4/4] Копирование результата в папку release...
if not exist "release\" mkdir release
copy /y "src-tauri\target\release\winsetup.exe" "release\WinSetup.exe" >nul
if errorlevel 1 (
    echo [ОШИБКА] Не удалось скопировать winsetup.exe ^(возможно, он запущен^).
    goto :fail
)
rem Конфиг не перезаписываем, чтобы не потерять твои правки
if not exist "release\winsetup.toml" (
    if exist "winsetup.toml" (
        copy /y "winsetup.toml" "release\winsetup.toml" >nul
    ) else if exist "winsetup.example.toml" (
        copy /y "winsetup.example.toml" "release\winsetup.toml" >nul
    )
)

echo.
echo ==========================================
echo   ГОТОВО: %~dp0release\WinSetup.exe
echo ==========================================
if /i not "%~1"=="nopause" pause
exit /b 0

:fail
echo.
echo ==========================================
echo   СБОРКА НЕ УДАЛАСЬ - смотри ошибки выше
echo ==========================================
if /i not "%~1"=="nopause" pause
exit /b 1