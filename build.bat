@echo off
setlocal
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
  echo [1/4] Creating virtual environment...
  python -m venv .venv || goto :error
)

echo [2/4] Installing pinned build dependencies...
".venv\Scripts\python.exe" -m pip install --upgrade pip || goto :error
".venv\Scripts\python.exe" -m pip install -r requirements-dev.txt || goto :error

echo [3/4] Building dist\EgressScope.exe...
if exist "dist" rmdir /s /q "dist"
".venv\Scripts\pyinstaller.exe" build.spec --noconfirm --clean || goto :error

echo [4/4] Writing dist\SHA256SUMS.txt...
for /f "tokens=*" %%H in ('powershell -NoProfile -Command "(Get-FileHash -Algorithm SHA256 'dist\EgressScope.exe').Hash.ToLower()"') do set "EXE_HASH=%%H"
if not defined EXE_HASH goto :error
> "dist\SHA256SUMS.txt" echo %EXE_HASH% *dist/EgressScope.exe

echo.
echo Build complete: %CD%\dist\EgressScope.exe
echo Checksum: dist\SHA256SUMS.txt
exit /b 0

:error
echo.
echo Build failed. See the output above.
exit /b 1
