$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

# 1. Удаляем все старые файлы от предыдущего прогона
Remove-Item 'bugs_report_anon.txt' -ErrorAction SilentlyContinue
Remove-Item '..\tasks\bug_*.md' -ErrorAction SilentlyContinue
Remove-Item '..\tasks\INDEX.md' -ErrorAction SilentlyContinue
Remove-Item '..\tasks\DIAGNOSIS_REPORT.md' -ErrorAction SilentlyContinue

# 2. Запускаем парсер
C:\Python312\python.exe 'parse_log.py'
if ($LASTEXITCODE -ne 0) { throw "Ошибка выполнения parse_log.py" }

# 3. Проверяем наличие свежих файлов
if (-not (Test-Path '..\tasks\INDEX.md')) {
    throw "INDEX.md не был создан!"
}
Write-Host "PARSER_OK: Свежие задачи созданы."
