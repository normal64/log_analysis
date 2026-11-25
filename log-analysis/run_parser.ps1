$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

if (-not (Test-Path 'EventLog.xml')) {
    throw "Не найден файл log-analysis\EventLog.xml! Положите выгрузку ЖР в папку log-analysis."
}
$bslCount = (Get-ChildItem '..\config-dump' -Filter '*.bsl' -Recurse -ErrorAction SilentlyContinue).Count
if ($bslCount -eq 0) {
    Write-Warning "В папке config-dump не найдено .bsl файлов! Анализ по коду будет недоступен."
}

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
