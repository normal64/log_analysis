import os
import re
import glob
import json
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FILE_PATH = os.path.join(BASE_DIR, 'EventLog.xml')
REPORT_PATH = os.path.join(BASE_DIR, 'bugs_report_anon.txt')
KNOWN_BUGS_PATH = os.path.join(BASE_DIR, 'known_bugs.json')
CONFIG_DUMP_REL = os.path.normpath(os.path.join(BASE_DIR, '..', 'config-dump'))
TASKS_DIR = os.path.normpath(os.path.join(BASE_DIR, '..', 'tasks'))

INVALID_XML_CHARS = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]')
SINGLE_LINE_USER_MSG = re.compile(r'^\{[^}]+\}:\s*.+$')
STACK_LINE_RE = re.compile(r'^\{([^}]+)\((\d+)\)\}:(.*)$')

UUID_RE = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.IGNORECASE)
QUOTED_RE = re.compile(r'["\'][^"\']+["\']')
DOC_NUM_RE = re.compile(r'\b[А-ЯЁA-Z0-9]{1,5}[-/]\d+[-/0-9]*\b', re.IGNORECASE)

SYSTEM_USERS = {'администратор', 'система / фоновое', 'система', ''}

METADATA_DIRS = {
    'ОбщийМодуль': 'CommonModules',
    'Документ': 'Documents',
    'Справочник': 'Catalogs',
    'Обработка': 'DataProcessors',
    'Отчет': 'Reports',
    'РегистрСведений': 'InformationRegisters',
    'РегистрНакопления': 'AccumulationRegisters',
    'РегистрБухгалтерии': 'AccountingRegisters',
    'РегистрРасчета': 'CalculationRegisters',
    'ПланВидовХарактеристик': 'ChartsOfCharacteristicTypes',
    'ПланСчетов': 'ChartsOfAccounts',
    'ПланВидовРасчета': 'ChartsOfCalculationTypes',
    'ПланОбмена': 'ExchangePlans',
    'БизнесПроцесс': 'BusinessProcesses',
    'Задача': 'Tasks',
    'ЖурналДокументов': 'DocumentJournals',
    'Константа': 'Constants',
    'ОбщаяФорма': 'CommonForms',
    'ОбщаяКоманда': 'CommonCommands',
    'HTTPСервис': 'HTTPServices',
    'WebСервис': 'WebServices',
    'РегламентноеЗадание': 'ScheduledJobs',
}


def strip_ns(tag):
    return tag.split('}', 1)[-1] if '}' in tag else tag


def mask_word(word):
    if len(word) <= 2:
        return word + '*' if len(word) == 2 else word
    return word[:2] + '***'


def mask_full_name(full_name):
    if not full_name or full_name.strip().lower() in SYSTEM_USERS:
        return full_name or 'Система / Фоновое'
    parts = re.sub(r'([а-яё])([А-ЯЁ])', r'\1 \2', full_name.strip()).split()
    return " ".join(mask_word(p) for p in parts)


def build_anonymizer(root):
    raw_names = set()
    for elem in root.iter():
        if strip_ns(elem.tag) == 'UserName' and elem.text:
            name = elem.text.strip()
            if name.lower() not in SYSTEM_USERS:
                raw_names.add(name)

    replacements = {}
    for name in raw_names:
        replacements[name] = mask_full_name(name)
        parts = re.sub(r'([а-яё])([А-ЯЁ])', r'\1 \2', name).split()
        if parts and len(parts[0]) > 3:
            replacements[parts[0]] = mask_word(parts[0])

    sorted_keys = sorted(replacements.keys(), key=len, reverse=True)
    pattern = re.compile('|'.join(re.escape(k) for k in sorted_keys), re.IGNORECASE) if sorted_keys else None

    def anonymize_text(text):
        if not text or not pattern:
            return text
        return pattern.sub(lambda m: replacements.get(m.group(0), mask_word(m.group(0))), text)

    return anonymize_text


def make_signature(lines):
    """Единый ключ схлопывания для INDEX.md, bugs_report_anon.txt и known_bugs.json."""
    first_line = lines[0] if lines else 'Без текста'
    module_line = next((l for l in lines if l.startswith('{')), '')

    if ':' in first_line and not first_line.startswith('{'):
        prefix, rest = first_line.split(':', 1)
        if len(prefix) >= 12 and rest.strip():
            first_line = prefix

    norm = re.sub(
        r'(менеджер объекта|объекта|реквизит|поля|свойства)\s+[А-ЯЁA-Z0-9_]+',
        r'\1 <OBJ>',
        first_line,
        flags=re.IGNORECASE,
    )
    norm = re.sub(r'\([^)]+\)', '(<VAL>)', norm)
    norm = UUID_RE.sub('<UUID>', norm)
    norm = QUOTED_RE.sub('"<STR>"', norm)
    norm = DOC_NUM_RE.sub('<NUM>', norm)
    norm = re.sub(r'\d+', 'N', norm)
    norm = re.sub(r'идентификатор\w*', 'идентификатор<X>', norm, flags=re.IGNORECASE)

    return f"{module_line}\n{norm}".strip() if module_line else norm.strip()


def resolve_1c_path(stack_location):
    parts = stack_location.split('.')
    if len(parts) < 2:
        return None

    meta_type = parts[0]
    base_folder = METADATA_DIRS.get(meta_type)
    if not base_folder:
        return None

    obj_name = parts[1]
    rel_path = None

    if meta_type == 'ОбщийМодуль':
        rel_path = f"{base_folder}/{obj_name}/Ext/Module.bsl"
    elif meta_type == 'ОбщаяФорма':
        rel_path = f"{base_folder}/{obj_name}/Ext/Form/Module.bsl"
    elif meta_type == 'ОбщаяКоманда':
        rel_path = f"{base_folder}/{obj_name}/Ext/CommandModule.bsl"
    elif len(parts) >= 3:
        sub_type = parts[2]
        if sub_type == 'МодульОбъекта':
            rel_path = f"{base_folder}/{obj_name}/Ext/ObjectModule.bsl"
        elif sub_type == 'МодульМенеджера':
            rel_path = f"{base_folder}/{obj_name}/Ext/ManagerModule.bsl"
        elif sub_type == 'МодульНабораЗаписей':
            rel_path = f"{base_folder}/{obj_name}/Ext/RecordSetModule.bsl"
        elif sub_type == 'Форма' and len(parts) >= 4:
            form_name = parts[3]
            rel_path = f"{base_folder}/{obj_name}/Forms/{form_name}/Ext/Form/Module.bsl"
        elif sub_type == 'Команда' and len(parts) >= 4:
            cmd_name = parts[3]
            rel_path = f"{base_folder}/{obj_name}/Commands/{cmd_name}/Ext/CommandModule.bsl"
        elif sub_type == 'Модуль':
            rel_path = f"{base_folder}/{obj_name}/Ext/Module.bsl"

    if not rel_path:
        return None

    full_check_path = os.path.normpath(os.path.join(CONFIG_DUMP_REL, rel_path))
    exists = os.path.exists(full_check_path)
    return f"config-dump/{rel_path}", exists


def extract_stack_targets(lines):
    targets = []
    seen = set()
    for line in lines:
        m = STACK_LINE_RE.match(line)
        if m:
            loc, line_num, code_snippet = m.group(1), m.group(2), m.group(3).strip()
            resolved = resolve_1c_path(loc)
            if resolved:
                bsl_path, exists = resolved
                key = (bsl_path, line_num)
                if key not in seen:
                    seen.add(key)
                    targets.append({
                        'bsl_path': bsl_path,
                        'line': line_num,
                        'exists': exists,
                        'snippet': code_snippet,
                        'raw_loc': loc,
                    })
    return targets


def is_user_validation_error(comment_text):
    text_lower = comment_text.lower()
    lines = [l.strip() for l in comment_text.split('\n') if l.strip()]

    if not lines:
        return True
    if 'исключениевызванноеизвстроенногоязыка' in text_lower:
        return True
    if any(k in text_lower for k in ['нарушениеправдоступа', 'недостаточно прав', 'ошибка совместного доступа к файлу']):
        return True
    if len(lines) <= 2 and SINGLE_LINE_USER_MSG.match(lines[0]):
        return True
    if 'не удалось провести "' in text_lower:
        return True

    user_messages = [
        'запрет продаж', 'период документа закрыт', 'не заполнено', 'не заполнен',
        'документ уже в бегунке', 'запрещено менять', 'слишком сложный поисковый запрос',
        'пересекаются элементы отбора',
    ]
    return any(msg in text_lower for msg in user_messages)


def load_known_bugs():
    if os.path.exists(KNOWN_BUGS_PATH):
        try:
            with open(KNOWN_BUGS_PATH, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def save_known_bugs(known_bugs):
    with open(KNOWN_BUGS_PATH, 'w', encoding='utf-8') as f:
        json.dump(known_bugs, f, ensure_ascii=False, indent=2)


def main():
    if not os.path.exists(FILE_PATH):
        print(f"Файл {FILE_PATH} не найден!")
        return

    with open(FILE_PATH, 'r', encoding='utf-8-sig', errors='replace') as f:
        clean_xml = INVALID_XML_CHARS.sub('', f.read())

    root = ET.fromstring(clean_xml)
    anonymize = build_anonymizer(root)
    known_bugs = load_known_bugs()

    unique_errors = {}
    error_counts = Counter()
    error_variants = defaultdict(list)
    total_events = 0

    for elem in root.iter():
        if strip_ns(elem.tag) == 'Event':
            data = {strip_ns(child.tag): (child.text or '').strip() for child in elem}
            if 'Level' not in data:
                continue
            total_events += 1
            if data.get('Level') == 'Error':
                comment_text = data.get('Comment') or ''
                if comment_text and not is_user_validation_error(comment_text):
                    lines = [l.strip() for l in comment_text.split('\n') if l.strip()]
                    first_line = lines[0] if lines else 'Без текста'
                    signature = make_signature(lines)

                    error_counts[signature] += 1
                    anon_first = anonymize(first_line)
                    if anon_first not in error_variants[signature] and len(error_variants[signature]) < 10:
                        error_variants[signature].append(anon_first)

                    if signature not in unique_errors:
                        raw_user = data.get('UserName') or 'Система / Фоновое'
                        anon_lines = [anonymize(l) for l in lines[:12]]
                        unique_errors[signature] = {
                            'title': anon_first,
                            'date': data.get('Date', ''),
                            'user': mask_full_name(raw_user),
                            'app': data.get('ApplicationPresentation', ''),
                            'details': "\n".join(anon_lines),
                            'targets': extract_stack_targets(lines),
                        }

    new_bugs_count = 0
    now_str = datetime.now().strftime('%Y-%m-%d %H:%M')

    for sig, count in error_counts.items():
        info = unique_errors[sig]
        event_date = info['date'] or now_str
        if sig not in known_bugs:
            info['is_new'] = True
            info['first_seen'] = event_date
            new_bugs_count += 1
            known_bugs[sig] = {
                'title': info['title'],
                'first_seen': event_date,
                'last_seen': event_date,
                'total_seen_count': count,
            }
        else:
            info['is_new'] = False
            info['first_seen'] = known_bugs[sig].get('first_seen', event_date)
            known_bugs[sig]['last_seen'] = event_date
            known_bugs[sig]['total_seen_count'] = known_bugs[sig].get('total_seen_count', 0) + count

    save_known_bugs(known_bugs)

    sorted_bugs = sorted(
        error_counts.items(),
        key=lambda item: (not unique_errors[item[0]]['is_new'], -item[1])
    )

    summary_lines = [
        f"Всего событий в ЖР: {total_events} | Уникальных ошибок: {len(unique_errors)} | Новых [NEW!]: {new_bugs_count}\n",
        "=" * 70,
    ]
    for sig, count in sorted_bugs:
        info = unique_errors[sig]
        badge = "[NEW!] " if info['is_new'] else f"(Впервые: {info['first_seen']}) "
        summary_lines.append(f"ПОВТОРЕНИЙ: {count} | {badge}{info['date']} | {info['app']} | {info['user']}")
        summary_lines.append(info['details'])
        variants = error_variants[sig]
        if len(variants) > 1:
            summary_lines.append("Варианты: " + " | ".join(variants))
        summary_lines.append("-" * 70)

    with open(REPORT_PATH, 'w', encoding='utf-8') as out:
        out.write("\n".join(summary_lines))

    os.makedirs(TASKS_DIR, exist_ok=True)
    for old_file in glob.glob(os.path.join(TASKS_DIR, 'bug_*.md')):
        os.remove(old_file)
    old_diag = os.path.join(TASKS_DIR, 'DIAGNOSIS_REPORT.md')
    if os.path.exists(old_diag):
        os.remove(old_diag)

    index_lines = [
        "# Сводка технических ошибок из ЖР 1С\n",
        f"Всего событий в ЖР: **{total_events}** | Уникальных ошибок: **{len(unique_errors)}** | Новых после прошлых проверок: **{new_bugs_count}**\n",
        "| Файл задачи | Статус | Повторений | Ошибка | Целевой модуль |",
        "| :--- | :---: | :---: | :--- | :--- |",
    ]

    for idx, (sig, count) in enumerate(sorted_bugs, start=1):
        info = unique_errors[sig]
        bug_filename = f"bug_{idx:02d}.md"
        bug_filepath = os.path.join(TASKS_DIR, bug_filename)

        status_badge = "**[NEW!]**" if info['is_new'] else f"с {info['first_seen'][:10]}"
        title_prefix = "[NEW!] " if info['is_new'] else ""
        first_seen_val = info['first_seen']
        status_text = (
            "Новая ошибка (впервые зафиксирована)"
            if info['is_new']
            else f"Известная ошибка (впервые: {first_seen_val})"
        )

        md = [
            f"# Задача #{idx:02d}: {title_prefix}{info['title']}\n",
            f"- **Статус:** {status_text}",
            f"- **Повторений в текущей выгрузке:** {count}",
            f"- **Время в выгрузке:** {info['date']}",
            f"- **Приложение:** {info['app']}",
            f"- **Пользователь (обезличено):** {info['user']}\n",
        ]

        variants = error_variants[sig]
        if len(variants) > 1:
            md.append("## Зафиксированные вариации ошибки в этом же месте кода\n")
            for v in variants:
                md.append(f"- `{v}`")
            md.append("")

        md.extend([
            "## Текст ошибки и стек вызовов\n",
            "```text",
            info['details'],
            "```\n",
        ])

        if info['targets']:
            first_target = info['targets'][0]
            md.append("## Файлы конфигурации для анализа\n")
            for t in info['targets']:
                status = "найден" if t['exists'] else "не найден в config-dump"
                md.append(f"- `{t['bsl_path']}` — **строка {t['line']}** ({status})")
                if t['snippet']:
                    md.append(f"  - Код в стеке: `{t['snippet']}`")
            md.append("\n## Инструкция для агента\n")
            md.append(
                f"Открой указанный файл `{first_target['bsl_path']}` вокруг строки **{first_target['line']}** "
                "(прочитай ±50 строк) и проследи стек вызовов от действия пользователя к месту сбоя. "
                "Определи: 1) Точное место, 2) Причину падения, 3) Пошаговые сценарии воспроизведения "
                "в пользовательском режиме (от самого вероятного к менее вероятным). Исправления кода не пиши."
            )
            primary_target = f"`{first_target['bsl_path']}:{first_target['line']}`"
        else:
            md.append("## Инструкция для агента\n")
            md.append("Это инфраструктурная/серверная ошибка без привязки к модулю `.bsl`. Укажи вероятную причину и условия возникновения.")
            primary_target = "Инфраструктура / Сервер"

        with open(bug_filepath, 'w', encoding='utf-8') as bf:
            bf.write("\n".join(md))

        short_title = info['title'][:70].replace('|', '/')
        index_lines.append(f"| `{bug_filename}` | {status_badge} | {count} | {short_title} | {primary_target} |")

    index_path = os.path.join(TASKS_DIR, 'INDEX.md')
    with open(index_path, 'w', encoding='utf-8') as idxf:
        idxf.write("\n".join(index_lines))

    print(f"Обработано событий: {total_events} | Уникальных ошибок: {len(unique_errors)} | Новых [NEW!]: {new_bugs_count}")
    print(f"База знаний: {KNOWN_BUGS_PATH}")
    print(f"Сводный отчёт: {REPORT_PATH}")
    print(f"Карточки задач: {TASKS_DIR}")


if __name__ == '__main__':
    main()
