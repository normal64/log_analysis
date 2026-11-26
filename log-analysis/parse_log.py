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
STACK_LINE_RE = re.compile(r'\{([^}]+)\((\d+)\)\}:(.*)$')
PROC_HEADER_RE = re.compile(r'^\s*(Процедура|Функция)\s+([А-ЯЁA-Z0-9_]+)', re.IGNORECASE)

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
    ext_name = None
    if ' ' in stack_location:
        ext_name, stack_location = stack_location.split(' ', 1)
        ext_name = ext_name.strip()
        stack_location = stack_location.strip()

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

    candidates = []
    if ext_name:
        candidates.extend([
            f"Extensions/{ext_name}/{rel_path}",
            f"{ext_name}/{rel_path}",
            rel_path,
        ])
    else:
        candidates.append(rel_path)
        ext_root = os.path.join(CONFIG_DUMP_REL, 'Extensions')
        if os.path.isdir(ext_root):
            for entry in sorted(os.listdir(ext_root)):
                if os.path.isdir(os.path.join(ext_root, entry)):
                    candidates.append(f"Extensions/{entry}/{rel_path}")

    for candidate in candidates:
        full_check_path = os.path.normpath(os.path.join(CONFIG_DUMP_REL, candidate))
        if os.path.exists(full_check_path):
            return f"config-dump/{candidate}", True

    return f"config-dump/{candidates[0]}", False


def extract_bsl_context(bsl_rel_path, line_num_str, radius=35):
    """Извлекает имя процедуры/функции и фрагмент кода ±radius строк вокруг места сбоя."""
    try:
        target_line = int(line_num_str)
    except ValueError:
        return None, None

    rel_inside_dump = bsl_rel_path.replace('config-dump/', '', 1)
    full_path = os.path.normpath(os.path.join(CONFIG_DUMP_REL, rel_inside_dump))
    if not os.path.exists(full_path):
        return None, None

    try:
        with open(full_path, 'r', encoding='utf-8-sig', errors='replace') as f:
            file_lines = f.read().splitlines()
    except Exception:
        return None, None

    total_lines = len(file_lines)
    if target_line < 1 or target_line > total_lines:
        return None, None

    proc_name = None
    for idx in range(target_line - 1, -1, -1):
        line_str = file_lines[idx]
        m = PROC_HEADER_RE.match(line_str)
        if m:
            proc_type = m.group(1)
            name = m.group(2)
            directive = ""
            if idx > 0 and file_lines[idx - 1].strip().startswith('&'):
                directive = f"{file_lines[idx - 1].strip()} "
            proc_name = f"{directive}{proc_type} {name}()"
            break

    start_idx = max(0, target_line - 1 - radius)
    end_idx = min(total_lines, target_line + radius)

    snippet_lines = []
    for i in range(start_idx, end_idx):
        curr_num = i + 1
        clean_line = file_lines[i].replace('\t', '    ')
        marker = "// >>> ОШИБКА ЗДЕСЬ:" if curr_num == target_line else ""
        if marker:
            snippet_lines.append(f"{marker}\n{clean_line}")
        else:
            snippet_lines.append(clean_line)


    return proc_name, "\n".join(snippet_lines)


def _get_ru_title(elem):
    """Достаёт русский текст из узла <Title> или <Synonym> в Form.xml 1С."""
    for child in elem:
        tag = strip_ns(child.tag)
        if tag in ('Title', 'Synonym'):
            for item in child.iter():
                if strip_ns(item.tag) == 'item':
                    lang = ''
                    content = ''
                    for sub in item:
                        stag = strip_ns(sub.tag)
                        if stag == 'lang':
                            lang = (sub.text or '').strip()
                        elif stag == 'content':
                            content = (sub.text or '').strip()
                    if lang == 'ru' and content:
                        return content
            if child.text and child.text.strip():
                return child.text.strip()
    return None


def extract_form_ui_context(bsl_rel_path):
    """Если модуль принадлежит форме (кроме общей формы отчета БСП), вытягивает русские заголовки из Form.xml."""
    if not bsl_rel_path.endswith('/Ext/Form/Module.bsl'):
        return None
    if 'CommonForms/ФормаОтчета/' in bsl_rel_path:
        return None

    rel_inside_dump = bsl_rel_path.replace('config-dump/', '', 1)
    form_xml_rel = rel_inside_dump.replace('/Ext/Form/Module.bsl', '/Ext/Form.xml')
    full_xml_path = os.path.normpath(os.path.join(CONFIG_DUMP_REL, form_xml_rel))

    if not os.path.exists(full_xml_path):
        return None

    try:
        tree = ET.parse(full_xml_path)
        root = tree.getroot()
    except Exception:
        return None

    form_title = _get_ru_title(root)
    commands = []
    fields = []

    for elem in root.iter():
        tag = strip_ns(elem.tag)
        if tag == 'Command':
            cmd_name = elem.attrib.get('name', '')
            ru_title = _get_ru_title(elem)
            if cmd_name and ru_title and len(commands) < 25:
                commands.append(f"`{cmd_name}` → **«{ru_title}»**")
        elif tag in ('InputField', 'CheckBoxField', 'RadioButtonField', 'Button', 'CommandBarButton', 'Table'):
            el_name = elem.attrib.get('name', '')
            ru_title = _get_ru_title(elem)
            if el_name and ru_title and len(fields) < 35:
                entry = f"`{el_name}` → **«{ru_title}»**"
                if entry not in fields and entry not in commands:
                    fields.append(entry)

    if not form_title and not commands and not fields:
        return None

    lines = ["## Контекст интерфейса формы (из Form.xml)\n"]
    if form_title:
        lines.append(f"- **Заголовок окна формы:** «{form_title}»")
    if commands:
        lines.append("- **Команды / Кнопки формы:** " + "; ".join(commands))
    if fields:
        lines.append("- **Элементы / Поля формы:** " + "; ".join(fields))
    lines.append("")
    return "\n".join(lines)


def extract_stack_targets(lines):
    targets = []
    seen = set()
    for line in lines:
        m = STACK_LINE_RE.search(line)
        if m:
            loc, line_num, code_snippet = m.group(1), m.group(2), m.group(3).strip()
            resolved = resolve_1c_path(loc)
            if resolved:
                bsl_path, exists = resolved
                key = (bsl_path, line_num)
                if key not in seen:
                    seen.add(key)
                    proc_name, code_block = (None, None)
                    ui_context = None
                    if exists:
                        proc_name, code_block = extract_bsl_context(bsl_path, line_num)
                        ui_context = extract_form_ui_context(bsl_path)
                    targets.append({
                        'bsl_path': bsl_path,
                        'line': line_num,
                        'exists': exists,
                        'snippet': code_snippet,
                        'raw_loc': loc,
                        'proc_name': proc_name,
                        'code_block': code_block,
                        'ui_context': ui_context,
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

    if re.search(r'задание на приемку\s+.*?\s+завершено,\s*изменения невозможны', text_lower):
        return True

    user_messages = [
        'запрет продаж', 'период документа закрыт', 'не заполнено', 'не заполнен',
        'документ уже в бегунке', 'запрещено менять', 'слишком сложный поисковый запрос',
        'пересекаются элементы отбора', 'необходимо установить закупочные цены',
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
                proc_info = f" | Метод: `{t['proc_name']}`" if t.get('proc_name') else ""
                md.append(f"- `{t['bsl_path']}` — **строка {t['line']}** ({status}){proc_info}")
                if t['snippet']:
                    md.append(f"  - Код в стеке: `{t['snippet']}`")
            md.append("")

            embedded_count = 0
            for t in info['targets']:
                if t.get('code_block') and embedded_count < 2:
                    proc_label = f" — `{t['proc_name']}`" if t.get('proc_name') else ""
                    md.append(f"## Фрагмент кода: `{t['bsl_path']}:{t['line']}`{proc_label}\n")
                    md.append("```bsl")
                    md.append(t['code_block'])
                    md.append("```\n")
                    embedded_count += 1

            for t in info['targets']:
                if t.get('ui_context'):
                    md.append(t['ui_context'])
                    break

            md.append("## Инструкция для агента\n")
            if first_target.get('code_block'):
                md.append(
                    "Фрагмент исходного `.bsl` и элементы интерфейса формы (если применимо) уже встроены выше. "
                    "**Не вызывай `read_file` для этого файла**, если контекста выше достаточно для понимания причины сбоя. "
                    "Определи: 1) Точное место и имя процедуры, 2) Причину падения, 3) Пошаговые сценарии воспроизведения "
                    "в пользовательском режиме (от самого вероятного к менее вероятным). Исправления кода не пиши."
                )
            else:
                md.append(
                    f"Модуль `{first_target['bsl_path']}` не найден в `config-dump` (возможно, типовой или в другой базе). "
                    "Сразу пиши диагноз по тексту исключения и стеку выше без поиска файлов в терминале."
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
