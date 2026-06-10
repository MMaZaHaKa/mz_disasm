"""
IDA Pro 7.6 IDAPython script (read-only w.r.t. IDA DB)

Назначение:
 - Генерировать/обновлять PPSSPP-style sym-файл из функций, найденных в IDA.
 - В режиме с входным .sym: парсит входной .sym, сопоставляет записи по адресу с функциями в IDA
   и **только в выходном .sym** обновляет имена на деманглированные имена из IDA.
   ВАЖНО: скрипт **не изменяет** имена/метаданные в самой базе IDA (никаких вызовов записи в DB).
 - В режиме без входного .sym: экспортирует все функции из IDA в новый sym-файл.
 - Сохраняет результат в файле, имя предлагается диалогом (по умолчанию idasym.sym).

Поведение при конфликтах имен:
 - Если деманглированное имя уже встречается, добавляется суффикс _1, _2 и т.д.
 - Если функция есть в IDA, но её адреса нет в исходном sym — добавляется запись с префиксом NOSYM_.
 - Записи из исходного sym, для которых нет соответствующей функции в IDA, остаются в итоговом файле.

Формат строки в файле:
    08804000 z_un_08804000,0080
    ADDRESS NAME,OFFSET(4 hex)

Как запускать: File -> Script file... или через консоль IDA.
"""

from __future__ import print_function
import ida_kernwin
import idautils
import ida_funcs
import idaapi
import idc
import os


def demangle_name_try(name):
    """Попробовать получить человекочитаемое (деманглированное) имя.
    НЕ записывает ничего в базу — только возвращает строку.
    """
    if not name:
        return name
    # try built-in demangler utilities — they return strings only
    try:
        if hasattr(idaapi, 'demangle_name'):
            try:
                dem = idaapi.demangle_name(name)
                if dem:
                    return dem
            except Exception:
                try:
                    dem = idaapi.demangle_name(name, 0)
                    if dem:
                        return dem
                except Exception:
                    pass
    except Exception:
        pass

    try:
        if hasattr(idc, 'demangle_name'):
            try:
                dem = idc.demangle_name(name, 0)
                if dem:
                    return dem
            except Exception:
                try:
                    dem = idc.demangle_name(name)
                    if dem:
                        return dem
                except Exception:
                    pass
    except Exception:
        pass

    # fallback: if IDA can provide a short demangled name without side effects
    try:
        if hasattr(idaapi, 'get_short_demangled_name'):
            dem = idaapi.get_short_demangled_name(name)
            if dem:
                return dem
    except Exception:
        pass

    return name


def format_addr(ea):
    return "{:08X}".format(ea)


def format_size(sz):
    return "{:04x}".format(sz)


def parse_sym_file(path):
    entries = {}  # ea -> (name_from_sym, size_from_sym)
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            for ln in f:
                ln = ln.strip()
                if not ln or ln.startswith('#'):
                    continue
                parts = ln.split()
                if len(parts) < 2:
                    continue
                addr_s = parts[0]
                rest = parts[1]
                if ',' in rest:
                    name_part, off_part = rest.split(',', 1)
                else:
                    name_part = rest
                    off_part = '0'
                try:
                    ea = int(addr_s, 16)
                except Exception:
                    continue
                try:
                    size = int(off_part, 16)
                except Exception:
                    try:
                        size = int(off_part)
                    except Exception:
                        size = 0
                entries[ea] = (name_part, size)
    except Exception as e:
        ida_kernwin.msg('Failed to read sym file: %s' % str(e))
    return entries


def collect_ida_functions():
    """Собрать функции из IDA: возвратить dict ea -> (demangled_name, size)
    Не совершает никаких записей в IDA.
    """
    funcs = {}
    for ea in idautils.Functions():
        try:
            name = idc.get_func_name(ea)
        except Exception:
            # безопасный fallback
            try:
                func = ida_funcs.get_func(ea)
                name = ida_funcs.get_func_name(ea)
            except Exception:
                name = None
        if not name:
            continue
        dem = demangle_name_try(name).strip()
        # sanitize name: remove commas/newlines which would break sym format
        dem = dem.replace(',', '_')
        f = ida_funcs.get_func(ea)
        if f:
            size = f.end_ea - f.start_ea
        else:
            # approximate
            size = 0
        funcs[ea] = (dem, size)
    return funcs


def make_unique(name, used):
    """Добавляет суффикс _1/_2 при конфликте имени.
    used — dict name->count (tracks already-used names in output)
    Возвращает уникальное имя и обновляет used.
    """
    if name not in used:
        used[name] = 1
        return name
    else:
        cnt = used[name]
        newname = f"{name}_{cnt}"
        while newname in used:
            cnt += 1
            newname = f"{name}_{cnt}"
        used[name] = cnt + 1
        used[newname] = 1
        return newname


def build_output_entries(sym_entries, ida_funcs_map):
    """Построить итоговый набор записей для записи в файл.
    sym_entries: dict ea -> (sym_name, sym_size)
    ida_funcs_map: dict ea -> (dem_name, size)

    Правило:
     - Для каждого адреса, который есть в sym_entries и совпадает с IDA func -> заменить имя на демангл из IDA (в выходном файле only).
     - Для адресов в sym_entries без IDA-входа оставить запись как есть.
     - Для функций в IDA, отсутствующих в sym_entries добавить NOSYM_<name>.

    Возвращает dict ea -> (out_name, out_size)
    """
    out = {}
    used_names = {}

    # first, copy original sym entries — and for those that match IDA, change name to IDA's demangled name
    for ea, (sym_name, sym_size) in sym_entries.items():
        if ea in ida_funcs_map:
            dem_name, ida_size = ida_funcs_map[ea]
            chosen_size = ida_size if ida_size else sym_size
            unique = make_unique(dem_name, used_names)
            out[ea] = (unique, chosen_size)
        else:
            # keep original sym entry
            unique = make_unique(sym_name, used_names)
            out[ea] = (unique, sym_size)

    # now add IDA functions that were not present in sym
    for ea, (dem_name, ida_size) in ida_funcs_map.items():
        if ea in out:
            continue
        pref = 'NOSYM_' + dem_name
        unique = make_unique(pref, used_names)
        out[ea] = (unique, ida_size)

    return out


def write_sym_file(path, entries):
    try:
        with open(path, 'w', encoding='utf-8') as f:
            for ea in sorted(entries.keys()):
                name, size = entries[ea]
                f.write(f"{format_addr(ea)} {name},{format_size(size)}\n")
        ida_kernwin.msg('Wrote sym file: %s' % path)
        return True
    except Exception as e:
        ida_kernwin.msg('Failed to write sym file: %s' % str(e))
        return False


def main():
    ida_kernwin.msg('IDA Sym generator (read-only for DB)')
    yn = ida_kernwin.ask_yn(ida_kernwin.ASKBTN_YES, 'Есть ли входной sym-файл для обновления? (Yes = открыть)')
    sym_entries = {}
    if yn == ida_kernwin.ASKBTN_YES:
        path = ida_kernwin.ask_file(0, "*.sym", 'Open sym file')
        if path and os.path.exists(path):
            sym_entries = parse_sym_file(path)
            ida_kernwin.msg('Parsed %d entries from sym.' % len(sym_entries))
        else:
            ida_kernwin.msg('No input file selected or file does not exist — will export only IDA functions.')

    ida_map = collect_ida_functions()
    ida_kernwin.msg('Collected %d functions from IDA.' % len(ida_map))

    if sym_entries:
        out_entries = build_output_entries(sym_entries, ida_map)
    else:
        # export all IDA functions as-is
        used = {}
        out_entries = {}
        for ea, (dem, size) in ida_map.items():
            name = make_unique(dem, used)
            out_entries[ea] = (name, size)

    default_name = 'idasym.sym'
    save_path = ida_kernwin.ask_file(1, default_name, 'Save sym file as')
    if not save_path:
        ida_kernwin.msg('Save cancelled.')
        return
    save_path = os.path.normpath(save_path)

    ok = write_sym_file(save_path, out_entries)
    if ok:
        ida_kernwin.msg('Done. Saved to: %s' % save_path)
    else:
        ida_kernwin.msg('Failed to save file.')


if __name__ == '__main__':
    main()
