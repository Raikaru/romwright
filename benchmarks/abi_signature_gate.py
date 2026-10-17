#!/usr/bin/env python3
"""Calling-convention gate: printed signatures vs source prototypes (P2.3, P2.4).

Truth rows carry the C parameter list the decomp's source declares. Each tool
(ours = `romwright-cli decompile-batch`, stock = headless Ghidra running
`scripts/ExportDecompiledSignatures.java`) is asked to decompile the same
addresses; its printed signature is reduced to the same shape and compared:

* **arity**: printed parameter count == source parameter count;
* **class**: per position, float/double vs integer/pointer (width is not part
  of the class: `long long param_1` for an `s32` is a cosmetic fault, not a
  calling-convention one);
* **signature**: arity and every class equal (the number that matters to a
  reader deciding whether the function takes what the source says);
* **class counts**: arity and the number of float parameters equal. The
  right measure where integer and float arguments travel in separate
  register files (PowerPC EABI): which positions the floats held is not in
  the binary, so a decompiler lists the file's registers in model order;
* **switch**, over functions the binary lowers to a jump table and the source
  writes a `switch` for: `case` labels printed vs the cases the table
  carries (entries that do not go to the default target: what a decompiler can
  show, the primary number) and vs the labels the source writes (labels that
  fall to the default or share a body are invisible to any decompiler);
* **artefacts**: `unaff_*`, `in_*` (register read before write), `extraout_*`
  and decompiler warnings in the printed C (the frame/callee-saved symptom).

A function a tool did not decompile counts as wrong for every measure (it is
the denominator), and is also reported on its own.
"""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]

FLOAT_TYPES = {'f32', 'float', 'f64', 'double', 'float4', 'float8', 'float10', 'long double'}
WIDE_INT_TYPES = {'s64', 'u64', 'long long', 'unsigned long long', 'longlong', 'ulonglong', 'undefined8',
                  'int8', 'uint8', 'long long int'}


def classify_type(text, aggregates=frozenset()):
    """'f4' | 'f8' | 'i4' | 'i8' for one C declaration (a name is tolerated)."""
    text = re.sub(r'\b(const|volatile|register|struct|union|enum|signed)\b', ' ', text)
    text = re.sub(r'\s+', ' ', text).strip()
    if '*' in text or '[' in text or re.search(r'\(\s*\*', text):
        return 'i4'
    words = text.split(' ')
    # drop the trailing parameter name when what remains is still a type
    for cut in range(len(words), 0, -1):
        head = ' '.join(words[:cut])
        if head in FLOAT_TYPES:
            return 'f8' if head in ('f64', 'double', 'float8', 'long double') else 'f4'
        if head in WIDE_INT_TYPES:
            return 'i8'
    if words and words[0] in aggregates:
        return 'agg'
    return 'i4'


def split_params(text):
    depth, parts, current = 0, [], ''
    for char in text:
        if char in '([':
            depth += 1
        elif char in ')]':
            depth -= 1
        if char == ',' and depth == 0:
            parts.append(current)
            current = ''
        else:
            current += char
    if current.strip():
        parts.append(current)
    return [p.strip() for p in parts]


def truth_params(params):
    """Class list of a source parameter list; `void` is no parameters."""
    params = params.strip()
    if params in ('', 'void'):
        return []
    return [classify_type(p) for p in split_params(params) if p != '...']


def truth_return(ret):
    ret = re.sub(r'\b(static|inline|extern|const)\b', ' ', ret).strip()
    if ret == 'void':
        return 'void'
    return 'float' if classify_type(ret).startswith('f') else 'value'


def printed_signature(code):
    """(return kind, parameter classes) of the first function header in `code`."""
    if not code:
        return None
    head = code.split('{', 1)[0]
    head = re.sub(r'/\*.*?\*/', ' ', head, flags=re.S)
    head = re.sub(r'//[^\n]*', ' ', head)
    head = re.sub(r'\s+', ' ', head).strip()
    close = head.rfind(')')
    if close < 0:
        return None
    depth = 0
    open_at = -1
    for i in range(close, -1, -1):
        if head[i] == ')':
            depth += 1
        elif head[i] == '(':
            depth -= 1
            if depth == 0:
                open_at = i
                break
    if open_at < 0:
        return None
    params = head[open_at + 1:close].strip()
    ret_text = re.sub(r'\b(__\w+|WARNING:.*)\b', ' ', head[:open_at])
    ret_words = ret_text.rsplit(' ', 1)[0].strip() if ' ' in ret_text.strip() else 'int'
    ret = 'void' if ret_words == 'void' else ('float' if ret_words in FLOAT_TYPES else 'value')
    if params in ('', 'void'):
        return ret, []
    return ret, [classify_type(p) for p in split_params(params) if p != '...']


ARTEFACT = re.compile(r'\b(unaff_\w+|in_[rf]\d+\w*|in_\w+|extraout_\w+)\b')


def artefacts(code):
    found = ARTEFACT.findall(code or '')
    # `unaff_r26` is a callee-saved register the frame never saved or restored;
    # `unaff_GQR0` and friends are other state (paired-singles control) and are
    # kept apart so the frame measure is not read through them.
    return dict(unaff=sum(1 for f in found if re.fullmatch(r'unaff_[rf]\d+', f)),
                unaff_other=sum(1 for f in found if f.startswith('unaff_') and not re.fullmatch(r'unaff_[rf]\d+', f)),
                in_register=sum(1 for f in found if f.startswith('in_')),
                extraout=sum(1 for f in found if f.startswith('extraout_')),
                # decompiler warnings that mean the analysis lost something; an
                # injected call fixup, a removed dead block and a Thumb `bx` proven a return are the analysis working
                warnings=sum(1 for line in (code or '').splitlines()
                             if re.search(r'WARNING:|Unable to|halt_baddata|Bad instruction|unable', line)
                             and not re.search(r'replaced with injection|Removing unreachable block|Treating indirect jump as return', line)))


def case_labels(code):
    return len(re.findall(r'\bcase\b', code or ''))


# ---- tool drivers -----------------------------------------------------------------

def run_ours(cli, binary, project, name, base, addresses, env=None, chunk=100):
    out = {}
    for i in range(0, len(addresses), chunk):
        part = addresses[i:i + chunk]
        command = [str(cli), 'decompile-batch', str(binary), ','.join(f'{a:x}' for a in part),
                   '--name', name, '--project', str(project)]
        if base is not None:
            command += ['--base', f'{base:x}']
        result = subprocess.run(command, capture_output=True, text=True, env=env, timeout=3600)
        if result.returncode:
            raise RuntimeError(result.stderr[-1500:])
        answers = json.loads(result.stdout.strip().splitlines()[-1])
        for key, code in answers.items():
            out[int(key, 16)] = code
    return out


def run_stock(ghidra, binary, loader_args, language, cspec, lines, work, timeout=60, thumb=False):
    """`lines`: one per function, hex address or `<block>+<hex offset>`."""
    work.mkdir(parents=True, exist_ok=True)
    listing = work / 'addresses.txt'
    listing.write_text(''.join(f'{line}\n' for line in lines))
    output = work / 'stock.json'
    if output.exists():
        output.unlink()
    command = [str(ghidra / 'support/analyzeHeadless'), str(work), 'stock', '-import', str(binary),
               *loader_args, *(['-processor', language, '-cspec', cspec] if language else []),
               '-scriptPath', str(ROOT / 'scripts'), '-postScript', 'ExportDecompiledSignatures.java',
               str(listing), str(output), str(timeout), *(['thumb'] if thumb else []), '-deleteProject']
    env = dict(__import__('os').environ, DEBUGINFOD_URLS='')
    log = subprocess.run(command, capture_output=True, text=True, env=env)
    if not output.is_file():
        raise RuntimeError('stock export failed:\n' + (log.stdout + log.stderr)[-3000:])
    data = json.loads(output.read_text())
    return data['functions']


# ---- scoring ----------------------------------------------------------------------

def score(pairs):
    """`pairs`: (truth row, {'code'|'c', 'signature'?} or None). Returns the measures."""
    n = len(pairs)
    arity = signature = positions = positions_ok = ret_ok = decompiled = 0
    float_rows = float_sig = 0
    counts_exact = 0
    art = dict(unaff=0, unaff_other=0, in_register=0, extraout=0, warnings=0)
    art_functions = 0
    switch_rows = switch_exact = switch_under = switch_over = 0
    switch_cases = switch_source = switch_table = 0
    switch_src_exact = 0
    details = []
    for row, got_row in pairs:
        want = row['classes'] if 'classes' in row else truth_params(row['params'])
        want_ret = truth_return(row['ret'])
        has_float = any(c.startswith('f') for c in want)
        float_rows += has_float
        code = (got_row or {}).get('code') or (got_row or {}).get('c') or ''
        printed = printed_signature(code) if code else None
        sig_text = (got_row or {}).get('signature')
        if printed is None and sig_text:
            printed = printed_signature(sig_text + ' {')
        positions += len(want)
        ok = False
        if printed:
            decompiled += 1
            got_ret, got = printed
            arity += len(got) == len(want)
            same = [a[0] == b[0] for a, b in zip(want, got)]
            positions_ok += sum(same)
            ok = len(got) == len(want) and all(same)
            signature += ok
            counts_exact += len(got) == len(want) and sum(c[0] == 'f' for c in got) == sum(c[0] == 'f' for c in want)
            float_sig += ok and has_float
            ret_ok += got_ret == want_ret
        a = artefacts(code)
        for key in art:
            art[key] += a[key]
        art_functions += any(a.values())
        tables = row.get('tables') or []
        source_cases = sum(s['cases'] for s in row.get('switches') or [])
        if tables and source_cases:
            switch_rows += 1
            switch_source += source_cases
            printed_cases = case_labels(code)
            table_cases = sum(t.get('cases', 0) for t in tables)
            switch_cases += printed_cases
            switch_table += table_cases
            switch_exact += printed_cases == table_cases
            switch_under += printed_cases < table_cases
            switch_over += printed_cases > table_cases
            switch_src_exact += printed_cases == source_cases
        details.append(dict(address=row.get('address', row.get('offset')), name=row['name'], truth=want,
                            got=printed[1] if printed else None, ok=ok))
    return dict(functions=n, decompiled=decompiled, arity_exact=arity, signature_exact=signature, class_counts_exact=counts_exact,
                positions=positions, positions_agree=positions_ok, return_kind_agree=ret_ok,
                float_functions=float_rows, float_signature_exact=float_sig,
                artefacts=art, functions_with_artefacts=art_functions,
                switch_functions=switch_rows, switch_cases_exact=switch_exact,
                switch_cases_under=switch_under, switch_cases_over=switch_over,
                switch_cases_printed=switch_cases, switch_cases_source=switch_source,
                switch_cases_table=switch_table, switch_source_exact=switch_src_exact,
                details=details)


def table(label, report):
    n = report['functions']
    pct = lambda a, b: f'{a}/{b} = {a / b:.4f}' if b else f'{a}/{b}'
    lines = [f'{label}:',
             f"  decompiled          {pct(report['decompiled'], n)}",
             f"  arity exact         {pct(report['arity_exact'], n)}",
             f"  signature exact     {pct(report['signature_exact'], n)}",
             f"  class counts exact  {pct(report['class_counts_exact'], n)}",
             f"  positions agree     {pct(report['positions_agree'], report['positions'])}",
             f"  return kind agrees  {pct(report['return_kind_agree'], n)}",
             f"  float-param funcs   {pct(report['float_signature_exact'], report['float_functions'])}",
             f"  artefacts           {report['artefacts']} in {report['functions_with_artefacts']} functions"]
    if report['switch_functions']:
        lines.append(f"  switch cases vs table  exact {report['switch_cases_exact']}/{report['switch_functions']}, "
                     f"under {report['switch_cases_under']}, over {report['switch_cases_over']}; printed "
                     f"{report['switch_cases_printed']} vs table {report['switch_cases_table']} vs source "
                     f"{report['switch_cases_source']} (source-exact {report['switch_source_exact']})")
    return '\n'.join(lines)


def softfloat(codes):
    """What a soft-float ABI must never print: float/double parameters (the
    ABI passes them in integer registers) and reads of FP registers."""
    out = dict(functions=len(codes), decompiled=0, params=0, float_params=0, functions_with_float_param=0,
               functions_with_fp_register_input=0, in_gp=0)
    for code in codes:
        if not code:
            continue
        out['decompiled'] += 1
        printed = printed_signature(code)
        classes = printed[1] if printed else []
        out['params'] += len(classes)
        floats = sum(c[0] == 'f' for c in classes)
        out['float_params'] += floats
        out['functions_with_float_param'] += floats > 0
        out['functions_with_fp_register_input'] += bool(re.search(r'\b(in_[fds]\d+|extraout_[fds]\d+|unaff_[fds]\d+)\b', code))
        out['in_gp'] += bool(re.search(r'\bin_gp\b', code))
    return out


def stock_line(row, block):
    return f"{block}+{row['offset']:x}" if block else f"{row['address']:x}"


def ours_address(row, base):
    return row['address'] if 'address' in row else base + row['offset']


def ours_pairs(truth, answers, base):
    return [(row, {'code': answers.get('%x' % ours_address(row, base))}
             if answers.get('%x' % ours_address(row, base)) else None) for row in truth]


def stock_pairs(truth, answers, block):
    return [(row, answers.get(stock_line(row, block))) for row in truth]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    o = sub.add_parser('ours', help='decompile the truth addresses with romwright-cli')
    o.add_argument('--truth', type=Path, required=True)
    o.add_argument('--binary', type=Path, required=True)
    o.add_argument('--project', type=Path, required=True)
    o.add_argument('--name', required=True)
    o.add_argument('--base', type=lambda v: int(v, 16), help='raw-image base passed to decompile-batch')
    o.add_argument('--module-base', type=lambda v: int(v, 16), default=0,
                   help='where the truth rows\' `offset` starts in this import (a REL\'s text)')
    o.add_argument('--cli', type=Path, default=ROOT / 'target/release/romwright-cli')
    o.add_argument('--out', type=Path, required=True)
    k = sub.add_parser('stock', help='decompile the truth addresses with headless Ghidra')
    k.add_argument('--truth', type=Path, required=True)
    k.add_argument('--binary', type=Path, required=True)
    k.add_argument('--ghidra', type=Path, default=Path.home() / 'ghidra_12.1.3_PUBLIC')
    k.add_argument('--loader-arg', action='append', default=[], help='repeatable analyzeHeadless import option')
    k.add_argument('--language', default='', help='processor id; empty lets the loader choose')
    k.add_argument('--cspec', default='default')
    k.add_argument('--block', help='memory block the truth `offset` is relative to (a REL\'s text)')
    k.add_argument('--thumb', action='store_true', help='create missed functions in Thumb state (GBA)')
    k.add_argument('--work', type=Path, required=True)
    k.add_argument('--out', type=Path, required=True)
    f = sub.add_parser('softfloat', help='float parameters and FP-register artefacts on a soft-float image')
    f.add_argument('--truth', type=Path, required=True, help='rows with an `address` (a sample is enough)')
    f.add_argument('--ours', type=Path)
    f.add_argument('--stock', type=Path)
    f.add_argument('--report', type=Path)
    s = sub.add_parser('score')
    s.add_argument('--truth', type=Path, required=True)
    s.add_argument('--ours', type=Path, help='JSON {addr_hex: code} from `ours`')
    s.add_argument('--module-base', type=lambda v: int(v, 16), default=0)
    s.add_argument('--stock', type=Path, help='JSON from `stock`')
    s.add_argument('--block')
    s.add_argument('--report', type=Path)
    args = parser.parse_args()
    truth = json.loads(args.truth.read_text())
    if args.command == 'ours':
        addresses = [ours_address(r, args.module_base) for r in truth]
        answers = run_ours(args.cli, args.binary, args.project, args.name, args.base, addresses)
        args.out.write_text(json.dumps({f'{a:x}': c for a, c in answers.items()}))
        return
    if args.command == 'stock':
        loader = []
        for item in args.loader_arg:
            loader += item.split()
        rows = run_stock(args.ghidra, args.binary, loader, args.language, args.cspec,
                         [stock_line(r, args.block) for r in truth], args.work, thumb=args.thumb)
        args.out.write_text(json.dumps({'functions': rows}))
        return
    if args.command == 'softfloat':
        report = {}
        for label, path in (('ours', args.ours), ('stock', args.stock)):
            if path is None:
                continue
            raw = json.loads(path.read_text())
            if label == 'stock':
                raw = {k: (v.get('c') or '') for k, v in raw['functions'].items()}
            report[label] = softfloat([raw.get('%x' % r['address']) or '' for r in truth])
            print(label, report[label])
        if args.report:
            args.report.write_text(json.dumps(report, indent=1))
        return
    report = {}
    ours = json.loads(args.ours.read_text()) if args.ours else None
    stock = json.loads(args.stock.read_text())['functions'] if args.stock else None
    if ours is not None:
        report['ours'] = score(ours_pairs(truth, ours, args.module_base))
    if stock is not None:
        report['stock'] = score(stock_pairs(truth, stock, args.block))
    if ours is not None and stock is not None:
        # The functions this tool's discovery found are the ones it can be asked
        # about; score both tools on exactly those too.
        found = [r for r in truth if ours.get('%x' % ours_address(r, args.module_base))]
        if found:
            report['ours-common'] = score(ours_pairs(found, ours, args.module_base))
            report['stock-common'] = score(stock_pairs(found, stock, args.block))
    for label, result in report.items():
        print(table(label, result))
    if args.report:
        args.report.write_text(json.dumps(report, indent=1))


if __name__ == '__main__':
    main()
