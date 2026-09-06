"""Frozen II.3 prototype arity scoring shared by reference and native gates."""
import hashlib
import json


def score_arity(truth, observed):
    matched = sorted(truth.keys() & observed.keys())
    if not matched:
        raise ValueError('no functions matched the DWARF truth')
    incorrect = []
    for entry in matched:
        actual, expected = observed[entry], truth[entry]['arity']
        if actual is not None and (type(actual) is not int or actual < 0):
            raise ValueError(f'invalid observed arity at {entry}: {actual!r}')
        if actual != expected:
            incorrect.append(dict(entry=entry, expected=expected, actual=actual))
    correct = len(matched) - len(incorrect)
    return dict(matched=len(matched), correct=correct, value=correct / len(matched),
        incorrect=incorrect, unmatched_truth=sorted(truth.keys() - observed.keys()))


def write_arity_report(path, report):
    """Keep complete mismatch evidence readable without oversized report commits."""
    path.parent.mkdir(parents=True, exist_ok=True)
    for row in report['corpus']:
        for producer, score in row.get('scores', {}).items():
            incorrect = score.pop('incorrect', None)
            if incorrect is None:
                continue
            score['incorrect_count'] = len(incorrect)
            if incorrect:
                data = ''.join(json.dumps(item) + '\n' for item in incorrect).encode()
                sha = hashlib.sha256(data).hexdigest()
                detail = path.parent / (path.stem + '-mismatches') / (
                    f"{row['id']}-{producer}-{sha[:16]}.jsonl")
                detail.parent.mkdir(parents=True, exist_ok=True)
                detail.write_bytes(data)
                score['incorrect_evidence'] = dict(
                    path=detail.relative_to(path.parent).as_posix(), sha256=sha)
    path.write_text(json.dumps(report, indent=2) + '\n')
