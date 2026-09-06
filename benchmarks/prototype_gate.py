"""Frozen II.3 prototype arity scoring shared by reference and native gates."""


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
