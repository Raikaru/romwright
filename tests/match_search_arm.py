"""The near-miss search arm shared by the lane harnesses (m22-002, m22-003): the product command's plan, the product's ranking.

`romwright-cli match --plan` is the only copy of the plan (docs/match.md): the single printing knobs, and, from what they did
on one function, the combinations to try next. A harness gives `search_row` two callables for its own lane:

    export(words, tag) -> C text or None     the romwright export of the function with `K=V` environment words set
    score(text, tag)   -> variants dict      the harness's scoring of one candidate: {"context": {...}, "standalone": {...}, ...}

and gets the best print back. Variants of one batch export and score in parallel on `pool`; a batch is not cut short at an
exact variant (the command stops at the first one).
"""
import json
import re
import subprocess
import time


def plan(cli, budget, outcomes_path=None, outcomes=None):
    """`match --plan`: the single knobs (`outcomes` None) or the combinations after them."""
    argv = [str(cli), "match", "--plan", "--budget", str(budget)]
    if outcomes is not None:
        outcomes_path.write_text(json.dumps(outcomes))
        argv += ["--outcomes", str(outcomes_path)]
    done = subprocess.run(argv, capture_output=True, text=True, timeout=60)
    if done.returncode != 0:
        raise RuntimeError(f"match --plan failed: {done.stderr[-300:]}")
    return json.loads(done.stdout)


def candidate_key(variants):
    """The product's ranking of one scored print (match_search::Score::key) on the headline (context) compile."""
    entry = variants["context"]
    differences = entry.get("byte_differences")
    return (bool(entry["exact"]), bool(entry["compiled"]), entry["percent"], -(differences if differences is not None else 2 ** 62))


def tag_of(label):
    return re.sub(r"\W+", "_", label)


def search_row(cli, budget, pool, tmp, export, score, default_text, default_variants):
    """Near-miss search of one function whose default print compiled and is not exact.
    -> (winner label, winner text, winner variants, record)"""
    started = time.time()
    context = default_variants["context"]
    rows = [{"variant": "default", "same_as": None, "exact": context["exact"], "compiled": context["compiled"], "percent": context["percent"]}]
    entries = [("default", default_text, default_variants)]  # (label, text, variants) of each distinct print
    seen = {default_text: 0}
    counts = {"decompiles": 0, "compiles": 0}

    def batch(items):
        texts = list(pool.map(lambda item: export(item["env"], tag_of(item["label"])), items))
        counts["decompiles"] += len(items)
        first = len(rows)
        todo = []
        for item, text in zip(items, texts):
            index = len(rows)
            record = {"variant": item["label"], "same_as": None}
            rows.append(record)
            if text is None:
                record["error"] = "no export"
            elif text in seen:
                record["same_as"] = seen[text]
            else:
                seen[text] = index
                todo.append((index, item["label"], text))
        scored = list(pool.map(lambda job: score(job[2], tag_of(job[1])), todo))
        counts["compiles"] += len(todo)
        for (index, label, text), variants in zip(todo, scored):
            entries.append((label, text, variants))
            rows[index].update(exact=variants["context"]["exact"], compiled=variants["context"]["compiled"], percent=variants["context"]["percent"])
        for record in rows[first:]:
            if record["same_as"] is not None:
                earlier = rows[record["same_as"]]
                record.update({k: earlier.get(k) for k in ("exact", "compiled", "percent")})

    def outcome(record, label):
        byte_differences = next((v["context"].get("byte_differences") for l, _, v in entries if l == label), None)
        return {"label": label, "distinct": record["same_as"] is None and "error" not in record, "exact": bool(record.get("exact")),
                "compiled": bool(record.get("compiled")), "percent": record.get("percent") or 0.0, "byte_diffs": byte_differences}

    outcomes_path = tmp / "outcomes.json"
    singles = plan(cli, budget)["singles"]
    batch(singles)
    if not any(r.get("exact") for r in rows):
        found = {"stock": outcome(rows[0], "default"), "singles": [outcome(record, item["label"]) for record, item in zip(rows[1:], singles)]}
        combinations = plan(cli, budget, outcomes_path, found)["combinations"]
        if combinations:
            batch(combinations)
    outcomes_path.unlink(missing_ok=True)
    best = max(range(len(entries)), key=lambda i: (candidate_key(entries[i][2]), -i))  # the earliest wins a tie
    label, text, variants = entries[best]
    return label, text, variants, {"budget": budget, "variants": rows, "winner": label, "improved": best != 0,
                                   "decompiles": counts["decompiles"], "compiles": counts["compiles"], "seconds": round(time.time() - started, 1)}
