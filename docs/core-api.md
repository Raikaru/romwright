# The Core API

`romwright-api` is the interface every consumer speaks: the Qt desktop, scripts and
agents all send the same requests. It has no analysis of its own — it opens a
project and answers from the store, so a request never changes what a fact
means.

Every exchange on this page is sent to a real `romwright-api` process by
`tests/m6-002_documented_api.py`, and each documented response must be a
subset of the real one: every documented field must be present with the
documented value. `$PROGRAM` is the program name and `$BINARY` the imported
binary's path.

## Running it

```
romwright-api --project DIR                    # newline-delimited JSON on stdin
romwright-api --project DIR --listen 127.0.0.1:8377   # HTTP/1.1 POST /v2, localhost
```

Requests are one JSON object per line; responses come back in order, one per
line. The TCP mode carries the same envelope over `POST /v2` and adds no
authentication of its own — bind it to localhost.

## The envelope

A request names the API version, an id of your choosing, a method and its
parameters. A response echoes the version and id, and carries exactly one of
`result` or `error`.

```json
{"api": 2, "id": 1, "method": "ping"}
{"api": 2, "id": 1, "result": {"api": 2, "service": "romwright-core"}}
```

Omitting `api` is an error rather than a default, so a client built against a
future version cannot be silently answered by an older service:

```json
{"api": 2, "id": 2, "method": "nope"}
{"api": 2, "id": 2, "error": {"code": "unknown_method", "message": "unknown_method: nope"}}
{"api": 2, "id": 3, "method": "xrefs", "params": {"program": "$PROGRAM"}}
{"api": 2, "id": 3, "error": {"code": "invalid_params", "message": "request: params.address is required"}}
```

Error codes are `invalid_request` (the envelope itself), `invalid_params` (a
missing or unusable parameter), `unknown_method`, and `core_error` (the store
or a pass refused).

## Addresses are typed, not integers

Every address in a request may be written as a hex string; every address in a
response is an object naming its space. A raw integer offset would lose the
space, and a program can have more than one.

```json
{"api": 2, "id": 4, "method": "search", "params": {"program": "$PROGRAM", "term": "add"}}
{"api": 2, "id": 4, "result": [{"address": {"space": "Ram", "offset": 4195430}, "kind": "function", "name": "add"}]}
```

## Facts carry their provenance

Every derived fact says which pass produced it and whether it is inferred or
asserted, carries the sentence that explains that pass, and says what kind of
evidence that pass has -- `declared` (the image states it), `decoded` (SLEIGH
decoded the instruction) or `inferred` (a pass concluded it). `confidence`
stays `null` unless something derives a number: today only a signature match,
whose number is the share of the record's bytes that were compared. A consumer that treats a swept string like a
linker-proven symbol is making that choice itself, with the evidence in hand.

```json
{"api": 2, "id": 5, "method": "strings", "params": {"program": "$PROGRAM"}}
{"api": 2, "id": 5, "result": [{"address": {"space": "Ram", "offset": 4198400}, "kind": "ASCII", "value": "/lib64/ld-linux-x86-64.so.2"}]}
{"api": 2, "id": 6, "method": "memory_regions", "params": {"program": "$PROGRAM"}}
{"api": 2, "id": 6, "result": [{"name": "elf:0", "permissions": "r-x", "size": 792, "source": "native-import", "start": {"space": "Ram", "offset": 4194304}}]}
```

## Edits are journalled

A rename returns the fact it wrote, and `undo` reverses the last journalled
command and says what it reversed.

```json
{"api": 2, "id": 7, "method": "rename", "params": {"program": "$PROGRAM", "address": "00400466", "name": "demo_add"}}
{"api": 2, "id": 7, "result": {"address": {"space": "Ram", "offset": 4195430}, "name": "demo_add"}}
{"api": 2, "id": 8, "method": "undo", "params": {"program": "$PROGRAM"}}
{"api": 2, "id": 8, "result": {"message": "undid rename seq 1 (00400466 -> add)"}}
```

## Paged reads

Large programs are read a window at a time. A page carries the window, the
total and the store revision the window was read at, so a client can tell a
stale page from a changed program: `functions_page`, `symbols_page`,
`xrefs_page` and `jobs_page` all answer that shape.

`symbols_page` and `xrefs_page` also take `evidence`, one of `declared`,
`decoded` or `inferred` -- the kind each fact reports. The filter narrows the
`total` as well as the window, so an audit that wants only what the image
states does not pay for the rest, and a kind that does not exist is
`invalid_params` rather than an empty page:

```json
{"api": 2, "id": 11, "method": "xrefs_page", "params": {"program": "$PROGRAM", "address": "00400466", "evidence": "declared", "offset": 0, "limit": 8}}
{"api": 2, "id": 11, "result": {"offset": 0, "total": 2}}
{"api": 2, "id": 12, "method": "xrefs_page", "params": {"program": "$PROGRAM", "address": "00400466", "evidence": "probably"}}
{"api": 2, "id": 12, "error": {"code": "invalid_params", "message": "request: params.evidence must be declared, decoded or inferred, not \"probably\""}}
```

## What needs the SLEIGH console

`xrefs` answers from the store, and the store holds more when the SLEIGH
console proved more: the call into `add` is a flow fact, while the reference
from the unwind tables is a loader fact. `decompile_doc` needs the console
outright. Both still start no JVM.

The `function` field names the function whose body contains the *source*
address, and is null when no function does — a reference from data has no
containing function.

<!-- requires: sleigh -->

```json
{"api": 2, "id": 9, "method": "xrefs", "params": {"program": "$PROGRAM", "address": "00400466"}}
{"api": 2, "id": 9, "result": [{"from": {"space": "Ram", "offset": 4195464}, "function": "main", "kind": "UNCONDITIONAL_CALL", "provenance": {"kind": "inferred", "source": "native-import"}}, {"from": {"space": "Ram", "offset": 4198824}, "function": null, "kind": "DATA", "provenance": {"kind": "inferred", "source": "native-import:elf-unwind"}}]}
{"api": 2, "id": 10, "method": "decompile_doc", "params": {"program": "$PROGRAM", "binary": "$BINARY", "address": "00400466"}}
{"api": 2, "id": 10, "result": {"address": {"space": "Ram", "offset": 4195430}, "prototype": {"calling_convention": "__stdcall", "no_return": false}, "jump_tables": []}}
```

`decompile_doc` returns the structured document — tokens with their kinds, the
recovered prototype, jump tables and storage — rather than a string, so a UI
can render and a script can inspect without re-parsing C.

## A project holds more than one image

A Nintendo DS cartridge is two CPU images; an executable can have overlays.
`programs` lists what a project holds, and `locate` answers the question an
address alone cannot -- **which** image maps it -- because images overlap: a
stripped `tiny_pe32.exe` and `tiny_bin` both start at `0x400000`.

```json
{"api": 2, "id": 13, "method": "programs"}
{"api": 2, "id": 13, "result": [{"program": "tiny", "language": "x86:LE:64:default"}]}
{"api": 2, "id": 14, "method": "locate", "params": {"address": "00400466"}}
{"api": 2, "id": 14, "result": [{"program": "tiny", "function": "add"}]}
```

Each row names the region that maps the address and the function containing
it, or `null` when no function does. A read still answers for one `program`:
sharing a project changes no answer.

## Every method

`ping`, `architectures`, `programs`, `locate`, `open`, `import_native`, `functions`,
`functions_page`, `symbols`, `symbols_page`, `xrefs`, `xrefs_page`,
`comments`, `comment`, `datatypes`, `type_defs`, `type_fields`, `type_graph`,
`propagate_type_links`, `strings`, `search`, `function_graph`,
`memory_regions`, `memory`, `memory_live`, `listing`, `disasm_native`,
`decompile_doc`, `prototypes`, `infer_prototypes`, `stack_variables`,
`return_behaviors`, `infer_nonreturning`, `thunks`, `classes`,
`recover_classes`, `signature_matches`, `apply_signatures`, `rename`, `undo`,
`bookmarks`, `set_bookmark`, `patches`, `set_patch`, `jobs_page`,
`trace_events`, `append_trace_event`, `collab_ops`, `append_collab_op`,
`apply_collab_op`, `events_since`, `debug_backtrace`, `debug_registers`,
`debug_memory`.

Requests that read take a `program`; requests that decode or decompile also
take the `binary` they were imported from.
