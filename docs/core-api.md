# The Core API

`romwright-api` exposes the Core service over stdio and HTTP. The Qt bridge
and CLI dispatch the same typed Core operations. Analysis facts remain in
the project store; matching candidates and trial evidence have separate
history and do not silently become native analysis facts.

The fixed request/response exchanges below are sent to a real `romwright-api`
process by `tests/m6-002_documented_api.py`; each documented response must be a
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

`function_at` takes `program` and a RAM `address`. It checks the nearest
preceding function, returning it only if its extent contains the address,
otherwise `null`. A zero-sized function matches only its entry.
`functions_page` accepts the same optional `address`:
it finds the containing function's page under the requested filter and sort,
and returns the actual `offset`, not the caller's original offset. A missing
or filtered-out anchor returns page zero. Rows, total, anchor and revision
come from one read transaction. Entry sorting compares numeric addresses,
including addresses above 4 GiB.

`symbols_page` and `xrefs_page` also take `evidence`, one of `declared`,
`decoded` or `inferred` -- the kind each fact reports. The filter narrows the
`total` as well as the window, so an audit that wants only what the image
states does not pay for the rest, and a kind that does not exist is
`invalid_params` rather than an empty page:

```json
{"api": 2, "id": 11, "method": "xrefs_page", "params": {"program": "$PROGRAM", "address": "00400466", "evidence": "declared", "offset": 0, "limit": 8}}
{"api": 2, "id": 11, "result": {"offset": 0, "rows": [{"provenance": {"evidence": "declared"}}]}}
{"api": 2, "id": 12, "method": "xrefs_page", "params": {"program": "$PROGRAM", "address": "00400466", "evidence": "probably"}}
{"api": 2, "id": 12, "error": {"code": "invalid_params"}}
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
{"api": 2, "id": 10, "result": {"address": {"space": "Ram", "offset": 4195430}}}
```

`decompile_doc` returns the structured document — tokens with their kinds, the
recovered prototype, jump tables and storage — rather than a string, so a UI
can render and a script can inspect without re-parsing C.

Direct calls also carry `call_targets`, keyed by native operation identity.
These are callee addresses, not the address of a printed call-site token.
The source exporter uses this identity to select asserted callee declarations.

`Core::export_m2c` / CLI `export-c` retain asserted C declarators for function
definitions and referenced callees, including pointer qualifiers, typedef
spellings and nested function declarators. Generated parameter names are bound
into the declared signature; incompatible arity or malformed referenced
assertions fail export rather than silently dropping the contract. Unreferenced
assertions are not parsed. This does not certify arbitrary C frontend support
or semantic equivalence of the generated function body.

The Rust `Core::function_bb_graph(program, binary, address)` operation and Qt
bridge's `function_bb_graph` use the complete native `FunctionIr`; they require
native decompilation and have no bounded-decoder fallback. Nodes are keyed by
native block ID. Their optional addresses anchor the first retained operation,
not a machine-block extent. All native blocks and successor edges are retained,
including empty/disconnected blocks and loops.

The Qt adapter enriches its `decompile_doc` result with this `graph`, known
direct-call `call_signatures`, and an authoritative `function_entry` when the
store identifies the containing function. These are adapter fields, not new
promises for the versioned HTTP/stdio document envelope. Metadata enrichment
reuses `Core::check_execution` before publishing, rejecting expired, cancelled
or revision-stale results.

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
`function_at`, `functions_page`, `symbols`, `symbols_page`, `xrefs`, `xrefs_page`,
`comments`, `comment`, `datatypes`, `type_defs`, `type_fields`, `type_graph`,
`propagate_type_links`, `strings`, `search`, `function_graph`,
`memory_regions`, `memory`, `memory_live`, `listing`, `disasm_native`,
`decompile_doc`, `prototypes`, `infer_prototypes`, `stack_variables`,
`return_behaviors`, `infer_nonreturning`, `thunks`, `classes`,
`recover_classes`, `signature_matches`, `apply_signatures`, `rename`, `undo`,
`bookmarks`, `set_bookmark`, `patches`, `set_patch`, `jobs_page`,
`trace_events`, `append_trace_event`, `collab_ops`, `append_collab_op`,
`apply_collab_op`, `events_since`, `debug_backtrace`, `debug_registers`,
`debug_memory`, `matching_workspace`, `matching_run`, `job_submit`,
`job_status`, `job_cancel`.

Requests that read take a `program`; requests that decode or decompile also
take the `binary` they were imported from.

## Matching workspaces

The request types are in `crates/romwright-model/src/matching.rs`.
Workspace management uses `matching_workspace` with `program` and an
`operation` object. Compilation and project verification use `matching_run`
with `program`, `binary`, `budget_ms` and an `operation` object.

The following are request templates, not fixed-response examples. First
import the program, then supply user-owned source, target object and compiler:

```text
{"api":2,"id":1,"method":"matching_workspace","params":{"program":"$PROGRAM","operation":{"operation":"setup","setup":{"name":"Example","symbol":"step","source":"unit.c","files":{"unit.c":{"kind":"path","path":"$SOURCE","redistributable":false}},"target":{"kind":"path","path":"$TARGET_OBJECT","redistributable":false},"profiles":[{"name":"O2","recipe":{"compiler":"$CLANG","arguments":["-O2"],"environment":{}},"compile_arguments":["-c","{source}","-o","{output}"],"version_arguments":["--version"],"tools":{}}]}}}}
```

Use the returned `candidate.id` in place of `42`:

```text
{"api":2,"id":2,"method":"matching_run","params":{"program":"$PROGRAM","binary":"$BINARY","budget_ms":120000,"operation":{"operation":"trial","candidate":42,"profile":"O2"}}}
```

For asynchronous execution, change the method to `job_submit` and add
`"op":"matching"` to `params`. Poll `job_status` with `{"job":ID}` or cancel
with `job_cancel` and the same parameters. HTTP requests remain responsive
while a compiler runs. Stdio serves requests in order: use `job_submit`, not
a synchronous `matching_run`, when that connection must also cancel a job.
Closing stdin or an invalid-input error cancels and joins owned workers.

The CLI accepts only the inner operation object, without the API envelope:

```text
romwright-cli matching-workspace PROGRAM setup.json --project DIR
romwright-cli matching-run BINARY PROGRAM trial.json --project DIR --budget-ms 120000
```

Use `-` instead of the JSON filename to read stdin. The desktop's Matching
dock uses these same operations; see [desktop.md](desktop.md).

### Candidate and trial operations

- Workspace operations: `setup`, `list`, `show`, `update`, `candidates`,
  `candidate`, `source`, `change`, `replace`, `trials`, `checks`, `export`,
  `import`. Lists use `after` and `limit`; workspace updates require the
  observed `revision`.
- `change` creates an immutable child using `parent`, `label`, `edits` and
  optional `pins`. Every edit has `file`, UTF-8 byte `start`/exclusive `end`,
  `replacement` and `reason`. Pins inherit and relocate unless explicitly
  replaced. Overlapping protected edits are refused; old candidates remain.
- `search` takes a `request` containing `candidate`, `profile`,
  `max_compilations`, independent `alternatives` and optional `expression`
  range. Built-in literal/cast variants and selected builtin scalar-type
  variants need no LLM. Type selections replace the type itself, rather than
  inserting an expression cast into a declaration. Integer types stay in the
  integer family; `float`/`double` are compared within the floating family.
  These are hypotheses, not assumed semantic equivalents. The compilation
  budget includes the baseline; failures remain evidence, not winning trials.
- `calibrate` takes known-reference `candidates`, named `profiles` and
  `max_compilations`. Results retain per-reference evidence and ties; a
  winning score is not a universal compiler-identification claim.
- `context` takes a `request` with `candidates`, `profile`, `edits` and
  `max_compilations`. It compares unchanged and changed context per function,
  retaining improvements and regressions without publishing global types.
- `prepare_patch` takes `candidate` and `profile`; `verify_patch` takes the
  returned hash-pinned `patch` and explicit `apply` boolean.

### Exactness and provenance

| Evidence | Meaning |
|---|---|
| `similarity` | Normalized objdiff score; 100 is not whole-object equality |
| `exact_instructions` | Selected defined function's raw instruction bytes |
| `exact_relocations` | Unambiguous relocation targets, bindings, flags and addends |
| `exact_object_bytes` | Entire compiled object equals the reference bytes |
| `project_exactness` | Configured final output equals the imported program artifact |

Unknown evidence stays `null`; ambiguous symbols or implicit relocation
addends do not become guessed equality. Instruction offsets are object
offsets, not ROM addresses. A source line without a filename is only a hint.
Without a configured final output, project exactness is unknown.

Exports contain immutable candidates and complete trial/check history.
Inputs default to **not redistributable**. Tool executables are never bundled;
private bytes and their revealing logs, instructions and project snapshots
are excluded. Import requires user-owned files mapped by digest and optional
local compiler/tool paths. Imported evidence is labelled unverified until
replayed; a project is unbound unless a local `project_root` is explicitly
provided. Import does not apply patches.

### Local decomp.me scratch export

`romwright-cli export-scratch PROGRAM ADDRESS BINARY --compiler ID --c-flags FLAGS
--target-object ORIGINAL.o --out NEW_DIRECTORY --project DIR` prepares a local
multipart upload bundle. Compiler ID and flags are explicit; an empty flags
string is allowed. It never uploads or publishes anything.

- `scratch.json` contains the API's scalar fields, including `compiler_flags`,
  generated `source_code`, optional supplied `context` and `diff_label`.
- `target.o` is the original relocatable object, including its symbols and
  relocations. Send it as the multipart **file** field `target_obj`, not a
  JSON filename. `export.json` describes this split and retains source warnings.
- `source.c` includes generated declarations/helpers; `ctx.c` contains the
  optional `--context FILE` contents, otherwise it is genuinely empty.
- Without `--target-object`, one unambiguous exportable matching-workspace
  target for the selected symbol may be used. Private targets are not included
  automatically. Linked images and display disassembly are not substitutes
  for the original object.
- The output directory must be new. The object must satisfy decomp.me's
  1000-KiB upload limit and contain the selected function. Export does not
  claim that a supplied object belongs to the linked image, or that the
  selected remote compiler has compiled the source.

This replaces the former disassembly/placeholder-context payload. It follows
the upstream [scratch serializer](https://github.com/decompme/decomp.me/blob/main/backend/coreapp/serializers.py)
and [object-upload handler](https://github.com/decompme/decomp.me/blob/main/backend/coreapp/views/scratch.py).
Review source, context, target bytes and redistribution rights before any
separate publishing action.

### Real-project verification boundary

A `ProjectBinding` declares `root`, workspace-to-project `sources`, the actual
`build` command and an `objects` map from authorized symbols to output paths.
Optional `generated` paths do not exempt object changes from scope checks.
Optional `linked_output` names the final output to compare with the imported
program artifact.

On Linux, verification requires bubblewrap. It snapshots the build tree,
including ignored inputs and internal symlink targets, onto project-store
storage. Baseline and candidate both rebuild declared outputs from scratch.
The original tree remains read-only to the build; temporary files are private.
This is build isolation, **not a hostile-code security sandbox**: network
access and readable host files remain available.

Verification reports unexpected files, objects, functions and data changes.
Tool hashes, original inputs and reviewed source preimages are rechecked
before application. Only reviewed source files are published, with journalled
rollback and retained recovery preimages if concurrent edits prevent rollback.
Build outputs are never copied back. Run the project's own full link when
whole-program equality, rather than a selected object's equality, is required.
