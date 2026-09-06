# Ventris Qt UI API contract

Every `core_request` method the desktop frontend sends, in one place. The
Qt side must not call anything absent from this list; additions require a
bridge entry (`crates/lre-qt-bridge/src/lib.rs` `dispatch`) and a row here.

Wire envelope: request is `{"method": "<name>", ...params}`; the response is
`{"ok": true, "result": ...}` or `{"ok": false, "error": "<message>"}`.
Addresses arrive either as hex strings or as `{"offset": <int>}` objects
(see `json_util.h addressText`).

## Paging and revision semantics

- Paged methods (`functions_page`, `symbols_page`, `xrefs_page`) return
  `Page<T>`: `{"rows": [T], "offset": <int>, "total": <int>,
  "revision": <int>}`. `total` bounds the fetch-more loop; `revision` is
  the program's mutation epoch and changes whenever a command (rename,
  comment, patch, ...) lands. The UI displays it and refetches after
  mutations; it does not currently diff revisions.
- `decompile_doc` returns the program revision with the document; a stale
  document is detected by comparing against the current revision.
- Non-paged list methods (`strings`, `bookmarks`, `type_defs`, ...) return
  full arrays; they have no revision field and are refetched wholesale.

## Session

| Method | Request | Result |
| --- | --- | --- |
| `open` | `program` | program info |
| `import_native` | `binary`, `name` | program info |

## Functions

| Method | Request | Result |
| --- | --- | --- |
| `functions_page` | `program`, `offset`, `limit` | `Page<FunctionRow>`; row: `entry` (address), `name`, `size`, `signature` |

## Listing and decompilation

| Method | Request | Result |
| --- | --- | --- |
| `listing` | `binary`, `start`, `count` | `ListingWindow`: `rows` (`stable_id`, `address`, `kind`, `text`, `bytes`), `start`, `count`, `overscan` |
| `jobs_page` | `offset`, `limit` | `JobsPage`: `rows` (`id`, `operation`, `address?`, `state`, `detail`), `total`, `pool` (`idle_workers`, `busy_workers`, `restarts`, `memory_cap_bytes`, `memory_cap_hits`) |
| `decompile_doc` | `binary`, `program`, `address` | `DecompDoc`: `tokens` (`text`, `kind`, `color`, `symbol?`, `address?`, ...), `address`, `revision` |
| `memory` | `binary`, `address` (RAM only), `size` | `{"address", "size", "bytes_hex"}` |

## Facts

| Method | Request | Result |
| --- | --- | --- |
| `symbols_page` | `program`, `offset`, `limit` | `Page<SymbolRow>`; row: `name`, `address`, `external`, `source` |
| `strings` | `program` | `[StringRow]`: `address`, `value`, `kind` |
| `search` | `program`, `term`, `limit` | `[SearchHit]`: `address?`, `kind`, `name`, `context` |
| `xrefs_page` | `program`, `address`, `incoming`, `offset`, `limit` | `Page<XrefRow>`; row: `from`, `to`, `kind`, `function`, `provenance` |
| `memory_regions` | `program` | `[MemoryRegion]`: `name`, `start`, `size`, `permissions`, `source` |
| `function_graph` | `program` | `{"nodes": [{address, name}], "edges": [{from, to, kind}]}` |

Xref provenance is `{"kind": "inferred" | "asserted", "source": "<producer>",
"confidence": <number> | null}`. Null confidence means unknown. Replacing
analysis results does not remove assertions. These are the same row semantics
as Core API 2; the Qt bridge keeps its existing FFI request envelope.

## Commands (undoable, bump the revision)

| Method | Request | Result |
| --- | --- | --- |
| `rename` | `program`, `address`, `name` | `{"address", "name"}` |
| `comment` | `program`, `address`, `kind`, `text` | `{"address", "kind", "text"}` |
| `undo` | `program` | `{"message"}` |
| `set_patch` | `program`, `address`, `original` (bytes), `patched` (bytes), `enabled` | `{"address", "enabled"}` |

## Analyst data

| Method | Request | Result |
| --- | --- | --- |
| `bookmarks` | `program` | `[BookmarkRow]`: `address`, `label`, `comment` |
| `set_bookmark` | `program`, `bookmark {address, label, comment}` | `{"address", "label"}` |
| `patches` | `program` | `[PatchRow]`: `address`, `original`, `patched`, `enabled` |

## Trace and collaboration (experimental docks)

`trace_events`, `collab_ops`, `append_collab_op`, and `apply_collab_op`
are not called from main: the Trace timeline and Collaboration docks
live on the `surfaces/experimental` branch and return only with a user
story and a phase of their own. The bridge methods remain available.

## Types

| Method | Request | Result |
| --- | --- | --- |
| `type_defs` | `program` | `[TypeDefRow]`: `name`, `kind`, `definition`, `size?`, `alignment?`, `base_type?`, `provenance`, `primitive?`, `element_count?` |
| `type_fields` | `program` | `[TypeFieldRow]`: `type_name`, `ordinal`, `field_name`, `offset`, `size?`, `type_ref?` |
| `prototypes` | `program` | `[PrototypeRow]`: `function`, `signature`, `calling_convention?`, `return_type?`, `provenance` |
| `stack_variables` | `program` | `[StackVariableRow]`: `function`, `ordinal`, `name`, `storage`, `type_name?`, `offset?`, `size?` |
| `type_graph` | `program` | `{"nodes": [{name, kind, size?}], "edges": [{source, target, kind, provenance}]}` |
| `set_type_def` | `program`, `row` (TypeDefRow) | `{"name"}` |
| `set_type_field` | `program`, `row` (TypeFieldRow) | `{"type_name", "ordinal"}` |
| `set_prototype` | `program`, `row` (PrototypeRow) | `{"function"}` |
| `replace_prototypes` | `program`, `rows` ([PrototypeRow]) | `{"count"}` (input rows; existing assertions are retained) |
| `set_stack_variable` | `program`, `row` (StackVariableRow) | `{"function", "ordinal"}` |
| `propagate_type_links` | `program` | `[TypeLinkRow]`: `source`, `target`, `kind`, `provenance` |

`primitive` is `signed_integer`, `unsigned_integer`, `float`, `boolean`, or
`void`; `null` means unclassified. Array `element_count` is a nonnegative
integer or `null` for unknown; zero is not treated as missing.

Prototype `provenance` is `{"kind": "asserted" | "inferred", "source": string,
"confidence": number | null}`. Confidence must be finite and within `[0, 1]`;
inferences require a nonempty source. Missing legacy provenance remains an
assertion of unknown origin/confidence. Inference cannot overwrite an existing
assertion. Desktop prototype edits explicitly record source `ui` and asserted
ownership without inventing a confidence.
