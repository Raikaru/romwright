# Scripting Romwright

`python/romwright_sdk.py` is a dependency-free client for the Core API. It
speaks the envelope documented in `docs/core-api.md` over either the local
`romwright-api` process or an HTTP `/v2` endpoint, and it keeps no second model of
the program: what it returns is what the store answered.

Every command and output line on this page is executed by
`tests/m6-005_scripting.py`.

## The client

```python
from romwright_sdk import Client

with Client.stdio("/path/to/project") as client:      # spawns romwright-api
    client.import_native("/bin/ls", "ls")
    rows = client.functions("ls")

with Client.http("http://127.0.0.1:8377") as client:  # an already-running service
    client.ping()
```

`Client.stdio(project, executable="romwright-api")` starts the service and closes it
on exit. `client.request(method, **params)` reaches any method the API
dispatches, so the client never limits what a script can do, and these named
helpers cover the common work:

| Group | Helpers |
|---|---|
| service | `ping`, `open`, `import_native` |
| reads | `functions`, `symbols`, `xrefs`, `strings`, `search` |
| code | `decompile` |
| annotation | `comment` |
| types | `types`, `type_fields`, `type_graph` |
| tracing | `trace_events`, `append_trace_event` |
| collaboration | `collaboration_ops`, `append_collaboration_op`, `apply_collaboration_op` |
| debugging | `debug_backtrace`, `debug_registers`, `debug_memory` |

The gate for this page fails if the client grows a helper the table omits, so
the list cannot fall behind the client.

Errors arrive as `ApiError` with the API's own `code` and `message`, so a
script can tell `invalid_params` from `core_error` without parsing prose.

## A script end to end

`examples/facts_report.py` imports a binary, reads its functions, writes one
fact and reverses it:

```console
$ python3 examples/facts_report.py --project $PROJECT --binary tests/fixtures-src/tiny_bin
add at 00400466 (20 bytes)
00400488 is inside main
renamed 00400466 -> demo_add
undid rename seq 1 (00400466 -> add)
```

Three things in that script are worth copying.

**Addresses are typed.** A response carries `{"space": "Ram", "offset": …}`,
never a bare integer, so the script's `offset()` helper unpacks the space it
was given instead of assuming one.

**The containing function is computed, not requested.** The script walks the
function extents itself. The store answers with what it proved; deciding that
`00400488` belongs to `main` is the consumer's step, and a script that wants a
different rule can apply one.

**Edits are journalled.** `rename` returns the fact it wrote and `undo`
reverses the last command, so a script that changes a project can undo its own
work — the same journal the desktop and the CLI use.

## Which parts need the SLEIGH console

Reads of the store need nothing beyond the built binaries. `decompile`,
`disasm_native` and `listing` need SLEIGH language data from the pinned Ghidra
install, exactly as they do on the command line (`docs/getting-started.md`).
The script above runs either way; only the number of functions the import
proves differs.
