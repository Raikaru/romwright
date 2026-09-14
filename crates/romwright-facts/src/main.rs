//! romwright-facts server: hosts the shared fact store over TCP.
//!
//! Usage: `romwright-facts --db PATH [--listen HOST:PORT]`
//!   --db       SQLite file for the durable store (required)
//!   --listen   address to serve JSON-line requests on (default 127.0.0.1:28090)
//!
//! One request per connection, one JSON object per line:
//!   {"method":"push_facts","params":{"bundle":{…}}}
//!   {"method":"pull_facts","params":{"binary_sha256":"…","signatures":["…"]}}

use romwright_facts::{serve_tcp, FactStore};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::Mutex;

fn main() {
    let mut args = std::env::args().skip(1);
    let mut db = None;
    let mut listen = "127.0.0.1:28090".to_string();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--db" => db = args.next().map(PathBuf::from),
            "--listen" | "-l" => listen = args.next().unwrap_or(listen),
            "--help" | "-h" => {
                eprintln!("usage: romwright-facts --db PATH [--listen HOST:PORT]");
                return;
            }
            other => {
                eprintln!("romwright-facts: unknown argument {other}");
                std::process::exit(2);
            }
        }
    }
    let Some(db) = db else {
        eprintln!("romwright-facts: --db PATH is required");
        std::process::exit(2);
    };
    let store = FactStore::open(&db).unwrap_or_else(|e| {
        eprintln!("romwright-facts: cannot open {db:?}: {e}");
        std::process::exit(1);
    });
    let listener = TcpListener::bind(&listen).unwrap_or_else(|e| {
        eprintln!("romwright-facts: cannot listen on {listen}: {e}");
        std::process::exit(1);
    });
    eprintln!("romwright-facts listening on {listen} (db {db:?})");
    if let Err(e) = serve_tcp(&Mutex::new(store), listener) {
        eprintln!("romwright-facts: {e}");
        std::process::exit(1);
    }
}
