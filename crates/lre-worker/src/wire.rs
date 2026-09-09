//! Wire framing for the pinned `ghidra_opt` protocol.
//!
//! Two layers, both transcribed from the pinned C++ (third_party/ghidra/
//! decompiler/): burst framing from ghidra_arch.cc (comment block above
//! `readToAnyBurst`), and the packed element encoding from marshal.hh
//! (`PackedFormat` namespace constants). A mismatch here is a hung worker,
//! so every constant cites its source line semantics.

/// Header-mask comparisons for provider.rs (PackedFormat constants).
pub const HEADER_MASK_EQ: u8 = 0xc0;
pub const ELEMENT_START_EQ: u8 = 0x40;
pub const ELEMENT_END_EQ: u8 = 0x80;
pub const ATTRIBUTE_EQ: u8 = 0xc0;

/// Burst codes (ghidra_arch.cc: open alignment is even, close is odd).
pub mod burst {
    /// Command stream from the client (us) to the decompiler.
    pub const COMMAND_OPEN: u8 = 0x02;
    /// Command stream terminator.
    pub const COMMAND_CLOSE: u8 = 0x03;
    /// Query issued by the decompiler mid-command; we must answer.
    pub const QUERY_OPEN: u8 = 0x04;
    /// Query terminator.
    pub const QUERY_CLOSE: u8 = 0x05;
    /// Our answer to a decompiler command (e.g. registerProgram).
    pub const RESPONSE_OPEN: u8 = 0x06;
    /// Command-response terminator.
    pub const RESPONSE_CLOSE: u8 = 0x07;
    /// The decompiler's answer to our query.
    pub const QRESPONSE_OPEN: u8 = 0x08;
    /// Query-response terminator.
    pub const QRESPONSE_CLOSE: u8 = 0x09;
    /// Exception from either side; cancels the current command.
    pub const EXCEP_OPEN: u8 = 0x0a;
    /// Exception terminator.
    pub const EXCEP_CLOSE: u8 = 0x0b;
    /// Raw byte stream (e.g. getBytes payload in hex-ish 'A'-biased form).
    pub const BYTESTREAM_OPEN: u8 = 0x0c;
    /// Byte-stream terminator.
    pub const BYTESTREAM_CLOSE: u8 = 0x0d;
    /// UTF-8 string stream (most parameters and results).
    pub const STRINGSTREAM_OPEN: u8 = 0x0e;
    /// String-stream terminator.
    pub const STRINGSTREAM_CLOSE: u8 = 0x0f;
}

/// A burst is one or more NUL bytes, then 0x01, then the code byte.
pub fn encode_burst(out: &mut Vec<u8>, code: u8) {
    out.push(0);
    out.push(0);
    out.push(0x01);
    out.push(code);
}

/// Reads one burst from `data` at `*pos`, returning the code byte.
/// Returns `None` at end-of-input (peer closed the pipe).
pub fn decode_burst(data: &[u8], pos: &mut usize) -> Option<u8> {
    loop {
        if *pos >= data.len() {
            return None;
        }
        let b = data[*pos];
        *pos += 1;
        match b {
            0 => continue, // alignment
            0x01 => {
                // code follows
                if *pos >= data.len() {
                    return None;
                }
                let code = data[*pos];
                *pos += 1;
                return Some(code);
            }
            _ => return Some(b), // lenient: some peers emit bare codes
        }
    }
}

/// Wraps `payload` in a string stream (open code, bytes, close code).
pub fn encode_string_stream(out: &mut Vec<u8>, payload: &[u8]) {
    encode_burst(out, burst::STRINGSTREAM_OPEN);
    out.extend_from_slice(payload);
    encode_burst(out, burst::STRINGSTREAM_CLOSE);
}

/// Encodes getStringData as consumed by ghidra_arch.cc:774-816. Character
/// limits follow DecompileCallback.StringData's UTF-16 code-unit count,
/// including Java's `?` replacement when the limit splits a surrogate pair.
pub fn encode_string_data_response(out: &mut Vec<u8>, value: Option<&str>, max_chars: usize) {
    let Some(value) = value else {
        out.reserve(8);
        encode_burst(out, burst::QRESPONSE_OPEN);
        encode_burst(out, burst::QRESPONSE_CLOSE);
        return;
    };
    // The two six-bit length fields must also fit the trailing NUL.
    const MAX_UTF8_BYTES: usize = (1 << 12) - 2;
    let mut end = 0;
    let mut units = 0;
    let mut replacement = false;
    for ch in value.chars() {
        if units + ch.len_utf16() > max_chars {
            replacement = units < max_chars && end < MAX_UTF8_BYTES;
            break;
        }
        if end + ch.len_utf8() > MAX_UTF8_BYTES {
            break;
        }
        units += ch.len_utf16();
        end += ch.len_utf8();
    }
    let size = end + usize::from(replacement) + 1;
    out.reserve(19 + size * 2);
    encode_burst(out, burst::QRESPONSE_OPEN);
    encode_burst(out, burst::BYTESTREAM_OPEN);
    out.extend_from_slice(&[
        ((size & 0x3f) + 0x20) as u8,
        (((size >> 6) & 0x3f) + 0x20) as u8,
        u8::from(end < value.len()),
    ]);
    for byte in value.as_bytes()[..end]
        .iter()
        .copied()
        .chain(replacement.then_some(b'?'))
        .chain(std::iter::once(0))
    {
        out.extend_from_slice(&[(byte >> 4) + b'A', (byte & 0xf) + b'A']);
    }
    encode_burst(out, burst::BYTESTREAM_CLOSE);
    encode_burst(out, burst::QRESPONSE_CLOSE);
}

// ---- Packed element encoding (marshal.hh PackedFormat) --------------------

/// Element-start header with a 5-bit id and no extension bit set.
pub const ELEMENT_START: u8 = 0x40;
/// Element-end header.
pub const ELEMENT_END: u8 = 0x80;
/// Attribute header.
pub const ATTRIBUTE: u8 = 0xc0;
// ---- Element/attribute ids (pinned from the C++ tables) -------------------
// marshal.cc:1264-1265 register ELEM_DATA/ELEM_INPUT; the ids below are the
// ones the protocol paths actually use, each cited to its defining file.
pub mod elem {
    /// ELEM_SET (globalcontext.cc:24): one tracked register value.
    pub const SET: u32 = 124;
    /// ELEM_VOID (marshal.cc:1273).
    pub const VOID: u32 = 10;
    /// ELEM_INJECT (pcodeinject.cc:34).
    pub const INJECT: u32 = 96;
    /// ELEM_PROTOTYPE and ELEM_RETURNSYM (fspec.cc:47,50).
    pub const PROTOTYPE: u32 = 169;
    pub const RETURNSYM: u32 = 172;
    /// ELEM_ADDR (address.cc:25)
    pub const ADDR: u32 = 11;
    /// ELEM_RANGELIST (address.cc:27)
    pub const RANGELIST: u32 = 13;
    /// ELEM_SYMBOL (marshal.cc type table)
    pub const SYMBOL: u32 = 6;
    /// ELEM_FUNCTIONSHELL (database.cc:34)
    pub const FUNCTIONSHELL: u32 = 72;
    /// ELEM_OVERRIDE (override.cc:26).
    pub const OVERRIDE: u32 = 223;
    /// ELEM_FLOW (override.cc:22).
    pub const FLOW: u32 = 219;
    /// ELEM_LABELSYM (database.cc:37).
    pub const LABELSYM: u32 = 75;
    /// ELEM_MAPSYM (database.cc:38)
    pub const MAPSYM: u32 = 76;
    /// ELEM_FUNCTION (funcdata.cc:23)
    pub const FUNCTION: u32 = 116;
    /// ELEM_DOC (ghidra_process.cc:73).
    pub const DOC: u32 = 229;
    /// ELEM_TRACKED_POINTSET (globalcontext.cc:25).
    pub const TRACKED_POINTSET: u32 = 125;
    /// ELEM_HOLE (database.cc:36).
    pub const HOLE: u32 = 74;
    /// ELEM_PARENT (database.cc:39).
    pub const PARENT: u32 = 77;
    /// `<val>` (marshal.cc: shared vocabulary), a namespace path component.
    pub const VAL: u32 = 8;
    /// ELEM_EXTERNREFSYMBOL (database.cc:32).
    pub const EXTERNREFSYMBOL: u32 = 70;
    /// ELEM_COMMENT (comment.cc:21).
    pub const COMMENT: u32 = 86;
    /// ELEM_COMMENTDB (comment.cc:22).
    pub const COMMENTDB: u32 = 87;
    /// ELEM_TEXT (comment.cc:23).
    pub const TEXT: u32 = 88;
    /// ELEM_TYPE (type.cc:67).
    pub const TYPE: u32 = 60;
    /// ELEM_TYPEREF (type.cc:70).
    pub const TYPEREF: u32 = 63;
}

pub mod attr {
    /// ATTRIB_VAL (marshal.cc:1255): a tracked register's value.
    pub const TRACKED_VALUE: u32 = 24;
    /// ATTRIB_CONTENT (marshal.cc:1232).
    pub const CONTENT: u32 = 1;
    /// ATTRIB_ID (marshal.cc:1240).
    pub const ID: u32 = 9;
    /// ATTRIB_NAME (marshal.cc:1245).
    pub const NAME: u32 = 14;
    /// ATTRIB_LABEL (jumptable.cc:23; shared marshaling id).
    pub const LABEL: u32 = 131;
    /// ATTRIB_OFFSET (marshal.cc:1247).
    pub const OFFSET: u32 = 16;
    /// ATTRIB_SIZE (marshal.cc:1252).
    pub const SIZE: u32 = 19;
    /// ATTRIB_SPACE (marshal.cc:1253).
    pub const SPACE: u32 = 20;
    /// ATTRIB_READONLY (marshal.cc:1248).
    pub const READONLY: u32 = 17;
    /// ATTRIB_ARRAYSIZE (type.cc:30).
    pub const ARRAYSIZE: u32 = 48;
    /// ATTRIB_NAMELOCK (marshal.cc:1246).
    pub const NAMELOCK: u32 = 15;
    /// ATTRIB_TYPELOCK (`AttributeId`, :79; read in database.cc:439).
    pub const TYPELOCK: u32 = 23;
    /// ATTRIB_METATYPE (marshal.cc:1243).
    pub const METATYPE: u32 = 12;
    /// ATTRIB_TYPE (marshal.cc:1253).
    pub const TYPE: u32 = 22;
    /// ATTRIB_FIRST (address.cc:21).
    pub const FIRST: u32 = 27;
    /// ATTRIB_LAST (address.cc:22).
    pub const LAST: u32 = 28;
    /// ATTRIB_MAXSIZE (fspec.cc:27).
    pub const MAXSIZE: u32 = 120;
    /// ATTRIB_MODEL (marshal.cc:1244).
    pub const MODEL: u32 = 13;
    /// ATTRIB_MODELLOCK (fspec.cc:29).
    pub const MODELLOCK: u32 = 122;
    /// ATTRIB_NORETURN (fspec.cc:30).
    pub const NORETURN: u32 = 123;
}

/// Query element ids (ghidra_arch.cc:30-48); these are what the decompiler
/// puts at the root of an interleaved query's packed payload.
pub mod query {
    pub const ISNAMEUSED: u32 = 239;
    pub const GETBYTES: u32 = 240;
    pub const GETCALLFIXUP: u32 = 241;
    pub const GETCALLMECH: u32 = 242;
    pub const GETCALLOTHERFIXUP: u32 = 243;
    pub const GETCODELABEL: u32 = 244;
    pub const GETCOMMENTS: u32 = 245;
    pub const GETCPOOLREF: u32 = 246;
    pub const GETDATATYPE: u32 = 247;
    pub const GETEXTERNALREF: u32 = 248;
    pub const GETMAPPEDSYMBOLS: u32 = 249;
    pub const GETNAMESPACEPATH: u32 = 250;
    pub const GETPCODE: u32 = 251;
    pub const GETPCODEEXECUTABLE: u32 = 252;
    pub const GETREGISTER: u32 = 253;
    pub const GETREGISTERNAME: u32 = 254;
    pub const GETSTRINGDATA: u32 = 255;
    pub const GETTRACKEDREGISTERS: u32 = 256;
    pub const GETUSEROPNAME: u32 = 257;
}

/// Follow-on bytes have bit 0x80 set, 7 bits of payload.
pub const RAWDATA_MARKER: u8 = 0x80;

/// Attribute type codes (marshal.hh).
pub mod attr_type {
    /// Boolean, lengthcode 0=false 1=true, no integer payload.
    pub const BOOLEAN: u8 = 1;
    /// Positive signed integer.
    pub const POSITIVE_INT: u8 = 2;
    /// Negative signed integer (negated form).
    pub const NEGATIVE_INT: u8 = 3;
    /// Unsigned integer.
    pub const UNSIGNED_INT: u8 = 4;
    /// Address space, encoded as its index.
    pub const SPACE: u8 = 5;
    /// String; integer payload is the byte length.
    pub const STRING: u8 = 7;
}

/// Encodes a 7-bit-per-byte integer, matching PackedEncode::encodeLength.
/// Zero emits a single type-byte with lengthcode 0.
pub fn encode_packed_int(out: &mut Vec<u8>, value: u64) {
    if value == 0 {
        return; // lengthcode 0 handled by the caller's type byte
    }
    // Ground truth (PackedEncode::encodeLength, marshal.cc): every 7-bit
    // group carries RAWDATA_MARKER, written most-significant group first.
    let mut sa = 63 - value.leading_zeros(); // highest set bit index
    sa -= sa % 7; // align to a group boundary
    while sa > 0 {
        let piece = ((value >> sa) & 0x7f) as u8 | RAWDATA_MARKER;
        out.push(piece);
        sa -= 7;
    }
    out.push(((value & 0x7f) as u8) | RAWDATA_MARKER);
}

/// Writes a packed element/attribute header per PackedEncode::writeHeader
/// (marshal.hh:661): ids <= 0x1f are one byte `base|id`; larger ids get the
/// extension bit plus `id>>7` in the header and one follow-on byte.
pub fn encode_header(out: &mut Vec<u8>, base: u8, id: u32) {
    if id > 0x1f {
        out.push(base | 0x20 | ((id >> 7) & 0x1f) as u8);
        out.push(0x80 | (id & 0x7f) as u8);
    } else {
        out.push(base | id as u8);
    }
}

/// Writes one attribute with a scalar integer value: header, type byte with
/// the group count, then the 7-bit groups (most significant first).
pub fn encode_attribute(out: &mut Vec<u8>, id: u32, type_code: u8, value: u64) {
    encode_header(out, ATTRIBUTE, id);
    let mut groups = Vec::new();
    encode_packed_int(&mut groups, value);
    out.push((type_code << 4) | groups.len() as u8);
    out.extend_from_slice(&groups);
}

/// Writes a string attribute (type 7): length-count groups + raw bytes.
pub fn encode_string_attribute(out: &mut Vec<u8>, id: u32, value: &[u8]) {
    encode_header(out, ATTRIBUTE, id);
    let mut groups = Vec::new();
    encode_packed_int(&mut groups, value.len() as u64);
    out.push((attr_type::STRING << 4) | groups.len() as u8);
    out.extend_from_slice(&groups);
    out.extend_from_slice(value);
}

/// Encodes a plain `<addr>` (ELEM_ADDR + space/offset), matching
/// AddressXML.encode(encoder, addr): NO size attribute.
pub fn encode_addr_element(out: &mut Vec<u8>, space_index: u32, offset: u64) {
    encode_header(out, ELEMENT_START, elem::ADDR);
    encode_attribute(out, attr::SPACE, attr_type::SPACE, space_index as u64);
    encode_attribute(out, attr::OFFSET, attr_type::UNSIGNED_INT, offset);
    encode_header(out, ELEMENT_END, elem::ADDR);
}

/// Encodes a `<addr>` with a size attribute (AddressXML.encode(addr, size)),
/// used for getregister answers and function storage entries. Size is a
/// signed integer (writeSignedInteger; positive values use type 2).
pub fn encode_addr_element_size(out: &mut Vec<u8>, space_index: u32, offset: u64, size: u64) {
    encode_header(out, ELEMENT_START, elem::ADDR);
    encode_attribute(out, attr::SPACE, attr_type::SPACE, space_index as u64);
    encode_attribute(out, attr::OFFSET, attr_type::UNSIGNED_INT, offset);
    encode_attribute(out, attr::SIZE, attr_type::POSITIVE_INT, size);
    encode_header(out, ELEMENT_END, elem::ADDR);
}

/// Full function metadata for callbacks and non-returning preload entries.
/// Funcdata::decode requires a unique nonzero local scope id. FuncProto::decode
/// requires a returnsym; the unlocked void output leaves type recovery enabled.
pub(crate) fn encode_function_element(
    out: &mut Vec<u8>,
    space: u32,
    scope_id: u64,
    address: u64,
    name: &str,
    size: u64,
    no_return: bool,
    convention: Option<&str>,
    fixup: Option<&str>,
    call_return_branches: &[u64],
) {
    encode_header(out, ELEMENT_START, elem::FUNCTION);
    encode_attribute(out, attr::ID, attr_type::UNSIGNED_INT, scope_id);
    encode_string_attribute(out, attr::NAME, name.as_bytes());
    encode_attribute(out, attr::SIZE, attr_type::POSITIVE_INT, size);
    encode_addr_element(out, space, address);
    encode_flow_override(out, space, call_return_branches);
    if no_return || convention.is_some() || fixup.is_some() {
        encode_header(out, ELEMENT_START, elem::PROTOTYPE);
        // A named model, locked: Ghidra's own encoder locks the model whenever
        // the name is known and not "unknown"
        // (`FunctionPrototype.grabFromFunction`, :135-136). Without the lock
        // the decompiler is free to reconsider the convention it was told.
        if let Some(model) = convention {
            encode_string_attribute(out, attr::MODEL, model.as_bytes());
            encode_header(out, ATTRIBUTE, attr::MODELLOCK);
            out.push((attr_type::BOOLEAN << 4) | 1);
        }
        // PackedEncode::writeBool (marshal.cc:1147): value is in the type byte.
        if no_return {
            encode_header(out, ATTRIBUTE, attr::NORETURN);
            out.push((attr_type::BOOLEAN << 4) | 1);
        }
        encode_header(out, ELEMENT_START, elem::RETURNSYM);
        encode_header(out, ELEMENT_START, elem::ADDR);
        encode_header(out, ELEMENT_END, elem::ADDR);
        encode_header(out, ELEMENT_START, elem::VOID);
        encode_header(out, ELEMENT_END, elem::VOID);
        encode_header(out, ELEMENT_END, elem::RETURNSYM);
        // A call fixup names p-code the compiler spec carries; the decompiler
        // resolves the name against its own inject library and inlines it
        // (`FuncProto::decode`, fspec.cc:4814-4819).
        if let Some(name) = fixup {
            encode_header(out, ELEMENT_START, elem::INJECT);
            encode_string_attribute(out, attr::CONTENT, name.as_bytes());
            encode_header(out, ELEMENT_END, elem::INJECT);
        }
        encode_header(out, ELEMENT_END, elem::PROTOTYPE);
    }
    encode_header(out, ELEMENT_END, elem::FUNCTION);
}

/// A named location the store holds a fact for, in the shape
/// `Scope::addMapSym` accepts: `<mapsym><symbol …><type …/></symbol><addr/>
/// <rangelist/></mapsym>` (database.cc:1564-1606, SymbolEntry::decode:206).
/// The symbol's type is written by `body`, which must emit exactly one type
/// element (`TypeFactory::decodeType`, type.cc:4638).
pub(crate) fn encode_data_symbol(
    out: &mut Vec<u8>,
    space: u32,
    address: u64,
    name: &str,
    read_only: bool,
    body: impl FnOnce(&mut Vec<u8>),
) {
    encode_header(out, ELEMENT_START, elem::MAPSYM);
    encode_header(out, ELEMENT_START, elem::SYMBOL);
    encode_attribute(out, attr::ID, attr_type::UNSIGNED_INT, 0);
    encode_string_attribute(out, attr::NAME, name.as_bytes());
    // Both the name and the type are the store's facts, and stock locks both
    // on every mapped data symbol it answers with
    // (`HighCodeSymbol`, :41-46: `setNameLock(true)`, `setTypeLock(true)`;
    // read in `Symbol::decodeHeader`, database.cc:394-434). Without the type
    // lock the decompiler retypes the symbol and drops the cast stock prints.
    encode_header(out, ATTRIBUTE, attr::NAMELOCK);
    out.push((attr_type::BOOLEAN << 4) | 1);
    encode_header(out, ATTRIBUTE, attr::TYPELOCK);
    out.push((attr_type::BOOLEAN << 4) | 1);
    if read_only {
        // `Varnode::readonly`, which is what lets the printer render a string
        // constant instead of the symbol that names it
        // (`PrintC::printCharacterConstant` requires `Scope::isReadOnly`,
        // printc.cc:1772; the attribute is read in database.cc:435).
        encode_header(out, ATTRIBUTE, attr::READONLY);
        out.push((attr_type::BOOLEAN << 4) | 1);
    }
    body(out);
    encode_header(out, ELEMENT_END, elem::SYMBOL);
    encode_addr_element(out, space, address);
    encode_header(out, ELEMENT_START, elem::RANGELIST);
    encode_header(out, ELEMENT_END, elem::RANGELIST);
    encode_header(out, ELEMENT_END, elem::MAPSYM);
}

/// Flow the store proves and the raw disassembly cannot see: a branch that
/// transfers control the way a call does. The shape is the `<override>` child
/// `Funcdata::decode` accepts (funcdata.cc:811) carrying `<flow>` elements
/// (`Override::decode`, override.cc:356-400); `callreturn` is the type name
/// `Override::stringToType` maps to `CALL_RETURN` (:421-433).
pub(crate) fn encode_flow_override(out: &mut Vec<u8>, space: u32, branches: &[u64]) {
    if branches.is_empty() {
        return;
    }
    encode_header(out, ELEMENT_START, elem::OVERRIDE);
    for branch in branches {
        encode_header(out, ELEMENT_START, elem::FLOW);
        encode_string_attribute(out, attr::TYPE, b"callreturn");
        encode_addr_element(out, space, *branch);
        encode_header(out, ELEMENT_END, elem::FLOW);
    }
    encode_header(out, ELEMENT_END, elem::OVERRIDE);
}

/// A name for a location the store holds no type for: `<labelsym>`, which the
/// C++ decodes into a `LabSymbol` -- one byte of `TYPE_UNKNOWN`
/// (database.cc:728-757), the same shape Ghidra's own `encodeLabel` sends for
/// a symbol that is not data (DecompileCallback.java:872-876).
/// `<parent>`: the formal path from the global scope down to one namespace,
/// as `HighFunction.encodeNamespace` writes it (:600-629) and
/// `Database::decodeScopePath` reads it (database.cc:3395-3425) -- an empty
/// first `<val>` for the root scope, then one `<val id=...>name</val>` per
/// component below it.
pub(crate) fn encode_namespace_path(out: &mut Vec<u8>, components: &[(u64, String)]) {
    encode_header(out, ELEMENT_START, elem::PARENT);
    encode_header(out, ELEMENT_START, elem::VAL);
    encode_header(out, ELEMENT_END, elem::VAL);
    for (id, name) in components {
        encode_header(out, ELEMENT_START, elem::VAL);
        encode_attribute(out, attr::ID, attr_type::UNSIGNED_INT, *id);
        encode_string_attribute(out, attr::CONTENT, name.as_bytes());
        encode_header(out, ELEMENT_END, elem::VAL);
    }
    encode_header(out, ELEMENT_END, elem::PARENT);
}

pub(crate) fn encode_label_symbol(out: &mut Vec<u8>, space: u32, address: u64, name: &str) {
    encode_header(out, ELEMENT_START, elem::MAPSYM);
    encode_header(out, ELEMENT_START, elem::LABELSYM);
    encode_attribute(out, attr::ID, attr_type::UNSIGNED_INT, 0);
    encode_string_attribute(out, attr::NAME, name.as_bytes());
    encode_header(out, ATTRIBUTE, attr::NAMELOCK);
    out.push((attr_type::BOOLEAN << 4) | 1);
    encode_header(out, ELEMENT_END, elem::LABELSYM);
    encode_addr_element(out, space, address);
    encode_header(out, ELEMENT_START, elem::RANGELIST);
    encode_header(out, ELEMENT_END, elem::RANGELIST);
    encode_header(out, ELEMENT_END, elem::MAPSYM);
}

/// A reference to a core type (`<typeref>`, type.cc:4643-4664). The id is
/// required: `findById` resolves by id and falls back to the name hash, which
/// never matches the ids `coretypes.xml` assigns.
pub(crate) fn encode_typeref(out: &mut Vec<u8>, name: &str, id: u64) {
    encode_header(out, ELEMENT_START, elem::TYPEREF);
    encode_attribute(out, attr::ID, attr_type::UNSIGNED_INT, id);
    encode_string_attribute(out, attr::NAME, name.as_bytes());
    encode_header(out, ELEMENT_END, elem::TYPEREF);
}

/// An array of a core type (`TypeArray::decode`, type.cc:1500-1520, which
/// requires `arraysize * element size == size`).
pub(crate) fn encode_array_type(out: &mut Vec<u8>, element: (&str, u64), count: u64) {
    encode_header(out, ELEMENT_START, elem::TYPE);
    encode_string_attribute(out, attr::NAME, b"");
    encode_string_attribute(out, attr::METATYPE, b"array");
    encode_attribute(out, attr::SIZE, attr_type::POSITIVE_INT, count);
    encode_attribute(out, attr::ARRAYSIZE, attr_type::POSITIVE_INT, count);
    encode_typeref(out, element.0, element.1);
    encode_header(out, ELEMENT_END, elem::TYPE);
}

/// A pointer to a core type (`TypePointer::decode`, type.cc).
pub(crate) fn encode_pointer_type(out: &mut Vec<u8>, target: (&str, u64), size: u64) {
    encode_pointer_to(out, size, |out| encode_typeref(out, target.0, target.1));
}

/// A pointer whose target is described rather than referenced by id.
pub(crate) fn encode_pointer_to(out: &mut Vec<u8>, size: u64, target: impl FnOnce(&mut Vec<u8>)) {
    encode_header(out, ELEMENT_START, elem::TYPE);
    encode_string_attribute(out, attr::NAME, b"");
    encode_string_attribute(out, attr::METATYPE, b"ptr");
    encode_attribute(out, attr::SIZE, attr_type::POSITIVE_INT, size);
    target(out);
    encode_header(out, ELEMENT_END, elem::TYPE);
}

/// A core type sent by description, with no id: `Datatype::decodeBasic`
/// derives `hashName(name)` itself when the id is omitted (type.cc:698-700).
/// That is how `undefined` can be named -- the decompiler registers it, size
/// 1, metatype unknown (`ArchitectureGhidra::buildTypegrp`,
/// ghidra_arch.cc:341), and no language's `coretypes.xml` declares it.
pub(crate) fn encode_basic_type(out: &mut Vec<u8>, name: &str, metatype: &str, size: u64) {
    encode_header(out, ELEMENT_START, elem::TYPE);
    encode_string_attribute(out, attr::NAME, name.as_bytes());
    encode_string_attribute(out, attr::METATYPE, metatype.as_bytes());
    encode_attribute(out, attr::SIZE, attr_type::POSITIVE_INT, size);
    encode_header(out, ELEMENT_END, elem::TYPE);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn burst_roundtrip() {
        let mut buf = Vec::new();
        encode_burst(&mut buf, burst::COMMAND_OPEN);
        buf.extend_from_slice(b"registerProgram");
        assert_eq!(buf[3], 0x02);
        let mut pos = 0;
        assert_eq!(decode_burst(&buf, &mut pos), Some(burst::COMMAND_OPEN));
    }

    #[test]
    fn decode_skips_alignment_nuls() {
        let data = [
            0u8,
            0,
            0,
            0x01,
            burst::QUERY_OPEN,
            0,
            0x01,
            burst::QUERY_CLOSE,
        ];
        let mut pos = 0;
        assert_eq!(decode_burst(&data, &mut pos), Some(burst::QUERY_OPEN));
        assert_eq!(decode_burst(&data, &mut pos), Some(burst::QUERY_CLOSE));
        assert_eq!(decode_burst(&data, &mut pos), None);
    }

    #[test]
    fn packed_int_most_significant_first() {
        // 300 = 0b10_0101100 -> groups 2, 0x2c -> 0x82, 0x2c
        let mut out = Vec::new();
        encode_packed_int(&mut out, 300);
        assert_eq!(out, vec![0x82, 0xac]);
    }

    #[test]
    fn header_extension_for_large_ids() {
        // PackedEncode::writeHeader (marshal.hh:661): id > 0x1f gets the
        // extension bit plus id>>7 in the header and one 0x80-marked byte.
        let mut out = Vec::new();
        encode_header(&mut out, ATTRIBUTE, 240);
        assert_eq!(out, vec![0xe1, 0xf0]);
        let mut out = Vec::new();
        encode_header(&mut out, ELEMENT_START, elem::DOC);
        assert_eq!(out, vec![0x61, 0xe5]);
    }

    #[test]
    fn addr_element_shape_matches_java() {
        // AddressXML.encode(encoder, addr): <addr space offset> packed.
        // Element 11; attrs SPACE(20,type 5) and OFFSET(16,type 4).
        let mut out = Vec::new();
        encode_addr_element(&mut out, 3, 0x40047a);
        assert_eq!(
            out,
            vec![
                0x4b, // element 11
                0xd4, 0x51, 0x83, // attr 20, type 5, 1 group: 3
                0xd0, 0x44, 0x82, 0x80, 0x88, 0xfa, // attr 16, type 4, 4 groups
                0x8b, // element end 11
            ]
        );
    }

    fn string_response(value: Option<&str>, limit: usize) -> Option<(String, bool)> {
        let mut frame = Vec::new();
        encode_string_data_response(&mut frame, value, limit);
        let mut pos = 0;
        assert_eq!(decode_burst(&frame, &mut pos), Some(burst::QRESPONSE_OPEN));
        let kind = decode_burst(&frame, &mut pos);
        if kind == Some(burst::QRESPONSE_CLOSE) {
            assert_eq!(pos, frame.len());
            return None;
        }
        assert_eq!(kind, Some(burst::BYTESTREAM_OPEN));
        let size = (frame[pos] - 0x20) as usize | (((frame[pos + 1] - 0x20) as usize) << 6);
        let truncated = frame[pos + 2] != 0;
        pos += 3;
        let bytes: Vec<_> = frame[pos..pos + size * 2]
            .chunks_exact(2)
            .map(|pair| ((pair[0] - b'A') << 4) | (pair[1] - b'A'))
            .collect();
        pos += size * 2;
        assert_eq!(
            decode_burst(&frame, &mut pos),
            Some(burst::BYTESTREAM_CLOSE)
        );
        assert_eq!(decode_burst(&frame, &mut pos), Some(burst::QRESPONSE_CLOSE));
        assert_eq!(pos, frame.len());
        assert_eq!(bytes.last(), Some(&0));
        Some((
            String::from_utf8(bytes[..size - 1].to_vec()).unwrap(),
            truncated,
        ))
    }

    #[test]
    fn string_response_preserves_utf8_and_java_character_limits() {
        assert_eq!(
            string_response(Some("café"), 4),
            Some(("café".into(), false))
        );
        assert_eq!(
            string_response(Some("A😀BC"), 3),
            Some(("A😀".into(), true))
        );
        assert_eq!(string_response(Some("A😀BC"), 2), Some(("A?".into(), true)));
    }

    #[test]
    fn string_response_distinguishes_absent_empty_and_zero_limit() {
        assert_eq!(string_response(None, 10), None);
        assert_eq!(string_response(Some(""), 0), Some(("".into(), false)));
        assert_eq!(string_response(Some("café"), 0), Some(("".into(), true)));
    }

    #[test]
    fn string_response_bounds_twelve_bit_length() {
        assert_eq!(
            string_response(Some(&"é".repeat(2050)), usize::MAX),
            Some(("é".repeat(2047), true))
        );
    }
}