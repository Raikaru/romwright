//! Numeric evidence shared by pre-SSA analysis and normalized FunctionIR.
//! Unknown is real information; conflicting signedness is not a guessed sign.
/// What one operand can be, as a class an inference can be scored on.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum Class {
    /// No operation constrained it.
    Unknown,
    /// A value of this width whose kind nothing proved — a `LOAD`'s result
    /// before any use classifies it. Ghidra spells this `undefined<N>`;
    /// carrying the width keeps a loaded return from reporting `unknown`.
    Opaque(u32),
    /// A number of this width, with no evidence of sign.
    Num(u32),
    Int(u32),
    Uint(u32),
    /// An integer of this width read as both signed and unsigned — the join
    /// of `Int` and `Uint`, which disagree only about sign. It sits above
    /// both and below `Top`, so `join` stays a least upper bound. `Num`
    /// cannot be that join: it is also the weak evidence `Int`/`Uint`
    /// refine, and one element cannot be both below and above them — that
    /// double role is what made `join` non-associative and the solver's
    /// fixpoint non-terminating.
    IntOrUint(u32),
    Float(u32),
    /// A pointer to data.
    Ptr,
    /// A pointer to code, which an indirect call proves.
    Code,
    /// Two facts that cannot both hold.
    Top,
}

impl Default for Class {
    fn default() -> Self {
        Class::Unknown
    }
}

impl Class {
    /// The name the DWARF truth uses, so the two are directly comparable.
    pub fn name(self) -> String {
        match self {
            Class::Unknown => "unknown".into(),
            Class::Opaque(bits) => format!("opaque{bits}"),
            Class::Num(bits) => format!("num{bits}"),
            Class::Int(bits) => format!("int{bits}"),
            Class::Uint(bits) => format!("uint{bits}"),
            Class::IntOrUint(bits) => format!("int-or-uint{bits}"),
            Class::Float(bits) => format!("float{bits}"),
            Class::Ptr => "ptr".into(),
            Class::Code => "code".into(),
            Class::Top => "top".into(),
        }
    }

    /// The bit width a sized class carries; pointer-ish and unknown
    /// classes have no meaningful width, so they report a word.
    pub fn width(self) -> u32 {
        match self {
            Class::Opaque(b)
            | Class::Num(b)
            | Class::Int(b)
            | Class::Uint(b)
            | Class::IntOrUint(b)
            | Class::Float(b) => b,
            _ => 64,
        }
    }

    /// The C type a prototype renders. `num`, `opaque`, and `int-or-uint`
    /// carry no proven sign, so they take C's default — `int` and its width
    /// siblings — which is what Ghidra prints for the same unproven slot.
    /// The analysis fact stays honest; this is only how it is spelled for a
    /// reader.
    pub fn c_name(self) -> String {
        match self {
            Class::Unknown => "int".into(),
            Class::Opaque(8) | Class::Num(8) | Class::IntOrUint(8) => "char".into(),
            Class::Int(8) => "signed char".into(),
            Class::Opaque(16) | Class::Num(16) | Class::Int(16) | Class::IntOrUint(16) => {
                "short".into()
            }
            Class::Opaque(64) | Class::Num(64) | Class::Int(64) | Class::IntOrUint(64) => {
                "long long".into()
            }
            Class::Opaque(_) | Class::Num(_) | Class::Int(_) | Class::IntOrUint(_) => "int".into(),
            Class::Uint(8) => "unsigned char".into(),
            Class::Uint(16) => "unsigned short".into(),
            Class::Uint(64) => "unsigned long long".into(),
            Class::Uint(_) => "unsigned int".into(),
            Class::Float(64) => "double".into(),
            Class::Float(_) => "float".into(),
            Class::Ptr | Class::Code => "void *".into(),
            Class::Top => "int".into(),
        }
    }

    /// The least class above both. A width joins with a width of the same
    /// size; two different widths keep the narrower, because the narrower
    /// use is the type and the wider is the slot it arrived in.
    pub fn join(self, other: Class) -> Class {
        use Class::*;
        match (self, other) {
            (Unknown, value) | (value, Unknown) => value,
            // Two opaque reads of one slot keep the narrower width; an
            // opaque value otherwise yields to anything that classifies it.
            (Opaque(left), Opaque(right)) => Opaque(left.min(right)),
            (Opaque(_), value) | (value, Opaque(_)) => value,
            (left, right) if left == right => left,
            (Top, _) | (_, Top) => Top,
            // A number with no sign evidence yields to one that has it, and
            // the width is the narrower of the two: one storage location is
            // read at several widths on any machine with subregisters --
            // `EDI` and `RDI` are the same bytes, and treating a 32-bit
            // signed read of a 64-bit slot as a contradiction reported every
            // x86-64 first parameter as conflicting evidence.
            (Num(left), Int(right)) | (Int(right), Num(left)) => Int(left.min(right)),
            (Num(left), Uint(right)) | (Uint(right), Num(left)) => Uint(left.min(right)),
            (Num(left), Float(right)) | (Float(right), Num(left)) => Float(left.min(right)),
            // A pointer read as an integer of pointer width is a pointer:
            // address arithmetic is integer arithmetic on every machine.
            (Ptr, Num(_)) | (Num(_), Ptr) => Ptr,
            (Code, Num(_)) | (Num(_), Code) => Code,
            // Address arithmetic is unsigned arithmetic: a slot read as an
            // unsigned value and dereferenced is a pointer, and the
            // dereference is the stronger fact. This holds at every width —
            // a `Uint(64)`-only rule made the `<= Ptr` region open upward,
            // which broke associativity (`Num32 join Uint64 join Ptr`).
            (Ptr, Uint(_)) | (Uint(_), Ptr) => Ptr,
            (Code, Uint(_)) | (Uint(_), Code) => Code,
            (Code, Ptr) | (Ptr, Code) => Code,
            (Num(left), Num(right)) => Num(left.min(right)),
            (Int(left), Int(right)) => Int(left.min(right)),
            (Uint(left), Uint(right)) => Uint(left.min(right)),
            (Float(left), Float(right)) => Float(left.min(right)),
            // about the sign and agree about everything else. The join is
            // `IntOrUint` — the least class above both — not `Num`, which
            // sits *below* them as weak evidence. Using `Num` here made
            // `join` non-associative and the solver's fixpoint diverge.
            (Int(left), Uint(right)) | (Uint(right), Int(left)) => IntOrUint(left.min(right)),
            // `IntOrUint` absorbs the integer classes it is the join of, and
            // `Num` below them; a float, pointer, or code reading is a
            // genuine conflict.
            (IntOrUint(left), Num(right)) | (Num(right), IntOrUint(left)) => {
                IntOrUint(left.min(right))
            }
            (IntOrUint(left), Int(right)) | (Int(right), IntOrUint(left)) => {
                IntOrUint(left.min(right))
            }
            (IntOrUint(left), Uint(right)) | (Uint(right), IntOrUint(left)) => {
                IntOrUint(left.min(right))
            }
            (IntOrUint(left), IntOrUint(right)) => IntOrUint(left.min(right)),
            // Anything else really is evidence in conflict.
            _ => Top,
        }
    }
}
