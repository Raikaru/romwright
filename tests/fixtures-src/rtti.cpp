// Gate input for m2-013, not a corpus member: the locked corpus C++ source
// defines no classes, so Itanium RTTI recovery needs its own shapes here.
// One class per inheritance form the ABI encodes differently:
//   Base   -> __class_type_info      (no bases)
//   Middle -> __si_class_type_info   (one public non-virtual base)
//   Multi  -> __vmi_class_type_info  (two non-virtual bases)
//   Virt   -> __vmi_class_type_info  (one virtual base)
//   Other  -> __class_type_info      (independent hierarchy)
struct Base {
    virtual ~Base() {}
    virtual int value() const { return 1; }
};

struct Middle : Base {
    int value() const override { return 2; }
};

struct Other {
    virtual int tag() const { return 7; }
};

struct Multi : Middle, Other {
    int value() const override { return 3; }
    int tag() const override { return 4; }
};

struct Virt : virtual Base {
    int value() const override { return 5; }
};

static int use(const Base *base, const Other *other) {
    return base->value() + other->tag();
}

Base base;
Middle middle;
Multi multi;
Virt virt;
Other other;

int main() {
    return use(&multi, &multi) + use(&virt, &other) + base.value() + middle.value();
}
