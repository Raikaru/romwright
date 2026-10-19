// Gate input for m2-014, not a corpus member: a freestanding MSVC-ABI image,
// so no CRT is linked and the two runtime symbols the RTTI data references are
// defined here. One class per shape the ABI records differently:
//   Base   -> one base class descriptor (itself)
//   Middle -> single non-virtual base
//   Multi  -> multiple non-virtual bases, second vfptr at a non-zero offset
//   Virt   -> virtual base, described through the PMD's pdisp/vdisp
//   Other  -> independent hierarchy
void *type_info_vftable[1] asm("??_7type_info@@6B@") = {nullptr};
void operator delete(void *, decltype(sizeof(int))) noexcept {}
void operator delete(void *) noexcept {}
// clang 18 registers each global's destructor through atexit in the dynamic
// initializer (clang 19 elides these empty ones); with no CRT linked, supply it.
extern "C" int atexit(void (*)()) { return 0; }

struct Base {
    virtual ~Base() {}
    virtual int value() { return 1; }
};

struct Middle : Base {
    int value() override { return 2; }
};

struct Other {
    virtual int tag() { return 7; }
};

struct Multi : Middle, Other {
    int value() override { return 3; }
    int tag() override { return 4; }
};

struct Virt : virtual Base {
    int value() override { return 5; }
};

Base base_obj;
Middle middle_obj;
Multi multi_obj;
Virt virt_obj;
Other other_obj;

static int use(Base *base, Other *other) { return base->value() + other->tag(); }

extern "C" int mainCRTStartup() {
    return use(&multi_obj, &multi_obj) + use(&virt_obj, &other_obj)
        + base_obj.value() + middle_obj.value();
}
