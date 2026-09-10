/* Type-recovery fixture: every class the inference can be scored on, in a
 * form the compiler cannot optimise away.
 *
 * The corpus rows carry DWARF, but their sources are integer arithmetic, so
 * `int32` is nearly the only truth they state. Scoring a type inference on
 * that says almost nothing: it cannot distinguish an inference from a
 * constant that answers "int32". This fixture states each class at least
 * twice, in both a signed and an unsigned reading, through a pointer, and
 * behind an indirect call -- the four things p-code actually commits to.
 *
 * Every parameter is used in a way that constrains it, and every function
 * returns its result, so nothing here depends on the optimiser keeping a
 * dead argument alive. Built at gate time with `-g` at two optimisation
 * levels; it is a fixture, not a corpus row, so it states no baseline of
 * its own.
 */
#include <stdint.h>

__attribute__((noinline)) int32_t signed_compare(int32_t value) {
    return value < 7 ? value * 3 : value - 1;
}

__attribute__((noinline)) uint32_t unsigned_compare(uint32_t value) {
    return value < 7u ? value / 3u : value >> 2;
}

__attribute__((noinline)) int64_t signed_wide(int64_t value) {
    return value < -3 ? value / 5 : value >> 3;
}

__attribute__((noinline)) uint64_t unsigned_wide(uint64_t value) {
    return value > 11u ? value % 7u : value << 1;
}

__attribute__((noinline)) int32_t through_pointer(const int32_t *values, uint64_t count) {
    int32_t total = 0;
    for (uint64_t index = 0; index < count; ++index) {
        total += values[index];
    }
    return total;
}

__attribute__((noinline)) double floating(double left, double right) {
    return left < right ? left * 2.0 : right / 3.0;
}

__attribute__((noinline)) float floating_narrow(float left, float right) {
    return left < right ? left + right : left - right;
}

__attribute__((noinline)) int32_t indirect(int32_t (*operation)(int32_t), int32_t value) {
    return operation(value) + 1;
}

__attribute__((noinline)) uint8_t narrow_unsigned(uint8_t value) {
    return value > 3u ? (uint8_t)(value * 5u) : (uint8_t)(value >> 1);
}

__attribute__((noinline)) int16_t narrow_signed(int16_t value) {
    return value < -2 ? (int16_t)(value * 3) : (int16_t)(value / 2);
}

__attribute__((noinline)) int32_t store_through_pointer(int32_t *slot, int32_t value) {
    *slot = value < 0 ? -value : value;
    return *slot;
}

__attribute__((noinline)) uint64_t mixed(const uint8_t *bytes, uint64_t length, int32_t bias) {
    uint64_t total = 0;
    for (uint64_t index = 0; index < length; ++index) {
        total += (uint64_t)bytes[index];
    }
    return bias < 0 ? total : total + (uint64_t)bias;
}

int main(int argc, char **argv) {
    int32_t values[4] = {1, 2, 3, 4};
    int32_t slot = 0;
    int32_t total = signed_compare(argc) + (int32_t)unsigned_compare((uint32_t)argc);
    total += (int32_t)signed_wide((int64_t)argc) + (int32_t)unsigned_wide((uint64_t)argc);
    total += through_pointer(values, 4);
    total += (int32_t)floating((double)argc, 2.0) + (int32_t)floating_narrow(1.0f, (float)argc);
    total += indirect(signed_compare, argc);
    total += narrow_unsigned((uint8_t)argc) + narrow_signed((int16_t)argc);
    total += store_through_pointer(&slot, argc);
    total += (int32_t)mixed((const uint8_t *)argv[0], 3, argc);
    return total;
}
