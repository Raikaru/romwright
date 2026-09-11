/* Indirect-call pruning fixture: a pool of address-taken functions with
 * different signatures, called through a global table indexed by a value
 * the compiler cannot know, so nothing constant-folds.
 *
 * The pool is the table's entries: functions whose address is stored in
 * `ops`, which the loader sees as initializer slots holding code
 * addresses. The call sites index the table by `argc`, so the callee is
 * genuinely indirect -- the compiler emits `call *reg` and the site's
 * argument registers carry the signature the callee must match.
 *
 * Signatures are chosen so the pool has incompatible members: a
 * two-parameter function where the site passes one, a float function
 * where the site passes a signed integer, a void-returning function
 * where the site uses the result. The true callee is the one whose
 * signature the site's argument registers state.
 */
#include <stdint.h>

__attribute__((noinline)) int32_t one_int(int32_t value) {
    return value < 7 ? value * 3 : value - 1;
}

__attribute__((noinline)) int32_t two_ints(int32_t left, int32_t right) {
    return left < right ? left + right : left - right;
}

__attribute__((noinline)) void one_int_void(int32_t value) {
    /* A result the caller must not use: the site that reads a return
     * register cannot be calling here. */
    (void)value;
}

__attribute__((noinline)) double one_double(double value) {
    return value < 7.0 ? value * 2.0 : value / 3.0;
}

__attribute__((noinline)) int32_t no_args(void) {
    return 42;
}

/* The pool: every entry is address-taken by the initializer, and every
 * entry is a candidate at every indirect site. */
static int32_t (*const ops[])(int32_t) = {
    one_int,
    (int32_t (*)(int32_t))two_ints,
    (int32_t (*)(int32_t))one_int_void,
    (int32_t (*)(int32_t))one_double,
    (int32_t (*)(int32_t))no_args,
};

__attribute__((noinline)) int32_t call_one(int32_t index, int32_t value) {
    /* The site sets one argument register to a signed value: the
     * comparison `value < 7` is signed, so the register's class is
     * `int32`. A candidate that takes a float here is incompatible. */
    return ops[index % 5](value < 7 ? value : -value);
}

__attribute__((noinline)) int32_t call_two(int32_t index, int32_t left, int32_t right) {
    /* The site sets two argument registers to signed values. */
    int32_t (*f)(int32_t, int32_t) = (int32_t (*)(int32_t, int32_t))ops[index % 5];
    return f(left < 7 ? left : -left, right < 7 ? right : -right);
}

int main(int argc, char **argv) {
    (void)argv;
    int32_t total = call_one(argc, argc);
    total += call_two(argc, argc, argc + 1);
    return total;
}
