#include <stddef.h>
#include <valgrind/memcheck.h>

void pqc_valgrind_make_secret(void *ptr, size_t len) {
    VALGRIND_MAKE_MEM_UNDEFINED(ptr, len);
}

void pqc_valgrind_make_public(void *ptr, size_t len) {
    VALGRIND_MAKE_MEM_DEFINED(ptr, len);
}

int pqc_valgrind_running(void) {
    return RUNNING_ON_VALGRIND;
}
