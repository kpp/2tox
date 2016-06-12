#include "mem_guard.hpp"

#include <sodium.h>

toxencryptsave::Mem_Guard::~Mem_Guard() {
    if (ptr) sodium_memzero(ptr, len);
}
