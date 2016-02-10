#ifndef TOXENCRYPTSAVE_MEM_GUARD_H
#define TOXENCRYPTSAVE_MEM_GUARD_H

#include <stddef.h>
#include <stdint.h>

namespace toxencryptsave
{

// zero region on descruction
struct Mem_Guard
{
    uint8_t* const ptr;
    size_t const len;

    explicit Mem_Guard(uint8_t* const in_mem, size_t const in_len) : ptr(in_mem), len(in_len) {}
    ~Mem_Guard();
private:
    Mem_Guard(); // = delete
    Mem_Guard(const Mem_Guard&); // = delete
    Mem_Guard& operator= (const Mem_Guard&); // = delete
};

}

#endif
