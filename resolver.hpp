#pragma once
#include <cstdint>
#include <intrin.h>
#include <malloc.h>

// rsh: leak/private research version
namespace rsh {

    // ham hash - loop unrolled, bit-shift fantezili
    static __forceinline constexpr uint32_t h(const char* s) {
        uint32_t v = 0x811c9dc5;
        while (*s) {
            v ^= (uint8_t)*s++;
            v = (v << 1) + (v << 4) + (v << 7) + (v << 8) + (v << 24); // fnv-1a ama biraz kurcalanmış
        }
        return v;
    }

    // peb'e zıpla - x64/x86 mix
    static __forceinline uintptr_t get_peb() {
#if defined(_M_X64)
        return (uintptr_t)__readgsqword(0x60);
#else
        return (uintptr_t)__readfsdword(0x30);
#endif
    }

    static void* resolve_export(uintptr_t base, uint32_t target);

    // forwarder belası, mecbur parse edicez
    static void* walk_fwd(char* fwd) {
        size_t n = 0; while (fwd[n]) n++;
        char* b = (char*)_alloca(n + 1);
        for (size_t i = 0; i <= n; i++) b[i] = fwd[i];

        char* dot = 0;
        for (char* p = b; *p; p++) if (*p == '.') { dot = p; break; }
        if (!dot) return 0;

        *dot = 0;
        char* func = dot + 1;

        // modül bul - ldr üzerinden manuel
        auto find_m = [](uint32_t th) -> uintptr_t {
            uintptr_t ldr = *(uintptr_t*)(get_peb() + 0x18);
            uintptr_t head = ldr + 0x10;
            uintptr_t curr = *(uintptr_t*)head;

            while (curr && curr != head) {
                // name offset: x64 0x60, x86 0x30
                uintptr_t n_ptr = *(uintptr_t*)(curr + (sizeof(void*) == 8 ? 0x60 : 0x30));
                uint16_t n_len = *(uint16_t*)(curr + (sizeof(void*) == 8 ? 0x58 : 0x2c));

                if (n_ptr) {
                    uint32_t h_v = 0x811c9dc5;
                    for (uint16_t i = 0; i < (n_len / 2); i++) {
                        uint8_t c = (uint8_t)((wchar_t*)n_ptr)[i];
                        if (c >= 'a' && c <= 'z') c -= 0x20;
                        h_v ^= c; h_v = (h_v << 1) + (h_v << 4) + (h_v << 7) + (h_v << 8) + (h_v << 24);
                    }
                    if (h_v == th) return *(uintptr_t*)(curr + (sizeof(void*) == 8 ? 0x30 : 0x18));
                }
                curr = *(uintptr_t*)curr;
            }
            return 0;
        };

        // dll hashle
        uint32_t dh = 0x811c9dc5;
        for (char* p = b; *p; p++) {
            uint8_t c = (uint8_t)*p;
            if (c >= 'a' && c <= 'z') c -= 0x20;
            dh ^= c; dh = (dh << 1) + (dh << 4) + (dh << 7) + (dh << 8) + (dh << 24);
        }

        uintptr_t base = find_m(dh);
        if (!base) {
            // .dll yoksa çakıp tekrar bak
            const char* ext = ".DLL";
            for(int i=0; ext[i]; i++) {
                dh ^= (uint8_t)ext[i];
                dh = (dh << 1) + (dh << 4) + (dh << 7) + (dh << 8) + (dh << 24);
            }
            base = find_m(dh);
        }

        if (!base) return 0;

        // ordinal gelirse direkt rva'ya zıpla
        if (func[0] == '#') {
            uint32_t ord = 0;
            for (int i = 1; func[i]; i++) ord = ord * 10 + (func[i] - '0');
            return resolve_export(base, ord);
        }

        uint32_t fh = 0x811c9dc5;
        while (*func) {
            fh ^= (uint8_t)*func++;
            fh = (fh << 1) + (fh << 4) + (fh << 7) + (fh << 8) + (fh << 24);
        }
        return resolve_export(base, fh);
    }

    // EAT walker - struct falan yok, sadece offset
    static void* resolve_export(uintptr_t base, uint32_t target) {
        if (!base) return 0;

        // MZ check
        if (*(uint16_t*)base != 0x5a4d) return 0;
        uintptr_t nt = base + *(uint32_t*)(base + 0x3c);
        if (*(uint32_t*)nt != 0x00004550) return 0;

        // EAT offset: x64 0x88, x86 0x78
        uint32_t eat_rva = *(uint32_t*)(nt + (sizeof(void*) == 8 ? 0x88 : 0x78));
        uint32_t eat_sz = *(uint32_t*)(nt + (sizeof(void*) == 8 ? 0x8c : 0x7c));
        if (!eat_rva) return 0;

        uintptr_t eat = base + eat_rva;
        uint32_t n_funcs = *(uint32_t*)(eat + 0x14);
        uint32_t n_names = *(uint32_t*)(eat + 0x18);
        uintptr_t adr_f = base + *(uint32_t*)(eat + 0x1c);
        uintptr_t adr_n = base + *(uint32_t*)(eat + 0x20);
        uintptr_t adr_o = base + *(uint32_t*)(eat + 0x24);

        // ordinal mi?
        if (target <= 0xFFFF) {
            uint32_t b_ord = *(uint32_t*)(eat + 0x10);
            uint32_t idx = target - b_ord;
            if (idx >= n_funcs) return 0;
            uint32_t rva = *(uint32_t*)(adr_f + (idx * 4));
            if (rva >= eat_rva && rva < (eat_rva + eat_sz)) return walk_fwd((char*)(base + rva));
            return (void*)(base + rva);
        }

        // isimle ara - register efficient loop
        for (uint32_t i = 0; i < n_names; i++) {
            char* name = (char*)(base + *(uint32_t*)(adr_n + (i * 4)));
            uint32_t h_v = 0x811c9dc5;
            char* k = name;
            while (*k) {
                h_v ^= (uint8_t)*k++;
                h_v = (h_v << 1) + (h_v << 4) + (h_v << 7) + (h_v << 8) + (h_v << 24);
            }

            if (h_v == target) {
                uint16_t or_idx = *(uint16_t*)(adr_o + (i * 2));
                uint32_t rva = *(uint32_t*)(adr_f + (or_idx * 4));
                if (rva >= eat_rva && rva < (eat_rva + eat_sz)) return walk_fwd((char*)(base + rva));
                return (void*)(base + rva);
            }
        }
        return 0;
    }

    // modül base çek - ldr walk
    static uintptr_t get_mod(uint32_t target) {
        uintptr_t ldr = *(uintptr_t*)(get_peb() + 0x18);
        uintptr_t head = ldr + 0x10;
        uintptr_t curr = *(uintptr_t*)head;
        while (curr && curr != head) {
            uintptr_t n_ptr = *(uintptr_t*)(curr + (sizeof(void*) == 8 ? 0x60 : 0x30));
            uint16_t n_len = *(uint16_t*)(curr + (sizeof(void*) == 8 ? 0x58 : 0x2c));
            if (n_ptr) {
                uint32_t h_v = 0x811c9dc5;
                for (uint16_t i = 0; i < (n_len / 2); i++) {
                    uint8_t c = (uint8_t)((wchar_t*)n_ptr)[i];
                    if (c >= 'a' && c <= 'z') c -= 0x20;
                    h_v ^= c; h_v = (h_v << 1) + (h_v << 4) + (h_v << 7) + (h_v << 8) + (h_v << 24);
                }
                if (h_v == target) return *(uintptr_t*)(curr + (sizeof(void*) == 8 ? 0x30 : 0x18));
            }
            curr = *(uintptr_t*)curr;
        }
        return 0;
    }
}

// makrolar - çaktırmadan hallet
#define R_MOD(s) rsh::get_mod(rsh::h(s))
#define R_EXP(m, s) rsh::resolve_export(m, rsh::h(s))
