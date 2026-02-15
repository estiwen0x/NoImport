#include "resolver.hpp"
#include <iostream>

typedef void* (__stdcall* VAlloc_t)(void*, size_t, uint32_t, uint32_t);

int main() {
    // k32'den çekiyoruz, çaktırma
    uintptr_t k32 = R_MOD("KERNEL32.DLL");
    auto pVAlloc = (VAlloc_t)R_EXP(k32, "VirtualAlloc");

    if (pVAlloc) {
        std::cout << "[+] Found: 0x" << std::hex << (uintptr_t)pVAlloc << std::endl;
        
        void* m = pVAlloc(0, 4096, 0x1000, 0x40);
        if (m) {
            std::cout << "[+] OK: 0x" << m << std::endl;
        }
    }

    // ntdll testi
    uintptr_t ntdll = R_MOD("NTDLL.DLL");
    if (ntdll) {
        // ordinal gelirse direkt rva'ya zıpla (test amaçlı isimle devam)
        void* pTerm = R_EXP(ntdll, "NtTerminateProcess");
        std::cout << "[+] NtTerm: 0x" << pTerm << std::endl;
    }

    return 0;
}
