# NoImport

**Architecting Stealth: Zero-Dependency Runtime Export Resolution for Windows**

`NoImport` is a high-performance, header-only C++ engine designed to eliminate static footprints in the **Import Address Table (IAT)**. By circumventing standard Windows loader mechanisms and `GetProcAddress` calls, it provides a robust layer of evasion against static analysis, IAT-hooking, and heuristic-based EDR detections.

---

## Technical Overview

The framework operates by manually interfacing with Windows internals, replacing high-level API dependencies with raw memory traversal.

* **IAT-Free Linkage:** Resolves all dependencies at runtime. The resulting binary contains zero plaintext function names or static import descriptors.
* **Manual PEB/LDR Traversal:** Navigates the `InLoadOrderModuleList` directly via the **Process Environment Block (PEB)** to locate loaded modules.
* **Direct EAT Parsing:** Locates function addresses by walking the **Export Address Table (EAT)** using raw offsets (`0x88`, `0x3c`, etc.), eliminating the need for Windows header structures.
* **Recursive Forwarder Resolution:** Deep-parsing of forwarded exports (e.g., `NTDLL.RtlAllocateHeap`) via manual string tokenization and recursive resolution.
* **Ordinal & Hash-Based Lookup:** Support for resolving exports via **compile-time hashes** or **ordinals** (using the `#ordinal` syntax).
* **Architecture Agnostic:** Dynamic offset logic ensures native compatibility across `x86` and `x64` architectures.

---

## Internal Hardening

To stay below the radar of modern heuristic engines, `NoImport` avoids standard "textbook" implementation patterns:

* **Stack-Only Execution:** Utilizes `_alloca` for transient string processing to ensure zero heap artifacts.
* **Modified FNV-1a Hashing:** The hashing logic uses bit-shift equivalents and unrolled loops to bypass signature-based detection of standard FNV-1a constants.
* **Register-Efficient Logic:** String comparisons and memory walks are optimized for low-level, register-heavy execution to mimic legitimate system-level code.

---

## Usage

```cpp
#include "resolver.hpp"

// Resolve KERNEL32 base and VirtualAlloc address
uintptr_t k32 = R_MOD("KERNEL32.DLL");
auto pVAlloc = (VAlloc_t)R_EXP(k32, "VirtualAlloc");

if (pVAlloc) {
    void* buffer = pVAlloc(nullptr, 4096, 0x1000, 0x40);
}

// Seamless support for NTDLL and Ordinals
uintptr_t ntdll = R_MOD("NTDLL.DLL");
void* pNtTerm = R_EXP(ntdll, "NtTerminateProcess");
