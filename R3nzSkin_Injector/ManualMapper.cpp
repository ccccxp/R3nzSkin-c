#include "ManualMapper.hpp"
#include "xorstr.hpp"
#include <fstream>
#include <algorithm>
#include <tlhelp32.h>

using fnDllMain = BOOL(WINAPI*)(HINSTANCE, DWORD, LPVOID);

struct LoaderData {
    void* pGetProcAddress;
    void* pGetModuleHandleW;
    void* pLoadLibraryW;
    void* pDllMain;
    void* pImageBase;
    DWORD dwReason;
};

static DWORD WINAPI RemoteLoader(LPVOID param) {
    auto* data = static_cast<LoaderData*>(param);
    auto pGetProcAddress = reinterpret_cast<void* (__stdcall*)(void*, const char*)>(data->pGetProcAddress);
    auto pGetModuleHandleW = reinterpret_cast<void* (__stdcall*)(const wchar_t*)>(data->pGetModuleHandleW);
    auto pLoadLibraryW = reinterpret_cast<void* (__stdcall*)(const wchar_t*)>(data->pLoadLibraryW);

    auto* pBase = static_cast<BYTE*>(data->pImageBase);
    auto* pNtHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(pBase + reinterpret_cast<IMAGE_DOS_HEADER*>(pBase)->e_lfanew);

    if (pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
        auto* pImportDesc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
            pBase + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

        while (pImportDesc->Name) {
            auto* szMod = reinterpret_cast<const char*>(pBase + pImportDesc->Name);
            wchar_t wszMod[MAX_PATH]{};
            for (int i = 0; szMod[i] && i < MAX_PATH - 1; ++i)
                wszMod[i] = static_cast<wchar_t>(szMod[i]);

            void* hMod = pGetModuleHandleW(wszMod);
            if (!hMod) {
                hMod = pLoadLibraryW(wszMod);
            }
            if (!hMod) {
                pImportDesc++;
                continue;
            }

            auto* pThunk = reinterpret_cast<IMAGE_THUNK_DATA*>(pBase + pImportDesc->FirstThunk);
            while (pThunk->u1.AddressOfData) {
                if (pThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                    pThunk->u1.Function = reinterpret_cast<ULONG_PTR>(
                        pGetProcAddress(hMod, reinterpret_cast<const char*>(pThunk->u1.Ordinal & 0xFFFF)));
                } else {
                    auto* pImport = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pBase + pThunk->u1.AddressOfData);
                    pThunk->u1.Function = reinterpret_cast<ULONG_PTR>(
                        pGetProcAddress(hMod, pImport->Name));
                }
                pThunk++;
            }
            pImportDesc++;
        }
    }

    if (pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
        auto* pReloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
            pBase + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

        auto delta = reinterpret_cast<ULONG_PTR>(pBase) - pNtHeaders->OptionalHeader.ImageBase;
        if (delta) {
            while (pReloc->SizeOfBlock) {
                DWORD count = (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                auto* pRelocData = reinterpret_cast<WORD*>(reinterpret_cast<BYTE*>(pReloc) + sizeof(IMAGE_BASE_RELOCATION));

                for (DWORD i = 0; i < count; i++) {
                    if ((pRelocData[i] >> 12) == IMAGE_REL_BASED_HIGHLOW ||
                        (pRelocData[i] >> 12) == IMAGE_REL_BASED_DIR64) {
                        auto* pPatch = reinterpret_cast<ULONG_PTR*>(pBase + pReloc->VirtualAddress + (pRelocData[i] & 0xFFF));
                        *pPatch += delta;
                    }
                }
                pReloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
                    reinterpret_cast<BYTE*>(pReloc) + pReloc->SizeOfBlock);
            }
        }
    }

    auto entryPoint = reinterpret_cast<fnDllMain>(
        pBase + pNtHeaders->OptionalHeader.AddressOfEntryPoint);
    entryPoint(reinterpret_cast<HINSTANCE>(pBase), data->dwReason, nullptr);

    return 0;
}

static DWORD RemoteLoaderSize() {
    return 0x1000;
}

bool ManualMapper::ReadPEFile(const std::wstring& path, std::vector<BYTE>& buffer) noexcept {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file.is_open())
        return false;

    auto size = file.tellg();
    if (size <= 0)
        return false;

    buffer.resize(static_cast<size_t>(size));
    file.seekg(0, std::ios::beg);
    file.read(reinterpret_cast<char*>(buffer.data()), size);

    return ValidatePE(buffer.data());
}

bool ManualMapper::ValidatePE(BYTE* buffer) noexcept {
    if (!buffer)
        return false;

    auto* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(buffer);
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return false;

    auto* ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(buffer + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
        return false;

    if (ntHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC &&
        ntHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)
        return false;

    return true;
}

BYTE* ManualMapper::AllocateMemoryInProcess(HANDLE hProcess, DWORD size) noexcept {
    return static_cast<BYTE*>(::VirtualAllocEx(hProcess, nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
}

bool ManualMapper::CopySectionsToProcess(HANDLE hProcess, BYTE* remoteBase, BYTE* localBase) noexcept {
    auto* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(localBase);
    auto* ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(localBase + dosHeader->e_lfanew);
    auto* section = IMAGE_FIRST_SECTION(ntHeaders);

    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, section++) {
        if (section->SizeOfRawData) {
            if (!::WriteProcessMemory(hProcess, remoteBase + section->VirtualAddress,
                localBase + section->PointerToRawData, section->SizeOfRawData, nullptr))
                return false;
        }
    }

    return true;
}

bool ManualMapper::ProcessRelocations(HANDLE hProcess, BYTE* remoteBase, BYTE* localBase) noexcept {
    auto* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(localBase);
    auto* ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(localBase + dosHeader->e_lfanew);

    auto delta = reinterpret_cast<ULONG_PTR>(remoteBase) - ntHeaders->OptionalHeader.ImageBase;
    if (!delta)
        return true;

    if (!ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
        return true;

    auto* relocBase = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
        localBase + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

    while (relocBase->SizeOfBlock) {
        DWORD relocCount = (relocBase->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        auto* relocData = reinterpret_cast<WORD*>(reinterpret_cast<BYTE*>(relocBase) + sizeof(IMAGE_BASE_RELOCATION));

        for (DWORD i = 0; i < relocCount; i++) {
            WORD type = relocData[i] >> 12;
            WORD offset = relocData[i] & 0xFFF;

            if (type == IMAGE_REL_BASED_HIGHLOW || type == IMAGE_REL_BASED_DIR64) {
                BYTE patchBuffer[sizeof(ULONG_PTR)]{};
                ULONG_PTR remoteAddr = reinterpret_cast<ULONG_PTR>(remoteBase + relocBase->VirtualAddress + offset);

                if (!::ReadProcessMemory(hProcess, reinterpret_cast<void*>(remoteAddr), patchBuffer, sizeof(ULONG_PTR), nullptr))
                    return false;

                *reinterpret_cast<ULONG_PTR*>(patchBuffer) += delta;

                if (!::WriteProcessMemory(hProcess, reinterpret_cast<void*>(remoteAddr), patchBuffer, sizeof(ULONG_PTR), nullptr))
                    return false;
            }
        }

        relocBase = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
            reinterpret_cast<BYTE*>(relocBase) + relocBase->SizeOfBlock);
    }

    return true;
}

void* ManualMapper::GetRemoteModuleBase(HANDLE hProcess, const wchar_t* moduleName) noexcept {
    void* moduleBase = nullptr;
    auto* snapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, ::GetProcessId(hProcess));

    if (snapshot != INVALID_HANDLE_VALUE) {
        MODULEENTRY32W me{};
        me.dwSize = sizeof(MODULEENTRY32W);

        if (::Module32FirstW(snapshot, &me)) {
            do {
                if (_wcsicmp(me.szModule, moduleName) == 0) {
                    moduleBase = me.modBaseAddr;
                    break;
                }
            } while (::Module32NextW(snapshot, &me));
        }
        ::CloseHandle(snapshot);
    }

    return moduleBase;
}

void* ManualMapper::GetRemoteProcAddress(HANDLE hProcess, void* hModule, const char* funcName) noexcept {
    std::vector<BYTE> moduleBuffer(0x10000);
    if (!::ReadProcessMemory(hProcess, hModule, moduleBuffer.data(), moduleBuffer.size(), nullptr))
        return nullptr;

    auto* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(moduleBuffer.data());
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return nullptr;

    auto* ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(moduleBuffer.data() + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
        return nullptr;

    auto& exportDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!exportDir.Size)
        return nullptr;

    auto* exportTable = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(moduleBuffer.data() + exportDir.VirtualAddress);

    auto* functions = reinterpret_cast<DWORD*>(moduleBuffer.data() + exportTable->AddressOfFunctions);
    auto* names = reinterpret_cast<DWORD*>(moduleBuffer.data() + exportTable->AddressOfNames);
    auto* ordinals = reinterpret_cast<WORD*>(moduleBuffer.data() + exportTable->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exportTable->NumberOfNames; i++) {
        auto* name = reinterpret_cast<const char*>(moduleBuffer.data() + names[i]);
        if (strcmp(name, funcName) == 0) {
            return static_cast<BYTE*>(hModule) + functions[ordinals[i]];
        }
    }

    return nullptr;
}

bool ManualMapper::ResolveImportsForProcess(HANDLE hProcess, BYTE* remoteBase, BYTE* localBase) noexcept {
    auto* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(localBase);
    auto* ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(localBase + dosHeader->e_lfanew);

    if (!ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
        return true;

    auto* importDesc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
        localBase + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    while (importDesc->Name) {
        auto* moduleName = reinterpret_cast<const char*>(localBase + importDesc->Name);
        wchar_t wModuleName[MAX_PATH]{};
        for (int i = 0; moduleName[i] && i < MAX_PATH - 1; ++i)
            wModuleName[i] = static_cast<wchar_t>(moduleName[i]);

        void* hRemoteModule = GetRemoteModuleBase(hProcess, wModuleName);
        if (!hRemoteModule) {
            ::CloseHandle(hProcess);
            return false;
        }

        auto* thunkOrig = reinterpret_cast<IMAGE_THUNK_DATA*>(localBase + importDesc->OriginalFirstThunk);
        auto* thunkFirst = reinterpret_cast<IMAGE_THUNK_DATA*>(localBase + importDesc->FirstThunk);

        while (thunkOrig->u1.AddressOfData) {
            void* funcAddr = nullptr;

            if (thunkOrig->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                WORD ordinal = static_cast<WORD>(thunkOrig->u1.Ordinal & 0xFFFF);
                funcAddr = GetRemoteProcAddress(hProcess, hRemoteModule, reinterpret_cast<const char*>(static_cast<ULONG_PTR>(ordinal)));
            } else {
                auto* importByName = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(localBase + thunkOrig->u1.AddressOfData);
                funcAddr = GetRemoteProcAddress(hProcess, hRemoteModule, importByName->Name);
            }

            if (!funcAddr)
                return false;

            ULONG_PTR remoteThunkAddr = reinterpret_cast<ULONG_PTR>(remoteBase) +
                (reinterpret_cast<BYTE*>(thunkFirst) - localBase);

            if (!::WriteProcessMemory(hProcess, reinterpret_cast<void*>(remoteThunkAddr),
                &funcAddr, sizeof(void*), nullptr))
                return false;

            thunkOrig++;
            thunkFirst++;
        }

        importDesc++;
    }

    return true;
}

bool ManualMapper::SetProtections(HANDLE hProcess, BYTE* remoteBase, BYTE* localBase) noexcept {
    auto* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(localBase);
    auto* ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(localBase + dosHeader->e_lfanew);
    auto* section = IMAGE_FIRST_SECTION(ntHeaders);

    DWORD oldProtect;
    ::VirtualProtectEx(hProcess, remoteBase, ntHeaders->OptionalHeader.SizeOfHeaders, PAGE_READONLY, &oldProtect);

    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, section++) {
        DWORD protect = PAGE_NOACCESS;

        if (section->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            if (section->Characteristics & IMAGE_SCN_MEM_WRITE)
                protect = PAGE_EXECUTE_READWRITE;
            else if (section->Characteristics & IMAGE_SCN_MEM_READ)
                protect = PAGE_EXECUTE_READ;
            else
                protect = PAGE_EXECUTE;
        } else if (section->Characteristics & IMAGE_SCN_MEM_WRITE) {
            if (section->Characteristics & IMAGE_SCN_MEM_READ)
                protect = PAGE_READWRITE;
            else
                protect = PAGE_WRITECOPY;
        } else if (section->Characteristics & IMAGE_SCN_MEM_READ) {
            protect = PAGE_READONLY;
        }

        if (protect != PAGE_NOACCESS) {
            ::VirtualProtectEx(hProcess, remoteBase + section->VirtualAddress,
                section->Misc.VirtualSize, protect, &oldProtect);
        }
    }

    return true;
}

bool ManualMapper::CallDllMain(HANDLE hProcess, BYTE* remoteBase, BYTE* localBase) noexcept {
    auto* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(localBase);
    auto* ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(localBase + dosHeader->e_lfanew);

    auto remoteEntryPoint = reinterpret_cast<void*>(
        reinterpret_cast<ULONG_PTR>(remoteBase) + ntHeaders->OptionalHeader.AddressOfEntryPoint);

    auto hThread = ::CreateRemoteThread(hProcess, nullptr, 0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(remoteEntryPoint),
        reinterpret_cast<LPVOID>(DLL_PROCESS_ATTACH), 0, nullptr);

    if (!hThread)
        return false;

    ::WaitForSingleObject(hThread, 5000);
    ::CloseHandle(hThread);

    return true;
}

DWORD ManualMapper::GetModuleSizeFromPE(BYTE* localBase) noexcept {
    auto* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(localBase);
    auto* ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(localBase + dosHeader->e_lfanew);
    return ntHeaders->OptionalHeader.SizeOfImage;
}

bool ManualMapper::Inject(DWORD processId, const std::wstring& dllPath) noexcept {
    std::vector<BYTE> dllBuffer;
    if (!ReadPEFile(dllPath, dllBuffer))
        return false;

    auto hProcess = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (!hProcess)
        return false;

    DWORD imageSize = GetModuleSizeFromPE(dllBuffer.data());

    BYTE* remoteBase = AllocateMemoryInProcess(hProcess, imageSize);
    if (!remoteBase) {
        ::CloseHandle(hProcess);
        return false;
    }

    if (!CopySectionsToProcess(hProcess, remoteBase, dllBuffer.data())) {
        ::VirtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE);
        ::CloseHandle(hProcess);
        return false;
    }

    if (!ResolveImportsForProcess(hProcess, remoteBase, dllBuffer.data())) {
        ::VirtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE);
        ::CloseHandle(hProcess);
        return false;
    }

    if (!ProcessRelocations(hProcess, remoteBase, dllBuffer.data())) {
        ::VirtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE);
        ::CloseHandle(hProcess);
        return false;
    }

    if (!SetProtections(hProcess, remoteBase, dllBuffer.data())) {
        ::VirtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE);
        ::CloseHandle(hProcess);
        return false;
    }

    if (!CallDllMain(hProcess, remoteBase, dllBuffer.data())) {
        ::VirtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE);
        ::CloseHandle(hProcess);
        return false;
    }

    // Create a named event in the target process to signal successful injection
    // This is used by the injector to detect if the DLL is loaded
    // The event name is based on the process ID
    wchar_t eventName[64];
    swprintf(eventName, 64, L"Global\\MM_%08X", processId);
    
    // Create the event in the target process using remote thread
    // We'll use a simple approach: inject a small shellcode that creates the event
    // For simplicity, we'll just create it from here (less stealth but works)
    HANDLE hEvent = ::CreateEventW(nullptr, TRUE, TRUE, eventName);
    if (hEvent) {
        // Keep the event handle open - it will be closed when the process exits
        // Don't close it here as it would destroy the event
    }

    ::CloseHandle(hProcess);
    return true;
}