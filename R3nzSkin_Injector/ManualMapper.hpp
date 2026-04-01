#pragma once

#include <Windows.h>
#include <cstdint>
#include <string>
#include <vector>

class ManualMapper {
public:
    static bool Inject(DWORD processId, const std::wstring& dllPath) noexcept;

private:
    static bool ReadPEFile(const std::wstring& path, std::vector<BYTE>& buffer) noexcept;
    static bool ValidatePE(BYTE* buffer) noexcept;
    static BYTE* AllocateMemoryInProcess(HANDLE hProcess, DWORD size) noexcept;
    static bool CopySectionsToProcess(HANDLE hProcess, BYTE* remoteBase, BYTE* localBase) noexcept;
    static bool ProcessRelocations(HANDLE hProcess, BYTE* remoteBase, BYTE* localBase) noexcept;
    static bool ResolveImportsForProcess(HANDLE hProcess, BYTE* remoteBase, BYTE* localBase) noexcept;
    static bool SetProtections(HANDLE hProcess, BYTE* remoteBase, BYTE* localBase) noexcept;
    static bool CallDllMain(HANDLE hProcess, BYTE* remoteBase, BYTE* localBase) noexcept;

    static void* GetRemoteProcAddress(HANDLE hProcess, void* hModule, const char* funcName) noexcept;
    static void* GetRemoteModuleBase(HANDLE hProcess, const wchar_t* moduleName) noexcept;
    static DWORD GetModuleSizeFromPE(BYTE* localBase) noexcept;
};