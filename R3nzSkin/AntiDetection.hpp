#pragma once

#include <Windows.h>
#include <TlHelp32.h>
#include <winternl.h>
#include <cstdint>
#include <string>
#include <vector>
#include <random>

// Anti-detection utilities for China server
namespace AntiDetection {

	// Random number generator for timing jitter
	inline std::uint32_t GetRandomDelay(std::uint32_t min, std::uint32_t max) noexcept {
		static std::mt19937 rng{ static_cast<std::uint32_t>(::GetTickCount64()) };
		std::uniform_int_distribution<std::uint32_t> dist(min, max);
		return dist(rng);
	}

	// Check if Tencent TP is running
	inline bool CheckTPProcess() noexcept {
		HANDLE snapshot{ ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
		if (snapshot == INVALID_HANDLE_VALUE)
			return false;

		PROCESSENTRY32W pe32{};
		pe32.dwSize = sizeof(PROCESSENTRY32W);

		// Known TP process names (expanded list)
		const wchar_t* tpProcesses[] = {
			L"TenProtect.exe",
			L"TPHelper.exe",
			L"TProtect.exe",
			L"TP.exe",
			L"TenSafe.exe",
			L"TenioDL.exe",
			L"bugreport.exe",
			L"ACE-Guard.exe",
			L"ACE-Base.exe",
			L"AntiCheatExpert.exe"
		};

		bool found{ false };
		if (::Process32FirstW(snapshot, &pe32)) {
			do {
				for (const auto* tpName : tpProcesses) {
					if (::_wcsicmp(pe32.szExeFile, tpName) == 0) {
						found = true;
						break;
					}
				}
			} while (::Process32NextW(snapshot, &pe32) && !found);
		}

		::CloseHandle(snapshot);
		return found;
	}

	// Check if debugger is present (multiple methods)
	inline bool IsDebuggerPresent() noexcept {
		// Method 1: Windows API
		if (::IsDebuggerPresent())
			return true;

		// Method 2: PEB check
		__try {
			BOOL debuggerPresent{ FALSE };
			::CheckRemoteDebuggerPresent(::GetCurrentProcess(), &debuggerPresent);
			if (debuggerPresent)
				return true;
		} __except (EXCEPTION_EXECUTE_HANDLER) {
			return true;
		}

		// Method 3: NtQueryInformationProcess
		using NtQueryInformationProcessFunc = NTSTATUS(NTAPI*)(HANDLE, DWORD, PVOID, ULONG, PULONG);
		const auto ntdll{ ::GetModuleHandleW(L"ntdll.dll") };
		if (ntdll) {
			const auto NtQueryInformationProcess{ reinterpret_cast<NtQueryInformationProcessFunc>(::GetProcAddress(ntdll, "NtQueryInformationProcess")) };
			if (NtQueryInformationProcess) {
				DWORD debugPort{ 0 };
				if (NtQueryInformationProcess(::GetCurrentProcess(), 7, &debugPort, sizeof(debugPort), nullptr) >= 0) {
					if (debugPort != 0)
						return true;
				}
			}
		}

		return false;
	}

	// Erase PE header from memory to prevent scanning
	inline void ErasePEHeader(HMODULE hModule) noexcept {
		if (!hModule) return;

		DWORD oldProtect{ 0 };
		auto pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
		auto headerSize = pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS64) + 0x200;

		if (::VirtualProtect(hModule, headerSize, PAGE_READWRITE, &oldProtect)) {
			::SecureZeroMemory(hModule, headerSize);
			::VirtualProtect(hModule, headerSize, oldProtect, &oldProtect);
		}
	}

	// Spoof thread start address / Hide from debugger
	inline void HideThreadFromDebugger() noexcept {
		using NtSetInformationThreadFunc = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG);
		const auto ntdll{ ::GetModuleHandleW(L"ntdll.dll") };
		if (ntdll) {
			const auto NtSetInformationThread{ reinterpret_cast<NtSetInformationThreadFunc>(::GetProcAddress(ntdll, "NtSetInformationThread")) };
			if (NtSetInformationThread) {
				// ThreadHideFromDebugger = 0x11
				NtSetInformationThread(::GetCurrentThread(), 0x11, nullptr, 0);
			}
		}
	}

	// Simple VM detection
	inline bool IsVirtualMachine() noexcept {
		// Check registry for VM indicators
		HKEY hKey;
		const wchar_t* vmKeys[] = {
			L"HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0",
			L"HARDWARE\\Description\\System"
		};

		for (const auto* keyPath : vmKeys) {
			if (::RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyPath, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
				wchar_t data[256]{};
				DWORD dataSize{ sizeof(data) };
				
				if (::RegQueryValueExW(hKey, L"Identifier", nullptr, nullptr, reinterpret_cast<LPBYTE>(data), &dataSize) == ERROR_SUCCESS) {
					const std::wstring identifier{ data };
					if (identifier.find(L"VBOX") != std::wstring::npos ||
					    identifier.find(L"VMware") != std::wstring::npos ||
					    identifier.find(L"Virtual") != std::wstring::npos) {
						::RegCloseKey(hKey);
						return true;
					}
				}
				::RegCloseKey(hKey);
			}
		}

		return false;
	}

	// Check for common analysis tools
	inline bool CheckAnalysisTools() noexcept {
		const wchar_t* toolWindows[] = {
			L"OLLYDBG",
			L"x64dbg",
			L"x32dbg",
			L"IDA",
			L"Immunity Debugger",
			L"WinDbg",
			L"Cheat Engine",
			L"Process Hacker",
			L"Process Monitor"
		};

		for (const auto* windowName : toolWindows) {
			if (::FindWindowW(nullptr, windowName) || ::FindWindowW(windowName, nullptr))
				return true;
		}

		return false;
	}

	// Comprehensive environment check
	inline bool IsUnderMonitoring() noexcept {
		// Check TP process
		if (CheckTPProcess())
			return true;

		// Check debugger
		if (IsDebuggerPresent())
			return true;

		// Check analysis tools
		if (CheckAnalysisTools())
			return true;

		return false;
	}

	// Apply all anti-detection measures
	inline void ApplyProtection(HMODULE hModule) noexcept {
		// Hide thread from debugger
		HideThreadFromDebugger();
		
		// Erase PE header (makes memory scanning harder)
		ErasePEHeader(hModule);
		
		// Random delay to avoid timing-based detection
		::Sleep(GetRandomDelay(50, 150));
	}

	// Anti-sandbox delay (run before main initialization)
	inline void DelayExecution() noexcept {
		// Sleep with random jitter to avoid detection
		const auto start{ ::GetTickCount64() };
		::Sleep(GetRandomDelay(100, 300));
		
		// Perform some calculations to look legitimate
		volatile std::uint64_t x{ start };
		for (std::uint32_t i = 0; i < 1000; ++i)
			x = (x * 13 + 7) % 1000000;
	}

	// Check system uptime (sandboxes often have low uptime)
	inline bool IsSandboxByUptime() noexcept {
		return ::GetTickCount64() < 60000; // Less than 1 minute uptime
	}

	// ============== ADVANCED ANTI-DETECTION ==============

	// Check for hardware breakpoints (DR registers)
	inline bool CheckHardwareBreakpoints() noexcept {
		CONTEXT ctx{};
		ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
		
		if (::GetThreadContext(::GetCurrentThread(), &ctx)) {
			return (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0);
		}
		return false;
	}

	// Clear hardware breakpoints
	inline void ClearHardwareBreakpoints() noexcept {
		CONTEXT ctx{};
		ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
		
		if (::GetThreadContext(::GetCurrentThread(), &ctx)) {
			ctx.Dr0 = 0;
			ctx.Dr1 = 0;
			ctx.Dr2 = 0;
			ctx.Dr3 = 0;
			ctx.Dr6 = 0;
			ctx.Dr7 = 0;
			::SetThreadContext(::GetCurrentThread(), &ctx);
		}
	}

	// Detect API hooking by checking for INT3 / JMP at function start
	inline bool IsApiHooked(const char* moduleName, const char* funcName) noexcept {
		const auto hModule{ ::GetModuleHandleA(moduleName) };
		if (!hModule) return false;

		const auto funcAddr{ ::GetProcAddress(hModule, funcName) };
		if (!funcAddr) return false;

		// Check for common hook patterns
		const auto pFunc{ reinterpret_cast<const unsigned char*>(funcAddr) };
		
		// INT3 (0xCC) - Software breakpoint
		if (pFunc[0] == 0xCC)
			return true;
		
		// JMP (0xE9) - Relative jump
		if (pFunc[0] == 0xE9)
			return true;
		
		// MOV RAX, addr; JMP RAX pattern (0x48 0xB8 ... 0xFF 0xE0)
		if (pFunc[0] == 0x48 && pFunc[1] == 0xB8)
			return true;

		return false;
	}

	// Check for memory modification (integrity check)
	inline std::uint32_t CalculateChecksum(void* addr, size_t size) noexcept {
		std::uint32_t checksum{ 0 };
		const auto bytes{ static_cast<const unsigned char*>(addr) };
		for (size_t i = 0; i < size; ++i) {
			checksum = (checksum >> 1) | (checksum << 31);
			checksum += bytes[i];
		}
		return checksum;
	}

	// Timing-based anti-debug (RDTSC)
	inline bool TimingCheck() noexcept {
		__try {
			const auto start{ __rdtsc() };
			
			// Perform some meaningless operations
			volatile int x{ 0 };
			for (int i = 0; i < 100; ++i)
				x += i;
			
			const auto end{ __rdtsc() };
			
			// If too many cycles elapsed, likely being debugged
			// Threshold varies by CPU, 500000 is conservative
			return (end - start) > 500000;
		} __except (EXCEPTION_EXECUTE_HANDLER) {
			return true;
		}
	}

	// Detect Cheat Engine process
	inline bool IsCheatEngineRunning() noexcept {
		const wchar_t* ceNames[] = {
			L"cheatengine",
			L"cheat engine",
			L"ce.exe",
			L"ce-",
			L"autoassemble"
		};

		HANDLE snapshot{ ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
		if (snapshot == INVALID_HANDLE_VALUE)
			return false;

		PROCESSENTRY32W pe32{};
		pe32.dwSize = sizeof(PROCESSENTRY32W);

		bool found{ false };
		if (::Process32FirstW(snapshot, &pe32)) {
			do {
				std::wstring processName{ pe32.szExeFile };
				// Convert to lowercase
				for (auto& c : processName)
					c = towlower(c);
				
				for (const auto* ceName : ceNames) {
					if (processName.find(ceName) != std::wstring::npos) {
						found = true;
						break;
					}
				}
			} while (::Process32NextW(snapshot, &pe32) && !found);
		}

		::CloseHandle(snapshot);
		return found;
	}

	// Obfuscate function calls using indirect call
	template<typename T, typename... Args>
	inline auto IndirectCall(T func, Args&&... args) noexcept {
		volatile auto pFunc{ func };
		return pFunc(std::forward<Args>(args)...);
	}

	// Junk code insertion macro for anti-analysis
	#define ANTI_ANALYSIS_JUNK() \
		do { \
			volatile int __junk_var = 0; \
			__junk_var = (__junk_var + 1) * 3 - 2; \
			if (__junk_var == 0x7FFFFFFF) ::Sleep(1); \
		} while(0)

	// Encrypt a DWORD value (simple XOR)
	inline std::uint32_t EncryptDword(std::uint32_t value, std::uint32_t key = 0xDEADBEEF) noexcept {
		return value ^ key;
	}

	inline std::uint32_t DecryptDword(std::uint32_t encrypted, std::uint32_t key = 0xDEADBEEF) noexcept {
		return encrypted ^ key;
	}

	// Check for loaded analysis DLLs
	inline bool CheckAnalysisDlls() noexcept {
		const wchar_t* suspiciousDlls[] = {
			L"dbghelp.dll",      // Debugging helper
			L"SbieDll.dll",      // Sandboxie
			L"api_log.dll",      // API Monitor
			L"dir_watch.dll",    // Directory watcher
			L"pstorec.dll",      // Protected storage
			L"vmcheck.dll"       // VM check
		};

		for (const auto* dllName : suspiciousDlls) {
			if (::GetModuleHandleW(dllName))
				return true;
		}

		return false;
	}

	// Advanced environment check
	inline bool AdvancedSecurityCheck() noexcept {
		// Check hardware breakpoints
		if (CheckHardwareBreakpoints()) {
			ClearHardwareBreakpoints();
			return true;
		}

		// Check for Cheat Engine
		if (IsCheatEngineRunning())
			return true;

		// Check for analysis DLLs
		if (CheckAnalysisDlls())
			return true;

		// Check for API hooks on critical functions
		if (IsApiHooked("ntdll.dll", "NtQueryInformationProcess") ||
		    IsApiHooked("kernel32.dll", "IsDebuggerPresent"))
			return true;

		// Timing check (very paranoid, disabled by default)
		// if (TimingCheck()) return true;

		return false;
	}

	// Comprehensive startup check
	inline bool PerformStartupChecks() noexcept {
		// Check for sandbox
		if (IsSandboxByUptime()) {
			::Sleep(60000); // Wait if uptime is too low
		}

		// Delay execution
		DelayExecution();

		// Basic monitoring check
		if (IsUnderMonitoring())
			return false;

		// Advanced security check
		if (AdvancedSecurityCheck())
			return false;

		// Return true if safe to continue
		return true;
	}
}
