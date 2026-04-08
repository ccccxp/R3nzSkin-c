#pragma once

#include <Windows.h>
#include <TlHelp32.h>
#include <cstdint>
#include <string>
#include <intrin.h>

// Anti-detection utilities for China server
namespace AntiDetection {
	// Check if Tencent TP is running
	inline bool CheckTPProcess() noexcept {
		HANDLE snapshot{ ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
		if (snapshot == INVALID_HANDLE_VALUE)
			return false;

		PROCESSENTRY32W pe32{};
		pe32.dwSize = sizeof(PROCESSENTRY32W);

		// Known TP process names - expanded list
		const wchar_t* tpProcesses[] = {
			L"TenProtect.exe",
			L"TPHelper.exe",
			L"TProtect.exe",
			L"TP.exe",
			L"GameProtect.exe",
			L"AntiCheatExpert.exe",
			L"ACE-Base64.exe",
			L"ACE-AT64.exe",
			L"QQPCRTP.exe",
			L"QQPCTray.exe"
		};

		bool found{ false };
		if (::Process32FirstW(snapshot, &pe32)) {
			do {
				for (const auto* tpName : tpProcesses) {
					if (::wcscmp(pe32.szExeFile, tpName) == 0) {
						found = true;
						break;
					}
				}
			} while (::Process32NextW(snapshot, &pe32) && !found);
		}

		::CloseHandle(snapshot);
		return found;
	}

	// Check for TP pre-start mode (driver-based detection)
	inline bool CheckTPPreStart() noexcept {
		// Check for TP driver
		HANDLE hDevice = ::CreateFileW(
			L"\\\\.\\TenProtect",
			GENERIC_READ,
			FILE_SHARE_READ | FILE_SHARE_WRITE,
			nullptr,
			OPEN_EXISTING,
			0,
			nullptr
		);
		
		if (hDevice != INVALID_HANDLE_VALUE) {
			::CloseHandle(hDevice);
			return true;
		}
		
		// Check for ACE driver
		hDevice = ::CreateFileW(
			L"\\\\.\\ACE",
			GENERIC_READ,
			FILE_SHARE_READ | FILE_SHARE_WRITE,
			nullptr,
			OPEN_EXISTING,
			0,
			nullptr
		);
		
		if (hDevice != INVALID_HANDLE_VALUE) {
			::CloseHandle(hDevice);
			return true;
		}
		
		return false;
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

		// Method 4: Hardware breakpoint detection
		CONTEXT ctx{};
		ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
		if (::GetThreadContext(::GetCurrentThread(), &ctx)) {
			if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3)
				return true;
		}

		// Method 5: Timing check (anti-debug)
		LARGE_INTEGER freq, start, end;
		::QueryPerformanceFrequency(&freq);
		::QueryPerformanceCounter(&start);
		
		// Perform some operations
		volatile int dummy = 0;
		for (int i = 0; i < 1000; ++i) dummy += i;
		
		::QueryPerformanceCounter(&end);
		auto elapsed = (end.QuadPart - start.QuadPart) * 1000000 / freq.QuadPart;
		
		// If elapsed time is too high, debugger might be present
		if (elapsed > 10000) // 10ms threshold
			return true;

		return false;
	}

	// Enhanced debugger detection
	inline bool IsDebuggerPresentEx() noexcept {
		// Check for x64dbg/x32dbg
		const wchar_t* debuggerWindows[] = {
			L"OLLYDBG",
			L"IDA",
			L"ida64",
			L"x64dbg",
			L"x32dbg",
			L"WinDbg",
			L"ImmunityDebugger",
			L"Cheat Engine"
		};
		
		for (const auto* className : debuggerWindows) {
			if (::FindWindowW(className, nullptr))
				return true;
		}
		
		// Check for debugger processes
		const wchar_t* debuggerProcesses[] = {
			L"ollydbg.exe",
			L"ida.exe",
			L"ida64.exe",
			L"x64dbg.exe",
			L"x32dbg.exe",
			L"windbg.exe",
			L"immunitydebugger.exe",
			L"cheatengine-x86_64.exe",
			L"cheatengine-i386.exe"
		};
		
		HANDLE snapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (snapshot != INVALID_HANDLE_VALUE) {
			PROCESSENTRY32W pe32{};
			pe32.dwSize = sizeof(PROCESSENTRY32W);
			
			if (::Process32FirstW(snapshot, &pe32)) {
				do {
					for (const auto* procName : debuggerProcesses) {
						if (_wcsicmp(pe32.szExeFile, procName) == 0) {
							::CloseHandle(snapshot);
							return true;
						}
					}
				} while (::Process32NextW(snapshot, &pe32));
			}
			::CloseHandle(snapshot);
		}
		
		return false;
	}

	// Check for analysis tools
	inline bool IsAnalysisToolPresent() noexcept {
		// Check for ProcessMonitor
		if (::FindWindowW(L"PROCMON_WINDOW_CLASS", nullptr))
			return true;
		
		// Check for Process Explorer
		if (::FindWindowW(L"PROCEXPLORER", nullptr))
			return true;
		
		// Check for Wireshark
		if (::FindWindowW(L"Wireshark", nullptr))
			return true;
		
		// Check for API Monitor
		if (::FindWindowW(L"APIMonitor", nullptr))
			return true;
		
		// Check for analysis tool processes
		const wchar_t* analysisProcesses[] = {
			L"procmon.exe",
			L"procexp.exe",
			L"procexp64.exe",
			L"wireshark.exe",
			L"apimonitor.exe",
			L"regshot.exe",
			L"pestudio.exe",
			L"die.exe",  // Detect It Easy
			L"PEiD.exe"
		};
		
		HANDLE snapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (snapshot != INVALID_HANDLE_VALUE) {
			PROCESSENTRY32W pe32{};
			pe32.dwSize = sizeof(PROCESSENTRY32W);
			
			if (::Process32FirstW(snapshot, &pe32)) {
				do {
					for (const auto* procName : analysisProcesses) {
						if (_wcsicmp(pe32.szExeFile, procName) == 0) {
							::CloseHandle(snapshot);
							return true;
						}
					}
				} while (::Process32NextW(snapshot, &pe32));
			}
			::CloseHandle(snapshot);
		}
		
		return false;
	}

	// Simple VM detection
	inline bool IsVirtualMachine() noexcept {
		// Check for VMware (x86/x64 compatible)
		// MSVC x64 doesn't support inline asm, using intrinsics or just registry check
#if defined(_M_IX86)
		__try {
			__asm {
				push   edx
				push   ecx
				push   ebx

				mov    eax, 'VMXh'
				mov    ebx, 0
				mov    ecx, 10
				mov    edx, 'VX'
				
				in     eax, dx

				pop    ebx
				pop    ecx
				pop    edx
			}
		} __except (EXCEPTION_EXECUTE_HANDLER) {
			return false;
		}
#endif

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

		// Check CPUID for VM signatures
		int cpuInfo[4] = { 0 };
		__cpuid(cpuInfo, 0x40000000);
		
		// Check for hypervisor vendor
		if (cpuInfo[1] == 0x7263694D &&  // "Micr"
			cpuInfo[2] == 0x666F736F &&  // "osof"
			cpuInfo[3] == 0x76482074) {  // "t Hv"
			return true;  // Microsoft Hyper-V
		}
		
		if (cpuInfo[1] == 0x564D566D &&  // "VMVm"
			cpuInfo[2] == 0x65726177 &&  // "eraw"
			cpuInfo[3] == 0x4D566572) {  // "MVer"
			return true;  // VMware
		}
		
		if (cpuInfo[1] == 0x566E6558 &&  // "VneX"
			cpuInfo[2] == 0x65584D4D &&  // "eXMM"
			cpuInfo[3] == 0x4D4D566E) {  // "MMVn"
			return true;  // Xen
		}

		return false;
	}

	// Check for sandbox environment
	inline bool IsSandbox() noexcept {
		// Check for common sandbox usernames
		wchar_t username[256]{};
		DWORD size = sizeof(username) / sizeof(wchar_t);
		if (::GetUserNameW(username, &size)) {
			const wchar_t* sandboxUsers[] = {
				L"CurrentUser",
				L"Sandbox",
				L"malware",
				L"maltest",
				L"test",
				L"virus",
				L"John Doe",
				L"Emily",
				L"HAPUBWS",
				L"Peter Wilson",
				L"timmy",
				L"user",
				L"schimansky"
			};
			
			for (const auto* user : sandboxUsers) {
				if (_wcsicmp(username, user) == 0)
					return true;
			}
		}
		
		// Check for low memory (sandboxes often have limited resources)
		MEMORYSTATUSEX memStatus{};
		memStatus.dwLength = sizeof(memStatus);
		if (::GlobalMemoryStatusEx(&memStatus)) {
			// Less than 2GB RAM might indicate sandbox
			if (memStatus.ullTotalPhys < 2ULL * 1024 * 1024 * 1024)
				return true;
		}
		
		// Check for low disk space
		ULARGE_INTEGER freeBytesAvailable;
		if (::GetDiskFreeSpaceExW(L"C:\\", &freeBytesAvailable, nullptr, nullptr)) {
			// Less than 60GB free space might indicate sandbox
			if (freeBytesAvailable.QuadPart < 60ULL * 1024 * 1024 * 1024)
				return true;
		}
		
		return false;
	}

	// Comprehensive environment check
	inline bool IsUnderMonitoring() noexcept {
		// Check TP process
		if (CheckTPProcess())
			return true;

		// Check TP pre-start mode
		if (CheckTPPreStart())
			return true;

		// Check debugger
		if (IsDebuggerPresent())
			return true;

		// Check enhanced debugger
		if (IsDebuggerPresentEx())
			return true;

		// Check analysis tools
		if (IsAnalysisToolPresent())
			return true;

		// Check VM (optional - may cause false positives)
		// if (IsVirtualMachine())
		//     return true;

		// Check sandbox
		if (IsSandbox())
			return true;

		return false;
	}

	// Anti-sandbox delay (run before main initialization)
	inline void DelayExecution() noexcept {
		// Sleep with random jitter to avoid detection
		const auto start{ ::GetTickCount64() };
		::Sleep(100 + (start % 200)); // 100-300ms
		
		// Perform some calculations to look legitimate
		volatile std::uint64_t x{ start };
		for (std::uint32_t i = 0; i < 1000; ++i)
			x = (x * 13 + 7) % 1000000;
	}

	// Heartbeat check - call periodically to detect if environment changes
	inline bool HeartbeatCheck() noexcept {
		static DWORD lastCheck = 0;
		DWORD currentTime = ::GetTickCount();
		
		// Check every 30 seconds
		if (currentTime - lastCheck < 30000)
			return true;
		
		lastCheck = currentTime;
		
		// Re-check environment
		if (IsUnderMonitoring())
			return false;
		
		return true;
	}
}
