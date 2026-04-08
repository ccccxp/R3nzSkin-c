#include <Windows.h>
#include <cstdlib>
#include <fstream>
#include <psapi.h>
#include <string>
#include <thread>
#include <tlhelp32.h>
#include <regex>
#include <msclr/marshal_cppstd.h>

#include "Injector.hpp"
#include "R3nzUI.hpp"
#include "xorstr.hpp"
#include "lazy_importer.hpp"
#include "HookInjector.hpp" // New stealth injector

using namespace System;
using namespace System::Windows::Forms;
using namespace System::Threading;
using namespace System::Globalization;
using namespace System::Net;

#define xor_clrstr_w(x) msclr::interop::marshal_as<String^>(static_cast<std::wstring>(_XorStrW(x)))

proclist_t WINAPI Injector::findProcesses(const std::wstring& name) noexcept
{
	auto process_snap{ LI_FN(CreateToolhelp32Snapshot)(TH32CS_SNAPPROCESS, 0) };
	proclist_t list;

	if (process_snap == INVALID_HANDLE_VALUE)
		return list;

	PROCESSENTRY32W pe32{};
	pe32.dwSize = sizeof(PROCESSENTRY32W);

	if (LI_FN(Process32FirstW).get()(process_snap, &pe32)) {
		if (pe32.szExeFile == name)
			list.push_back(pe32.th32ProcessID);

		while (LI_FN(Process32NextW).get()(process_snap, &pe32)) {
			if (pe32.szExeFile == name)
				list.push_back(pe32.th32ProcessID);
		}
	}

	LI_FN(CloseHandle)(process_snap);
	return list;
}

bool WINAPI Injector::isInjected(const std::uint32_t pid) noexcept
{
	auto hProcess{ LI_FN(OpenProcess)(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid) };

	if (nullptr == hProcess)
		return false;

	HMODULE hMods[1024];
	DWORD cbNeeded{};

	if (LI_FN(K32EnumProcessModules)(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
		for (auto i{ 0u }; i < (cbNeeded / sizeof(HMODULE)); ++i) {
			TCHAR szModName[MAX_PATH];
			if (LI_FN(K32GetModuleBaseNameW)(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(TCHAR))) {
				if (std::wcscmp(szModName, _XorStrW(L"d3d11_helper.dll")) == 0) { // Changed DLL name
					LI_FN(CloseHandle)(hProcess);
					return true;
				}
			}
		}
	}
	LI_FN(CloseHandle)(hProcess);
	return false;
}

bool WINAPI Injector::inject(const std::uint32_t pid) noexcept
{
	TCHAR current_dir[MAX_PATH];
	LI_FN(GetCurrentDirectoryW)(MAX_PATH, current_dir);
	
	// Obfuscated DLL name
	const auto dll_path{ std::wstring(current_dir) + _XorStrW(L"\\d3d11_helper.dll") };

	if (const auto f{ std::ifstream(dll_path) }; !f.is_open()) {
		LI_FN(MessageBoxW)(nullptr, _XorStrW(L"DLL file could not be found.\nTry reinstalling the cheat."), _XorStrW(L"Error"), MB_ICONERROR | MB_OK);
		return false;
	}

	// Use HookInjector instead of CreateRemoteThread
	return HookInjector::InjectViaCBT(pid, dll_path);
}

void WINAPI Injector::enableDebugPrivilege() noexcept
{
	HANDLE token{};
	if (OpenProcessToken(LI_FN(GetCurrentProcess).get()(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
		LUID value;
		if (LookupPrivilegeValueW(nullptr, _XorStrW(SE_DEBUG_NAME), &value)) {
			TOKEN_PRIVILEGES tp{};
			tp.PrivilegeCount = 1;
			tp.Privileges[0].Luid = value;
			tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
			if (AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr))
				LI_FN(CloseHandle)(token);
		}
	}
}

void Injector::autoUpdate()
{
	/* do not even bother if we are from Chinese regions and Brazil */
	auto whitelisted_regions = gcnew array<String^> {
		xor_clrstr_w(L"zh-CN"),
		xor_clrstr_w(L"zh-TW"),
		xor_clrstr_w(L"zh-HK"),
		xor_clrstr_w(L"zh-MO"),
		xor_clrstr_w(L"zh-SG"),
		xor_clrstr_w(L"pt-BR")
	};
	auto current_culture = CultureInfo::CurrentCulture;
	auto region = current_culture->Name;
	for each (auto whitelisted_region in whitelisted_regions)
	{
		if (region->Equals(whitelisted_region, StringComparison::OrdinalIgnoreCase))
		{
			return;
		}
	}
	
    // Auto-update disabled for stealth version to prevent connecting to public GitHub
}

void Injector::run() noexcept
{
	enableDebugPrivilege();
	while (true) {
		const auto& league_client_processes{ Injector::findProcesses(_XorStrW(L"LeagueClient.exe")) };
		const auto& league_processes{ Injector::findProcesses(_XorStrW(L"League of Legends.exe")) };

		R3nzSkinInjector::gameState = (league_processes.size() > 0) ? true : false;
		R3nzSkinInjector::clientState = (league_client_processes.size() > 0) ? true : false;
		
		if (league_processes.size() > 0xff)
			break;

		for (auto& pid : league_processes) {
			if (!Injector::isInjected(pid)) {
				R3nzSkinInjector::cheatState = false;
				if (R3nzSkinInjector::btnState) {
					std::this_thread::sleep_for(1.5s);
					if (Injector::inject(pid))
						R3nzSkinInjector::cheatState = true;
					else
						R3nzSkinInjector::cheatState = false;
				}
				std::this_thread::sleep_for(1s);
			} else {
				R3nzSkinInjector::cheatState = true;
			}
		}
		std::this_thread::sleep_for(1s);
	}
}
