#pragma warning(disable : 6387 4715)

#include <Windows.h>
#include <clocale>
#include <chrono>
#include <thread>

#include "CheatManager.hpp"
#include "Config.hpp"
#include "Hooks.hpp"
#include "Memory.hpp"
#include "SDK/GameState.hpp"

// Anti-detection includes
#include "AntiDetection.hpp"
#include "CompileTimeRandom.hpp"

// Exported hook procedure for SetWindowsHookEx injection
// This function does nothing but allows the DLL to be loaded into the target process
extern "C" __declspec(dllexport) LRESULT CALLBACK CBTProc(int nCode, WPARAM wParam, LPARAM lParam) {
	return ::CallNextHookEx(nullptr, nCode, wParam, lParam);
}

// Exported hook procedure for GetMessage hook (alternative)
extern "C" __declspec(dllexport) LRESULT CALLBACK GetMsgProc(int nCode, WPARAM wParam, LPARAM lParam) {
	return ::CallNextHookEx(nullptr, nCode, wParam, lParam);
}

bool WINAPI HideThread(const HANDLE hThread) noexcept
{
	__try {
		// Obfuscated string for "NtSetInformationThread"
		// Using simple stack string construction to avoid static string analysis
		wchar_t ntdllStr[] = { 'n','t','d','l','l','.','d','l','l','\0' };
		char funcStr[] = { 'N','t','S','e','t','I','n','f','o','r','m','a','t','i','o','n','T','h','r','e','a','d','\0' };
		
		using FnSetInformationThread = NTSTATUS(NTAPI*)(HANDLE ThreadHandle, UINT ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength);
		const auto NtSetInformationThread{ reinterpret_cast<FnSetInformationThread>(::GetProcAddress(::GetModuleHandleW(ntdllStr), funcStr)) };

		if (!NtSetInformationThread)
			return false;

		// Use random thread info class offset (0x11 is ThreadHideFromDebugger)
		// We use 0x11 directly but could randomize the call timing
		const auto status{ NtSetInformationThread(hThread, 0x11u, nullptr, 0ul) };
		return status == 0x00000000;
	} __except (TRUE) {
		return false;
	}
	return false;
}

__declspec(safebuffers) static void WINAPI DllAttach([[maybe_unused]] LPVOID lp) noexcept
{
	using namespace std::chrono_literals;

	// Anti-sandbox delay
	RANDOM_DELAY();

	cheatManager.start();
	
	if (HideThread(::GetCurrentThread()))
		cheatManager.logger->addLog("Thread Hidden!\n");

	// Wait for game to be ready
	cheatManager.memory->Search(true);
	while (true) {
		std::this_thread::sleep_for(1s);
		
		// Heartbeat check
		if (!AntiDetection::HeartbeatCheck()) {
			// Environment changed, exit silently
			::ExitProcess(0u);
		}
		
		if (!cheatManager.memory->client)
			cheatManager.memory->Search(true);
		else if (cheatManager.memory->client->game_state == GGameState_s::Running)
			break;
	}
	cheatManager.logger->addLog("GameClient found!\n");
	
	std::this_thread::sleep_for(500ms);
	cheatManager.memory->Search(false);
	cheatManager.logger->addLog("All offsets found!\n");
	std::this_thread::sleep_for(500ms);

	cheatManager.config->init();
	cheatManager.config->load();
	cheatManager.gui->is_open = cheatManager.config->isOpen;
	cheatManager.logger->addLog("CFG loaded!\n");
	
	cheatManager.hooks->install();
		
	while (cheatManager.cheatState) {
		std::this_thread::sleep_for(250ms);
		
		// Periodic heartbeat check
		if (!AntiDetection::HeartbeatCheck()) {
			// Environment changed, exit silently
			cheatManager.cheatState = false;
		}
	}

	::ExitProcess(0u);
}

__declspec(safebuffers) BOOL APIENTRY DllMain(const HMODULE hModule, const DWORD reason, [[maybe_unused]] LPVOID reserved)
{
	if (reason == DLL_PROCESS_ATTACH) {
		DisableThreadLibraryCalls(hModule);

		// Environment Check
		if (AntiDetection::IsUnderMonitoring()) {
			// Silently fail or crash safely
			return FALSE;
		}

		HideThread(hModule);
		std::setlocale(LC_ALL, ".utf8");

		// Create a named event to signal successful injection
		// This allows the injector to detect if the DLL is loaded
		// The event name is based on the current process ID
		wchar_t eventName[64];
		swprintf(eventName, 64, L"Global\\MM_%08X", ::GetCurrentProcessId());
		HANDLE hEvent = ::CreateEventW(nullptr, TRUE, TRUE, eventName);
		// Keep the event handle open - it will be closed when the process exits
		
		::_beginthreadex(nullptr, 0u, reinterpret_cast<_beginthreadex_proc_type>(DllAttach), nullptr, 0u, nullptr);
		::CloseHandle(hModule);
		return TRUE;
	}
	
	return FALSE;
}
