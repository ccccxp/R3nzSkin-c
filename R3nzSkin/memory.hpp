#pragma once

#include <Windows.h>
#include <cstdint>
#include <d3d11.h>

#include "Offsets.hpp"

#include "SDK/AIBaseCommon.hpp"
#include "SDK/AIHero.hpp"
#include "SDK/AITurret.hpp"
#include "SDK/AIMinionClient.hpp"
#include "SDK/ChampionManager.hpp"
#include "SDK/GameClient.hpp"
#include "SDK/ManagerTemplate.hpp"

class offset_signature {
public:
	std::vector<std::string> pattern;
	bool sub_base;
	bool read;
	bool relative;
	std::int32_t additional;
	std::uint64_t* offset;
};

class Memory {
public:
	void Search(bool gameClient = true);

	std::uintptr_t base;
	HWND window;

	GameClient* client;
	AIBaseCommon* localPlayer;
	ManagerTemplate<AIHero>* heroList;
	ManagerTemplate<AIMinionClient>* minionList;
	ManagerTemplate<AITurret>* turretList;
	ChampionManager* championManager;
	
	std::uintptr_t materialRegistry;
	IDXGISwapChain* swapChain;

	using translateString_t = const char* (__fastcall*)(const char*);

	translateString_t translateString;
private:
	void update(bool gameClient = true) noexcept;

	bool gameClientErrorShown{ false };  // Only show error once
	bool sigsErrorShown{ false };

	std::vector<offset_signature> gameClientSig
	{
		{
			{
				// GameClient patterns - historical versions (newest first)
				"48 8B 05 ? ? ? ? 48 8B F2 83 78",          // Current CN server
				"48 8B 05 ? ? ? ? 4C 8B FA 83 78 0C 02",    // Older version (full)
				"48 8B 05 ? ? ? ? 4C 8B FA 83 78",          // Older version (short)
				// New patterns from memory scan
				"48 8B 05 ? ? ? ? 48 8B 40 10 48",          // New variant 1
				"48 8B 05 ? ? ? ? 48 8B D9 48 83",          // New variant 2
				// Ultra generic patterns (more wildcards)
				"48 8B 05 ? ? ? ? 48 8B ? ? 83 78",         // Generic MOV RAX + any reg
				"48 8B 05 ? ? ? ? 4C 8B ? ? 83 78",         // Generic MOV RAX + R8-R15
				"48 8B 0D ? ? ? ? 48 8B ? ? 83 78",         // MOV RCX variant
				"48 8B 0D ? ? ? ? 4C 8B ? ? 83 78",         // MOV RCX + R8-R15
				"48 8B 15 ? ? ? ? 48 8B ? ? 83 78",         // MOV RDX variant
				"48 8B 1D ? ? ? ? 48 8B ? ? 83 78",         // MOV RBX variant
				// State check patterns (game_state == 2)
				"83 78 ? 02 75",                            // cmp [rax+?], 2; jne
				"83 79 ? 02 75",                            // cmp [rcx+?], 2; jne
				"83 78 ? 02 74",                            // cmp [rax+?], 2; je
				"83 ? 10 02"                                // cmp [?+10h], 2 (offset 0x10)
			}, true, false, true, 0, &offsets::global::GameClient
		}
	};

	std::vector<offset_signature> sigs
	{
		{
			{
				"48 8B 3D ? ? ? ? 48 85 FF 74 15 48 81 C7"
			}, true, false, true, 0, &offsets::global::Player
		},
		{
			{
				"48 8B 05 ? ? ? ? 48 8B ? 08 8B 40 ? ? 8D ? ? ? 3B ? 74"
			}, true, false, true, 0, &offsets::global::ManagerTemplate_AIHero_
		},
		{
			{
				"48 8B 0D ? ? ? ? 48 69 D0 ? ? 00 00 48 8B 05"
			}, true, false, true, 0, &offsets::global::ChampionManager
		},
		{
			{
				"48 8B 0D ? ? ? ? E8 ? ? ? ? 48 8B 0D ? ? ? ? E8 ? ? ? ? 48 8B 0D ? ? ? ? E8 ? ? ? ? E8 ? ? ? ? 48 8B 0D ? ? ? ? 48 8B 01"
			}, true, false, true, 0, &offsets::global::ManagerTemplate_AIMinionClient_
		},
		{
			{
				"48 8B 05 ? ? ? ? 48 8B 70 28 48 85 F6 74"
			}, true, false, true, 0, &offsets::global::ManagerTemplate_AITurret_
		},
		{
			{
				"48 8B 0D ? ? ? ? FF 15 ? ? ? ? 48 8B 05 ? ? ? ?"
			}, true, false, true, 0, &offsets::global::Riot__g_window
		},
		{
			{
				"48 8D 8D ? ? 00 00 44 8B 8C 24 ? ? 00 00"
			}, false, true, false, 0, &offsets::AIBaseCommon::CharacterDataStack
		},
		{
			{
				"88 86 ? ? 00 00 48 89 45 ? 0F B6 45 A8 88 86 ? 13"
			}, false, true, false, 0, &offsets::AIBaseCommon::SkinId
		},
		{
			{
				"48 8D BB ? ? ? ? C6 83 ? ? ? ? ? 0F 84"
			}, false, true, false, 0, &offsets::MaterialRegistry::SwapChain
		},
		{
			{
				"E8 ? ? ? ? 8B 95 ? ? 00 00 48 8B 0D ? ? ? ? E8 ? ? ? ? 48 8B D8"
			}, true, false, false, 0, &offsets::functions::CharacterDataStack__Push
		},
		{
			{
				"88 54 24 10 55 53 56 57 41 54 41 55 41 56 41"
			}, true, false, false, 0, &offsets::functions::CharacterDataStack__Update
		},
		{
			{
				"E8 ? ? ? ? 8B 57 34 45 33 C9"
			}, true, false, false, 0, &offsets::functions::Riot__Renderer__MaterialRegistry__GetSingletonPtr
		},
		{
			{
				"E8 ? ? ? ? 0F 57 DB 4C 8B C0 F3 0F 5A DE"
			}, true, false, false, 0, &offsets::functions::translateString_UNSAFE_DONOTUSE
		},
		{
			{
				"E8 ? ? ? ? 4C 3B ? 0F 94 C0"
			}, true, false, false, 0, &offsets::functions::GetGoldRedirectTarget
		}
	};
};
