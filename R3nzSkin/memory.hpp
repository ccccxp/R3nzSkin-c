#pragma once

#include <Windows.h>
#include <cstdint>
#include <d3d11.h>
#include <vector>
#include <string>

#include "Offsets.hpp"

#include "SDK/AIBaseCommon.hpp"
#include "SDK/AIHero.hpp"
#include "SDK/AITurret.hpp"
#include "SDK/AIMinionClient.hpp"
#include "SDK/ChampionManager.hpp"
#include "SDK/GameClient.hpp"
#include "SDK/ManagerTemplate.hpp"

// Encrypted signature class - stores signature in encrypted form and decrypts at runtime
class EncryptedSignature {
private:
	std::vector<std::uint8_t> encrypted_data;
	std::uint8_t xor_key;

public:
	EncryptedSignature(const char* pattern) noexcept {
		// Generate random XOR key based on compile time
		xor_key = static_cast<std::uint8_t>((__TIME__[7] - '0') * 10 + (__TIME__[6] - '0') +
			(__TIME__[4] - '0') * 60 + (__TIME__[3] - '0') * 600 +
			(__TIME__[1] - '0') * 3600 + (__TIME__[0] - '0') * 36000);
		
		// Encrypt the pattern string
		auto len = strlen(pattern);
		encrypted_data.resize(len);
		for (size_t i = 0; i < len; ++i) {
			encrypted_data[i] = static_cast<std::uint8_t>(pattern[i]) ^ xor_key;
		}
	}

	// Decrypt and return the pattern string
	std::string decrypt() const noexcept {
		std::string result;
		result.resize(encrypted_data.size());
		for (size_t i = 0; i < encrypted_data.size(); ++i) {
			result[i] = static_cast<char>(encrypted_data[i] ^ xor_key);
		}
		return result;
	}
};

class offset_signature {
public:
	std::vector<EncryptedSignature> encrypted_patterns;  // Encrypted patterns
	std::vector<std::string> pattern;  // Legacy patterns (for compatibility)
	bool sub_base;
	bool read;
	bool relative;
	std::int32_t additional;
	std::uint64_t* offset;

	// Constructor for encrypted patterns
	offset_signature(std::vector<EncryptedSignature> enc_patterns, bool sb, bool r, bool rel, std::int32_t add, std::uint64_t* off)
		: encrypted_patterns(std::move(enc_patterns)), sub_base(sb), read(r), relative(rel), additional(add), offset(off) {}

	// Constructor for legacy patterns
	offset_signature(std::vector<std::string> p, bool sb, bool r, bool rel, std::int32_t add, std::uint64_t* off)
		: pattern(std::move(p)), sub_base(sb), read(r), relative(rel), additional(add), offset(off) {}

	// Get decrypted patterns
	std::vector<std::string> get_patterns() const noexcept {
		if (!encrypted_patterns.empty()) {
			std::vector<std::string> result;
			for (const auto& enc : encrypted_patterns) {
				result.push_back(enc.decrypt());
			}
			return result;
		}
		return pattern;
	}
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

	// Game client signatures - using encrypted patterns
	std::vector<offset_signature> gameClientSig
	{
		offset_signature(
			{ EncryptedSignature("48 8B 05 ? ? ? ? 48 8B F2 83 78") },
			true, false, true, 0, &offsets::global::GameClient
		)
	};

	// Main signatures - using encrypted patterns
	std::vector<offset_signature> sigs
	{
		offset_signature(
			{ EncryptedSignature("48 8B 3D ? ? ? ? 48 85 FF 74 15 48 81 C7") },
			true, false, true, 0, &offsets::global::Player
		),
		offset_signature(
			{ EncryptedSignature("48 8B 05 ? ? ? ? 48 8B ? 08 8B 40 ? ? 8D ? ? ? 3B ? 74") },
			true, false, true, 0, &offsets::global::ManagerTemplate_AIHero_
		),
		offset_signature(
			{ EncryptedSignature("48 8B 0D ? ? ? ? 48 69 D0 ? ? 00 00 48 8B 05") },
			true, false, true, 0, &offsets::global::ChampionManager
		),
		offset_signature(
			{ EncryptedSignature("48 8B 0D ? ? ? ? E8 ? ? ? ? 48 8B 0D ? ? ? ? E8 ? ? ? ? 48 8B 0D ? ? ? ? E8 ? ? ? ? E8 ? ? ? ? 48 8B 0D ? ? ? ? 48 8B 01") },
			true, false, true, 0, &offsets::global::ManagerTemplate_AIMinionClient_
		),
		offset_signature(
			{ EncryptedSignature("48 8B 05 ? ? ? ? 48 8B 70 28 48 85 F6 74") },
			true, false, true, 0, &offsets::global::ManagerTemplate_AITurret_
		),
		offset_signature(
			{ EncryptedSignature("48 8B 0D ? ? ? ? FF 15 ? ? ? ? 48 8B 05 ? ? ? ?") },
			true, false, true, 0, &offsets::global::Riot__g_window
		),
		offset_signature(
			{ EncryptedSignature("48 8D 8D ? ? 00 00 44 8B 8C 24 ? ? 00 00") },
			false, true, false, 0, &offsets::AIBaseCommon::CharacterDataStack
		),
		offset_signature(
			{ EncryptedSignature("88 87 ? ? 00 00 48 89 45 87 0F B6 45 88 88 87 ? 13") },
			false, true, false, 0, &offsets::AIBaseCommon::SkinId
		),
		offset_signature(
			{ EncryptedSignature("48 8D BB ? ? ? ? C6 83 ? ? ? ? ? 0F 84") },
			false, true, false, 0, &offsets::MaterialRegistry::SwapChain
		),
		offset_signature(
			{ EncryptedSignature("E8 ? ? ? ? 8B 95 ? ? 00 00 48 8B 0D ? ? ? ? E8 ? ? ? ? 48 8B D8") },
			true, false, false, 0, &offsets::functions::CharacterDataStack__Push
		),
		offset_signature(
			{ EncryptedSignature("4C 8B DC 53 56 57 48 83 EC ? 49") },
			true, false, false, 0, &offsets::functions::CharacterDataStack__Update
		),
		offset_signature(
			{ EncryptedSignature("E8 ? ? ? ? 8B 57 34 45 33 C9") },
			true, false, false, 0, &offsets::functions::Riot__Renderer__MaterialRegistry__GetSingletonPtr
		),
		offset_signature(
			{ EncryptedSignature("E8 ? ? ? ? 0F 57 DB 4C 8B C0 F3 0F 5A DE") },
			true, false, false, 0, &offsets::functions::translateString_UNSAFE_DONOTUSE
		),
		offset_signature(
			{ EncryptedSignature("E8 ? ? ? ? 4C 3B ? 0F 94 C0") },
			true, false, false, 0, &offsets::functions::GetGoldRedirectTarget
		)
	};
};
