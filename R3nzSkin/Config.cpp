#include <Windows.h>
#include <string>
#include <system_error>

#include "CheatManager.hpp"
#include "Config.hpp"
#include "Memory.hpp"

// Registry path disguised as Windows Game Overlay (for stealth)
const wchar_t* Config::registryPath = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\GameOverlay";

// Helper: Save DWORD to registry
bool Config::saveToRegistry(const wchar_t* valueName, DWORD data) noexcept
{
	HKEY hKey;
	if (::RegCreateKeyExW(HKEY_CURRENT_USER, registryPath, 0, nullptr, 0, KEY_WRITE, nullptr, &hKey, nullptr) != ERROR_SUCCESS)
		return false;

	const auto result{ ::RegSetValueExW(hKey, valueName, 0, REG_DWORD, reinterpret_cast<const BYTE*>(&data), sizeof(DWORD)) == ERROR_SUCCESS };
	::RegCloseKey(hKey);
	return result;
}

// Helper: Save string to registry
bool Config::saveToRegistry(const wchar_t* valueName, const std::wstring& data) noexcept
{
	HKEY hKey;
	if (::RegCreateKeyExW(HKEY_CURRENT_USER, registryPath, 0, nullptr, 0, KEY_WRITE, nullptr, &hKey, nullptr) != ERROR_SUCCESS)
		return false;

	const auto result{ ::RegSetValueExW(hKey, valueName, 0, REG_SZ, reinterpret_cast<const BYTE*>(data.c_str()), static_cast<DWORD>((data.length() + 1) * sizeof(wchar_t))) == ERROR_SUCCESS };
	::RegCloseKey(hKey);
	return result;
}

// Helper: Load DWORD from registry
DWORD Config::loadFromRegistry(const wchar_t* valueName, DWORD defaultValue) noexcept
{
	HKEY hKey;
	if (::RegOpenKeyExW(HKEY_CURRENT_USER, registryPath, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
		return defaultValue;

	DWORD data{ 0 };
	DWORD dataSize{ sizeof(DWORD) };
	DWORD type{ 0 };

	if (::RegQueryValueExW(hKey, valueName, nullptr, &type, reinterpret_cast<BYTE*>(&data), &dataSize) != ERROR_SUCCESS || type != REG_DWORD) {
		::RegCloseKey(hKey);
		return defaultValue;
	}

	::RegCloseKey(hKey);
	return data;
}

// Helper: Load string from registry
std::wstring Config::loadFromRegistry(const wchar_t* valueName, const std::wstring& defaultValue) noexcept
{
	HKEY hKey;
	if (::RegOpenKeyExW(HKEY_CURRENT_USER, registryPath, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
		return defaultValue;

	DWORD dataSize{ 0 };
	DWORD type{ 0 };

	// Get size first
	if (::RegQueryValueExW(hKey, valueName, nullptr, &type, nullptr, &dataSize) != ERROR_SUCCESS || type != REG_SZ) {
		::RegCloseKey(hKey);
		return defaultValue;
	}

	std::wstring data(dataSize / sizeof(wchar_t), L'\0');
	if (::RegQueryValueExW(hKey, valueName, nullptr, nullptr, reinterpret_cast<BYTE*>(&data[0]), &dataSize) != ERROR_SUCCESS) {
		::RegCloseKey(hKey);
		return defaultValue;
	}

	::RegCloseKey(hKey);
	
	// Remove null terminator
	if (!data.empty() && data.back() == L'\0')
		data.pop_back();
		
	return data;
}

void Config::init() noexcept
{
	// Nothing needed for registry-based config
}

void Config::save() noexcept
{
	const auto player{ cheatManager.memory->localPlayer };

	// Save player skin config
	if (player) {
		const auto championName{ std::string(player->get_character_data_stack()->base_skin.model.str) };
		saveToRegistry((L"PlayerSkin_" + std::wstring(championName.begin(), championName.end())).c_str(), static_cast<DWORD>(this->current_combo_skin_index));
	}

	// Save hotkeys as KeyCode enum index (not VK code!)
	saveToRegistry(L"MenuKeyCode", static_cast<DWORD>(this->menuKey.getKeyCode()));
	saveToRegistry(L"NextSkinKeyCode", static_cast<DWORD>(this->nextSkinKey.getKeyCode()));
	saveToRegistry(L"PrevSkinKeyCode", static_cast<DWORD>(this->previousSkinKey.getKeyCode()));

	// Save options
	saveToRegistry(L"HeroName", static_cast<DWORD>(this->heroName ? 1 : 0));
	saveToRegistry(L"RainbowText", static_cast<DWORD>(this->rainbowText ? 1 : 0));
	saveToRegistry(L"QuickSkinChange", static_cast<DWORD>(this->quickSkinChange ? 1 : 0));
	saveToRegistry(L"IsOpen", static_cast<DWORD>(this->isOpen ? 1 : 0));

	// Save float as bits
	const auto fontScaleBits{ *reinterpret_cast<const DWORD*>(&this->fontScale) };
	saveToRegistry(L"FontScale", fontScaleBits);

	// Save ward and minion config
	saveToRegistry(L"WardIndex", static_cast<DWORD>(this->current_combo_ward_index));
	saveToRegistry(L"WardSkin", static_cast<DWORD>(this->current_ward_skin_index));
	saveToRegistry(L"MinionSkin", static_cast<DWORD>(this->current_minion_skin_index));

	// Save ally skins as JSON string
	if (!this->current_combo_ally_skin_index.empty()) {
		json ally_json;
		for (const auto& [hash, skinIdx] : this->current_combo_ally_skin_index)
			ally_json[std::to_string(hash)] = skinIdx;
		const auto jsonStr{ ally_json.dump() };
		saveToRegistry(L"AllySkins", std::wstring(jsonStr.begin(), jsonStr.end()));
	}

	// Save enemy skins as JSON string
	if (!this->current_combo_enemy_skin_index.empty()) {
		json enemy_json;
		for (const auto& [hash, skinIdx] : this->current_combo_enemy_skin_index)
			enemy_json[std::to_string(hash)] = skinIdx;
		const auto jsonStr{ enemy_json.dump() };
		saveToRegistry(L"EnemySkins", std::wstring(jsonStr.begin(), jsonStr.end()));
	}

	// Save jungle mob skins as JSON string
	if (!this->current_combo_jungle_mob_skin_index.empty()) {
		json jungle_json;
		for (const auto& [hash, skinIdx] : this->current_combo_jungle_mob_skin_index)
			jungle_json[std::to_string(hash)] = skinIdx;
		const auto jsonStr{ jungle_json.dump() };
		saveToRegistry(L"JungleSkins", std::wstring(jsonStr.begin(), jsonStr.end()));
	}
}

void Config::load() noexcept
{
	const auto player{ cheatManager.memory->localPlayer };

	// Load player skin config
	if (player) {
		const auto championName{ std::string(player->get_character_data_stack()->base_skin.model.str) };
		this->current_combo_skin_index = static_cast<std::int32_t>(loadFromRegistry((L"PlayerSkin_" + std::wstring(championName.begin(), championName.end())).c_str(), 0));
	}

	// Load hotkeys as KeyCode enum index (not VK code!)
	// First try new format (KeyCode), then fallback to old format for migration
	auto menuKeyCode = loadFromRegistry(L"MenuKeyCode", static_cast<DWORD>(KeyBind::MAX));
	auto nextKeyCode = loadFromRegistry(L"NextSkinKeyCode", static_cast<DWORD>(KeyBind::MAX));
	auto prevKeyCode = loadFromRegistry(L"PrevSkinKeyCode", static_cast<DWORD>(KeyBind::MAX));
	
	// Use new format if valid, otherwise use defaults
	this->menuKey = KeyBind(static_cast<KeyBind::KeyCode>(menuKeyCode < KeyBind::MAX ? menuKeyCode : KeyBind::INSERT));
	this->nextSkinKey = KeyBind(static_cast<KeyBind::KeyCode>(nextKeyCode < KeyBind::MAX ? nextKeyCode : KeyBind::PAGE_UP));
	this->previousSkinKey = KeyBind(static_cast<KeyBind::KeyCode>(prevKeyCode < KeyBind::MAX ? prevKeyCode : KeyBind::PAGE_DOWN));

	// Load options
	this->heroName = loadFromRegistry(L"HeroName", 1) != 0;
	this->rainbowText = loadFromRegistry(L"RainbowText", 0) != 0;
	this->quickSkinChange = loadFromRegistry(L"QuickSkinChange", 0) != 0;
	this->isOpen = loadFromRegistry(L"IsOpen", 1) != 0;

	// Load float from bits
	static const float defaultFontScale = 1.0f;
	const auto fontScaleBits{ loadFromRegistry(L"FontScale", *reinterpret_cast<const DWORD*>(&defaultFontScale)) };
	this->fontScale = *reinterpret_cast<const float*>(&fontScaleBits);

	// Load ward and minion config
	this->current_combo_ward_index = static_cast<std::int32_t>(loadFromRegistry(L"WardIndex", 0));
	this->current_ward_skin_index = static_cast<std::int32_t>(loadFromRegistry(L"WardSkin", static_cast<DWORD>(-1)));
	this->current_minion_skin_index = static_cast<std::int32_t>(loadFromRegistry(L"MinionSkin", static_cast<DWORD>(-1)));

	// Load ally skins from JSON
	const auto allySkinsStr{ loadFromRegistry(L"AllySkins", L"") };
	if (!allySkinsStr.empty()) {
		try {
			json ally_json = json::parse(std::string(allySkinsStr.begin(), allySkinsStr.end()));
			for (const auto& [key, value] : ally_json.items())
				this->current_combo_ally_skin_index[std::stoull(key)] = value.get<std::int32_t>();
		} catch (...) {}
	}

	// Load enemy skins from JSON
	const auto enemySkinsStr{ loadFromRegistry(L"EnemySkins", L"") };
	if (!enemySkinsStr.empty()) {
		try {
			json enemy_json = json::parse(std::string(enemySkinsStr.begin(), enemySkinsStr.end()));
			for (const auto& [key, value] : enemy_json.items())
				this->current_combo_enemy_skin_index[std::stoull(key)] = value.get<std::int32_t>();
		} catch (...) {}
	}

	// Load jungle mob skins from JSON
	const auto jungleSkinsStr{ loadFromRegistry(L"JungleSkins", L"") };
	if (!jungleSkinsStr.empty()) {
		try {
			json jungle_json = json::parse(std::string(jungleSkinsStr.begin(), jungleSkinsStr.end()));
			for (const auto& [key, value] : jungle_json.items())
				this->current_combo_jungle_mob_skin_index[std::stoull(key)] = value.get<std::int32_t>();
		} catch (...) {}
	}
}

void Config::reset() noexcept
{
	this->menuKey = KeyBind(KeyBind::INSERT);
	this->nextSkinKey = KeyBind(KeyBind::PAGE_UP);
	this->previousSkinKey = KeyBind(KeyBind::PAGE_DOWN);
	this->heroName = true;
	this->rainbowText = false;
	this->quickSkinChange = false;
	this->isOpen = true;
	this->fontScale = 1.0f;
	this->current_combo_skin_index = 0;
	this->current_combo_ward_index = 0;
	this->current_combo_minion_index = 0;
	this->current_minion_skin_index = -1;
	this->current_ward_skin_index = -1;
	this->current_combo_order_turret_index = 0;
	this->current_combo_chaos_turret_index = 0;
	this->current_combo_ally_skin_index.clear();
	this->current_combo_enemy_skin_index.clear();
	this->current_combo_jungle_mob_skin_index.clear();
}
