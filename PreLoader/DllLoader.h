#ifndef UNICODE
#define UNICODE
#endif

#include <Windows.h>

typedef __int8  i8;
typedef __int16 i16;
typedef __int32 i32;
typedef __int64 i64;

typedef unsigned __int8  u8;
typedef unsigned __int16 u16;
typedef unsigned __int32 u32;
typedef unsigned __int64 u64;

#ifdef _WIN64
typedef unsigned __int64 uAddr;
#else
typedef unsigned __int32 uAddr;
#endif
#define uAddr_defined

typedef u8  ubyte;
typedef u16 ushort;
typedef u32 uint;
typedef u64 ulong;

#ifdef _DEBUG
#define dprintf(...)   printf(__VA_ARGS__)
#define dwprintf(...) wprintf(__VA_ARGS__)
#else
#define dprintf(...)  do {} while(0)
#define dwprintf(...) do {} while(0)
#endif

template<typename T>
void WriteMem(uAddr address, T value)
{
	DWORD oldProtect;
	VirtualProtect(LPVOID(address), sizeof T, PAGE_EXECUTE_READWRITE, &oldProtect);
	*reinterpret_cast<T*>(address) = value;
	VirtualProtect(LPVOID(address), sizeof T, oldProtect, &oldProtect);
}

template<typename T>
void WriteMemRaw(uAddr address, T value)
{
	*reinterpret_cast<T*>(address) = value;
}

#define WriteInt(address, value)  WriteMem(address, int(value))
#define WriteUInt(address, value)  WriteMem(address, uint(value))
#define WriteUAddr(address, value)  WriteMem(address, uAddr(value))

#define WriteShort(address, value)   WriteMem(address, short(value))
#define WriteUShort(address, value)  WriteMem(address, ushort(value))

#define WriteByte(address, value)  WriteMem(address, byte(value))


#define WriteIntRaw(address, value)  WriteMemRaw(address, int(value))
#define WriteUIntRaw(address, value)  WriteMemRaw(address, uint(value))
#define WriteUAddrRaw(address, value)  WriteMemRaw(address, uAddr(value))

#define WriteShortRaw(address, value)   WriteMemRaw(address, short(value))
#define WriteUShortRaw(address, value)  WriteMemRaw(address, ushort(value))

#define WriteByteRaw(address, value)  WriteMemRaw(address, byte(value))


#define dll_export extern "C" __declspec(dllexport) void __cdecl
#define var_export extern "C" __declspec(dllexport)


HMODULE hDll;

namespace API_EXPORT {
	inline void PLACE_HOLDER(DWORD n)
	{
		SleepEx(n, TRUE);
	}

	dll_export GetFileVersionInfoA(void) { PLACE_HOLDER(1); }
	dll_export GetFileVersionInfoByHandle(void) { PLACE_HOLDER(2); }
	dll_export GetFileVersionInfoExW(void) { PLACE_HOLDER(3); }
	dll_export GetFileVersionInfoSizeA(void) { PLACE_HOLDER(4); }
	dll_export GetFileVersionInfoSizeExW(void) { PLACE_HOLDER(5); }
	dll_export GetFileVersionInfoSizeW(void) { PLACE_HOLDER(6); }
	dll_export GetFileVersionInfoW(void) { PLACE_HOLDER(7); }
	dll_export VerFindFileA(void) { PLACE_HOLDER(8); }
	dll_export VerFindFileW(void) { PLACE_HOLDER(9); }
	dll_export VerInstallFileA(void) { PLACE_HOLDER(10); }
	dll_export VerInstallFileW(void) { PLACE_HOLDER(11); }
	dll_export VerLanguageNameA(void) { PLACE_HOLDER(12); }
	dll_export VerLanguageNameW(void) { PLACE_HOLDER(13); }
	dll_export VerQueryValueA(void) { PLACE_HOLDER(14); }
	dll_export VerQueryValueW(void) { PLACE_HOLDER(15); }
	dll_export VerQueryValueIndexA(void) { PLACE_HOLDER(16); }
	dll_export VerQueryValueIndexW(void) { PLACE_HOLDER(17); };
}

void FixSingleApi(LPCSTR lpProcName, uAddr fnEntry)
{
	// In x64 bit system, 
	// When compile as DEBUG, it will generate code like jmp xxxx
	// Which is not long enough to hold a 64-bit address.

	// Where as in RELEASE mode, it will just pass the *real* address
	// to this function.

	FARPROC fnDest = GetProcAddress(hDll, lpProcName);
	if (fnEntry && fnDest)
	{
		DWORD oldProtect;
#ifdef _WIN64
#define SHELL_LENGTH 14
#else
#define SHELL_LENGTH 5
#endif
		VirtualProtect(reinterpret_cast<void*>(fnEntry), SHELL_LENGTH, PAGE_EXECUTE_READWRITE, &oldProtect);

#ifdef _WIN64

#if TRUE
		// TODO: Use less bytes.
		/*
		00007FFC7DADAA61 | 68 78 56 34 12                       | push LOW32
		00007FFC7DADAA66 | C7 44 24 04 78 56 34 12              | mov dword ptr ss:[rsp+4], HI32
		00007FFC7DADAA6E | C3                                   | ret
		*/

		ubyte szPayload[] = {
			0x68, 0, 0, 0, 0,
			0xC7, 0x44, 0x24, 0x04, 0, 0, 0, 0,
			0xC3
		};

		memcpy_s(LPVOID(fnEntry), sizeof(szPayload), szPayload, sizeof(szPayload));
		*LPDWORD(fnEntry + 1) = DWORD(uAddr(fnDest));
		*LPDWORD(fnEntry + 9) = DWORD(uAddr(fnDest) >> 32);

#else
		// 00007FFD7709E251 | 48 B8 56 34 12 90 78 56 34 12 | mov rax, 1234567890123456 |
		// 00007FFD7709E25B | FF E0 | jmp rax |

		WriteUShortRaw(fnEntry, 0xB848);
		*reinterpret_cast<FARPROC*>(fnEntry + 2) = fnDest;

		// jmp rax
		WriteUShortRaw(fnEntry + 10, 0xE0FF);
#endif



#else
		// 773E3D66 | E9 0D 19 F6 9A | jmp 12345678 |
		WriteByteRaw(fnEntry, 0xE9);
		//WriteRelativeAddress(fnEntry + 1, uAddr(fnDest));
		WriteUAddr(fnEntry + 1, uAddr(fnDest) - (fnEntry + 1) - 4);
#endif
		VirtualProtect(reinterpret_cast<void*>(fnEntry), SHELL_LENGTH, oldProtect, &oldProtect);
	}
	else
	{
		dprintf("Couldn't find export function %s: fnDest is null.\n", lpProcName);
	}
	}

void FixLibraryImport(HINSTANCE hModule) {
	wchar_t szTargetDll[MAX_PATH] = { 0 };
	wchar_t szThisDllPath[MAX_PATH] = { 0 };

	GetSystemDirectory(szTargetDll, MAX_PATH);
	GetModuleFileName(hModule, szThisDllPath, MAX_PATH);
	auto szDllName = wcsrchr(szThisDllPath, L'\\');
	wcscat_s(szTargetDll, MAX_PATH, szDllName++);

	hDll = LoadLibrary(szTargetDll);

	// If error, exit.
	if (!hDll) {
		ExitProcess(1);
		// ReSharper disable once CppUnreachableCode
		return;
	}

	int i = 0;
	while (szDllName[i])
	{
		szDllName[i] = tolower(szDllName[i]);
		i++;
	}

	dwprintf(L"Fix import for %s..\n", szDllName);

#pragma region Restore API
	if (wcscmp(szDllName, L"version.dll") == 0)
	{
		FixSingleApi("GetFileVersionInfoA", uAddr(API_EXPORT::GetFileVersionInfoA));
		FixSingleApi("GetFileVersionInfoByHandle", uAddr(API_EXPORT::GetFileVersionInfoByHandle));
		FixSingleApi("GetFileVersionInfoExW", uAddr(API_EXPORT::GetFileVersionInfoExW));
		FixSingleApi("GetFileVersionInfoSizeA", uAddr(API_EXPORT::GetFileVersionInfoSizeA));
		FixSingleApi("GetFileVersionInfoSizeExW", uAddr(API_EXPORT::GetFileVersionInfoSizeExW));
		FixSingleApi("GetFileVersionInfoSizeW", uAddr(API_EXPORT::GetFileVersionInfoSizeW));
		FixSingleApi("GetFileVersionInfoW", uAddr(API_EXPORT::GetFileVersionInfoW));
		FixSingleApi("VerFindFileA", uAddr(API_EXPORT::VerFindFileA));
		FixSingleApi("VerFindFileW", uAddr(API_EXPORT::VerFindFileW));
		FixSingleApi("VerInstallFileA", uAddr(API_EXPORT::VerInstallFileA));
		FixSingleApi("VerInstallFileW", uAddr(API_EXPORT::VerInstallFileW));
		FixSingleApi("VerLanguageNameA", uAddr(API_EXPORT::VerLanguageNameA));
		FixSingleApi("VerLanguageNameW", uAddr(API_EXPORT::VerLanguageNameW));
		FixSingleApi("VerQueryValueA", uAddr(API_EXPORT::VerQueryValueA));
		FixSingleApi("VerQueryValueW", uAddr(API_EXPORT::VerQueryValueW));
		FixSingleApi("VerQueryValueIndexA", uAddr(API_EXPORT::VerQueryValueIndexA));
		FixSingleApi("VerQueryValueIndexW", uAddr(API_EXPORT::VerQueryValueIndexW));
	}

#pragma endregion
}

