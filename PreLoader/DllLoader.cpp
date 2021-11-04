#include "DllLoader.h"
//#include "pscmd.h"
#include <windows.h>
#include <Psapi.h>
#include <fstream>
#include <string>
#include "..\MinHook\include\MinHook.h"


std::string DectoHex(PBYTE dec)
{
	char buffer[33];
	_i64toa_s((INT64)dec, buffer, 33, 16);
	return std::string(buffer);
}

void plog(const std::string str)
{
	char time[4096];
	SYSTEMTIME sys;
	GetLocalTime(&sys);
	sprintf_s(time, "[%4d/%02d/%02d %02d:%02d:%02d.%03d]\n",
		sys.wYear, sys.wMonth, sys.wDay, sys.wHour, sys.wMinute,
		sys.wSecond, sys.wMilliseconds);
	std::ofstream	OsWrite("plogs.txt", std::ofstream::app);
	OsWrite << time;
	OsWrite << str;
	OsWrite << std::endl;
	OsWrite.close();
}

bool WriteMemory(PBYTE BaseAddress, PBYTE Buffer, DWORD nSize)
{
	DWORD ProtectFlag = 0;
	if (VirtualProtectEx(GetCurrentProcess(), BaseAddress, nSize, PAGE_EXECUTE_READWRITE, &ProtectFlag))
	{
		memcpy(BaseAddress, Buffer, nSize);
		FlushInstructionCache(GetCurrentProcess(), BaseAddress, nSize);
		VirtualProtectEx(GetCurrentProcess(), BaseAddress, nSize, ProtectFlag, &ProtectFlag);
		return true;
	}
	return false;
}

typedef int (APIENTRY* WINMAIN)(HINSTANCE, HINSTANCE, LPWSTR, INT);
WINMAIN fpWINMAIN = NULL;
int APIENTRY DetourWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, INT nCmdShow)
{
	plog("DetourWinMain");
	return fpWINMAIN(hInstance, hPrevInstance, lpCmdLine, nCmdShow);
}

VOID InstallLoader()
{
	//获取程序入口点
	MODULEINFO mi;
	GetModuleInformation(GetCurrentProcess(), GetModuleHandle(NULL), &mi, sizeof(MODULEINFO));
	PBYTE entry = (PBYTE)mi.EntryPoint;
	plog("Entry:" + DectoHex(entry));

	//入口点写NOP
	//BYTE patch[] = { 0x90, 0x90, 0x90, 0x90 };
	//WriteMemory(entry, patch, sizeof(patch));

	// 入口点跳转到Loader
	if (MH_CreateHook(entry, DetourWinMain, (LPVOID*)&fpWINMAIN) == MH_OK)
	{
		plog("CreateHook OK.");
		if (MH_EnableHook(entry) == MH_OK)
		{
			plog("EnableHook OK.");
		}
	}
	else
	{
		plog("CreateHook Failed.");
	}
}

typedef SHORT (WINAPI* GETASYNKEYSTATE)(int vKey);
GETASYNKEYSTATE fpGetAsynKeyState = NULL;
SHORT WINAPI DetourGetAsynKeyState(int vKey)
{
	return fpGetAsynKeyState(vKey);
}

typedef int (WINAPI* MESSAGEBOXW)(HWND, LPCWSTR, LPCWSTR, UINT);
MESSAGEBOXW fpMessageBoxW = NULL;
int WINAPI DetourMessageBoxW(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType)
{
	return fpMessageBoxW(hWnd, L"Hooked!", lpCaption, uType);
}

typedef HANDLE(WINAPI* CREATEFILEMAPPINGW)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCWSTR);
CREATEFILEMAPPINGW fpCreateFileMappingW = NULL;
HANDLE WINAPI DetourCreateFileMappingW(HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCWSTR lpName)
{
	MessageBoxA(NULL, "Mapping", "Mapping", 0);
	return fpCreateFileMappingW(hFile, lpFileMappingAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName);
}


BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
	switch (fdwReason) {
	case DLL_PROCESS_ATTACH:

		FixLibraryImport(hinstDLL);

		plog(GetCommandLineA());
		//plog(GetCurrentCommandLineA());

		// 初始化HOOK库成功以后安装加载器
		if (MH_Initialize() == MH_OK)
		{
			plog("MH_Initialize succeed.");
			InstallLoader();
			MH_CreateHook(&MessageBoxW, &DetourMessageBoxW, reinterpret_cast<LPVOID*>(&fpMessageBoxW));
			MH_EnableHook(&MessageBoxW);
			//MH_CreateHook(&CreateFileMappingW, &DetourCreateFileMappingW, reinterpret_cast<LPVOID*>(&fpCreateFileMappingW));
			//MH_EnableHook(&CreateFileMappingW);
			//MH_CreateHook(&GetAsynKeyState, &DetourGetAsynKeyState, reinterpret_cast<LPVOID*>(&fpGetAsynKeyState));
			//MH_EnableHook(&GetAsynKeyState);

		}
		else
		{
			plog("MH_Initialize failed.");
		}
		break;

	case DLL_PROCESS_DETACH:
		FreeLibrary(hDll);
		break;
	}
	return TRUE;
}

