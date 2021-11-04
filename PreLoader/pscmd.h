/*
	Pscmd
	--------
	License     	Apache 2.0 License
	--------
	Copyright 2018 SMALLSO Studios.

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.
	------
	E-mail      	xiaoyy@altca.cn
	WorkQQ   	20177621
	Website   	https://www.xiaoyy.org/
	------
	SMALLSO Studios.
	2018/5/17 22:08
*/

#pragma once

/* Contains the necessary Windows SDK header files */
#include <string>
#include "windows.h"
#include "winternl.h"

/* Defining the request result status code in NTSTATUS */
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

/* Automatically selects the corresponding API based on the character set type of the current project */
#ifdef _UNICODE
	typedef WCHAR* PCMDBUFFER_T;
	#define GetProcessCommandLine GetProcessCommandLineW
#else
	typedef CHAR* PCMDBUFFER_T;
	#define GetProcessCommandLine GetProcessCommandLineA
#endif

/* Multiple version declarations for GetProcessCommandLine */
BOOL
WINAPI
GetProcessCommandLineW(
	_In_			HANDLE		hProcess,
	_In_opt_	LPCWSTR		lpcBuffer,
	_In_opt_	SIZE_T			nSize,
	_In_opt_	SIZE_T*			lpNumberOfBytesCopied
);

BOOL
WINAPI
GetProcessCommandLineA(
	_In_			HANDLE		hProcess,
	_In_opt_	LPCSTR		lpcBuffer,
	_In_opt_	SIZE_T			nSize,
	_In_opt_	SIZE_T*			lpNumberOfBytesCopied
);


/* NTAPI ZwQueryInformationProcess */
typedef NTSTATUS(NTAPI* Typedef_ZwQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
Typedef_ZwQueryInformationProcess pNTAPI_ZwQueryInformationProcess =
(Typedef_ZwQueryInformationProcess)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "ZwQueryInformationProcess");

/*
	获取指定进程命令行字符串，失败返回 FALSE（Unicode Version）
	--------
	HANDLE hProcess							需获取其命令行字符串的进程句柄，该句柄应具有 PROCESS_QUERY_INFORMATION 和 PROCESS_VM_READ 访问权限
	LPCWSTR lpcBuffer							指向接收命令行字符串的宽字符缓冲区指针，缓冲区应使用 memset 初始化为 zero，该参数可以为 NULL
	SIZE_T nSize										参数 lpcBuffer 指向的宽字符缓冲区有效大小（Bytes），该参数可以为 NULL
	SIZE_T* lpNumberOfBytesCopied	实际复制到 lpcBuffer 指向的宽字符缓冲区中的字节数（Bytes），如 lpcBuffer 为 NULL 或 nSize 太小，该参数将返回所需缓冲区的建议大小（Bytes），该参数可以为 NULL
*/
BOOL WINAPI GetProcessCommandLineW(HANDLE hProcess, LPCWSTR lpcBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesCopied)
{
	BOOL result = FALSE;
	if (pNTAPI_ZwQueryInformationProcess)
	{
		PROCESS_BASIC_INFORMATION BasicInfo; memset(&BasicInfo, NULL, sizeof(BasicInfo));
		PEB PebBaseInfo; memset(&PebBaseInfo, NULL, sizeof(PebBaseInfo));
		RTL_USER_PROCESS_PARAMETERS ProcessParameters; memset(&ProcessParameters, NULL, sizeof(ProcessParameters));
		if (pNTAPI_ZwQueryInformationProcess(hProcess, PROCESSINFOCLASS::ProcessBasicInformation, &BasicInfo, sizeof(BasicInfo), NULL) == STATUS_SUCCESS)
		{
			if (ReadProcessMemory(hProcess, BasicInfo.PebBaseAddress, &PebBaseInfo, sizeof(PebBaseInfo), NULL)
				&& ReadProcessMemory(hProcess, PebBaseInfo.ProcessParameters, &ProcessParameters, sizeof(ProcessParameters), NULL))
			{
				if (lpcBuffer && nSize >= ProcessParameters.CommandLine.Length + 2)
					result = ReadProcessMemory(hProcess, ProcessParameters.CommandLine.Buffer, (LPVOID)lpcBuffer,
						ProcessParameters.CommandLine.Length, lpNumberOfBytesCopied);
				else if (lpNumberOfBytesCopied) { *lpNumberOfBytesCopied = ProcessParameters.CommandLine.Length + 2; result = TRUE; }
			}
		}
	}
	return result;
}

/*
	获取指定进程命令行字符串，失败返回 FALSE（Ansi Version）
	--------
	GetProcessCommandLineA 是基于 GetProcessCommandLineW 的 Ansi 版本，应用程序应尽可能使用 GetProcessCommandLineW，而不是此 GetProcessCommandLineA
	--------
	HANDLE hProcess							需获取其命令行字符串的进程句柄，该句柄应具有 PROCESS_QUERY_INFORMATION 和 PROCESS_VM_READ 访问权限
	LPCWSTR lpcBuffer							指向接收命令行字符串的多字节缓冲区指针，缓冲区应使用 memset 初始化为 zero，该参数可以为 NULL
	SIZE_T nSize										参数 lpcBuffer 指向的多字节缓冲区有效大小（Bytes），该参数可以为 NULL
	SIZE_T* lpNumberOfBytesCopied	实际复制到 lpcBuffer 指向的多字节缓冲区中的字节数（Bytes），如 lpcBuffer 为 NULL 或 nSize 太小，该参数将返回所需缓冲区的建议大小（Bytes），该参数可以为 NULL
*/
BOOL WINAPI GetProcessCommandLineA(HANDLE hProcess, LPCSTR lpcBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesCopied)
{
	BOOL result = FALSE;
	SIZE_T nCommandLineSize = NULL;
	if (GetProcessCommandLineW(hProcess, NULL, NULL, &nCommandLineSize))
	{
		WCHAR* lpLocalBuffer = (WCHAR*)malloc(nCommandLineSize);
		if (lpLocalBuffer)
		{
			memset(lpLocalBuffer, NULL, nCommandLineSize);
			if (GetProcessCommandLineW(hProcess, lpLocalBuffer, nCommandLineSize, &nCommandLineSize))
			{
				INT iNumberOfBytes = WideCharToMultiByte(CP_ACP, NULL, lpLocalBuffer, nCommandLineSize, (LPSTR)lpcBuffer, nSize, NULL, NULL);
				if (lpNumberOfBytesCopied) *lpNumberOfBytesCopied = (!lpcBuffer || (nSize < (iNumberOfBytes + 1))) ? iNumberOfBytes + 1 : iNumberOfBytes;
				result = iNumberOfBytes > 0;
			}
			free(lpLocalBuffer);
		}
	}
	return result;
}


std::wstring GetCurrentCommandLineW()
{
	HANDLE hProcess = GetCurrentProcess();
	/*
		进程句柄 hProcess 应具有 PROCESS_QUERY_INFORMATION |  PROCESS_VM_READ 访问权限，否则将导致 GetProcessCommandLine 失败。
		应用程序应尽可能使用 GetProcessCommandLineW 即 Unicode 版本，而不是 Ansi 版本，这有助于提高应用程序执行性能且防止在特定语言下丢失数据。
		pscmd.h header file 默认通过当前项目的字符集设置来确定所调用的 GetProcessCommandLine 版本与 PCMDBUFFER_T 缓冲区类型定义（Unicode 或 Ansi）。
	*/
	WCHAR lpUnicodeBuffer[2048];
	SIZE_T nCommandLineSize = NULL;
	if (GetProcessCommandLine(hProcess, NULL, NULL, &nCommandLineSize)) // 将 lpcBuffer 和 nSize 设置为 NULL 以获取建议缓冲区大小（nCommandLineSize）
	{
		
		/* 使用 memset（或 WINAPI ZeroMemory）将分配的 Unicode 缓冲区初始化为 zero */
		memset(lpUnicodeBuffer, NULL, 2048);

		/* 再次调用  GetProcessCommandLine 并传入所分配的 Unicode 缓冲区，以取得实际数据 */
		GetProcessCommandLine(hProcess, lpUnicodeBuffer, nCommandLineSize, &nCommandLineSize);
	}
	return std::wstring(lpUnicodeBuffer);
}


std::string GetCurrentCommandLineA()
{
	HANDLE hProcess = GetCurrentProcess();
	/*
		进程句柄 hProcess 应具有 PROCESS_QUERY_INFORMATION |  PROCESS_VM_READ 访问权限，否则将导致 GetProcessCommandLine 失败。
		应用程序应尽可能使用 GetProcessCommandLineW 即 Unicode 版本，而不是 Ansi 版本，这有助于提高应用程序执行性能且防止在特定语言下丢失数据。
		pscmd.h header file 默认通过当前项目的字符集设置来确定所调用的 GetProcessCommandLine 版本与 PCMDBUFFER_T 缓冲区类型定义（Unicode 或 Ansi）。
	*/
	WCHAR lpUnicodeBuffer[2048];
	SIZE_T nCommandLineSize = NULL;
	if (GetProcessCommandLine(hProcess, NULL, NULL, &nCommandLineSize)) // 将 lpcBuffer 和 nSize 设置为 NULL 以获取建议缓冲区大小（nCommandLineSize）
	{

		/* 使用 memset（或 WINAPI ZeroMemory）将分配的 Unicode 缓冲区初始化为 zero */
		memset(lpUnicodeBuffer, NULL, 2048);

		/* 再次调用  GetProcessCommandLine 并传入所分配的 Unicode 缓冲区，以取得实际数据 */
		GetProcessCommandLine(hProcess, lpUnicodeBuffer, nCommandLineSize, &nCommandLineSize);
	}
	std::wstring wstr(lpUnicodeBuffer);
	return std::string(wstr.begin(), wstr.end());
}