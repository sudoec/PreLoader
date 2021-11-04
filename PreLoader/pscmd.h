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
	��ȡָ�������������ַ�����ʧ�ܷ��� FALSE��Unicode Version��
	--------
	HANDLE hProcess							���ȡ���������ַ����Ľ��̾�����þ��Ӧ���� PROCESS_QUERY_INFORMATION �� PROCESS_VM_READ ����Ȩ��
	LPCWSTR lpcBuffer							ָ������������ַ����Ŀ��ַ�������ָ�룬������Ӧʹ�� memset ��ʼ��Ϊ zero���ò�������Ϊ NULL
	SIZE_T nSize										���� lpcBuffer ָ��Ŀ��ַ���������Ч��С��Bytes�����ò�������Ϊ NULL
	SIZE_T* lpNumberOfBytesCopied	ʵ�ʸ��Ƶ� lpcBuffer ָ��Ŀ��ַ��������е��ֽ�����Bytes������ lpcBuffer Ϊ NULL �� nSize ̫С���ò������������軺�����Ľ����С��Bytes�����ò�������Ϊ NULL
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
	��ȡָ�������������ַ�����ʧ�ܷ��� FALSE��Ansi Version��
	--------
	GetProcessCommandLineA �ǻ��� GetProcessCommandLineW �� Ansi �汾��Ӧ�ó���Ӧ������ʹ�� GetProcessCommandLineW�������Ǵ� GetProcessCommandLineA
	--------
	HANDLE hProcess							���ȡ���������ַ����Ľ��̾�����þ��Ӧ���� PROCESS_QUERY_INFORMATION �� PROCESS_VM_READ ����Ȩ��
	LPCWSTR lpcBuffer							ָ������������ַ����Ķ��ֽڻ�����ָ�룬������Ӧʹ�� memset ��ʼ��Ϊ zero���ò�������Ϊ NULL
	SIZE_T nSize										���� lpcBuffer ָ��Ķ��ֽڻ�������Ч��С��Bytes�����ò�������Ϊ NULL
	SIZE_T* lpNumberOfBytesCopied	ʵ�ʸ��Ƶ� lpcBuffer ָ��Ķ��ֽڻ������е��ֽ�����Bytes������ lpcBuffer Ϊ NULL �� nSize ̫С���ò������������軺�����Ľ����С��Bytes�����ò�������Ϊ NULL
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
		���̾�� hProcess Ӧ���� PROCESS_QUERY_INFORMATION |  PROCESS_VM_READ ����Ȩ�ޣ����򽫵��� GetProcessCommandLine ʧ�ܡ�
		Ӧ�ó���Ӧ������ʹ�� GetProcessCommandLineW �� Unicode �汾�������� Ansi �汾�������������Ӧ�ó���ִ�������ҷ�ֹ���ض������¶�ʧ���ݡ�
		pscmd.h header file Ĭ��ͨ����ǰ��Ŀ���ַ���������ȷ�������õ� GetProcessCommandLine �汾�� PCMDBUFFER_T ���������Ͷ��壨Unicode �� Ansi����
	*/
	WCHAR lpUnicodeBuffer[2048];
	SIZE_T nCommandLineSize = NULL;
	if (GetProcessCommandLine(hProcess, NULL, NULL, &nCommandLineSize)) // �� lpcBuffer �� nSize ����Ϊ NULL �Ի�ȡ���黺������С��nCommandLineSize��
	{
		
		/* ʹ�� memset���� WINAPI ZeroMemory��������� Unicode ��������ʼ��Ϊ zero */
		memset(lpUnicodeBuffer, NULL, 2048);

		/* �ٴε���  GetProcessCommandLine ������������� Unicode ����������ȡ��ʵ������ */
		GetProcessCommandLine(hProcess, lpUnicodeBuffer, nCommandLineSize, &nCommandLineSize);
	}
	return std::wstring(lpUnicodeBuffer);
}


std::string GetCurrentCommandLineA()
{
	HANDLE hProcess = GetCurrentProcess();
	/*
		���̾�� hProcess Ӧ���� PROCESS_QUERY_INFORMATION |  PROCESS_VM_READ ����Ȩ�ޣ����򽫵��� GetProcessCommandLine ʧ�ܡ�
		Ӧ�ó���Ӧ������ʹ�� GetProcessCommandLineW �� Unicode �汾�������� Ansi �汾�������������Ӧ�ó���ִ�������ҷ�ֹ���ض������¶�ʧ���ݡ�
		pscmd.h header file Ĭ��ͨ����ǰ��Ŀ���ַ���������ȷ�������õ� GetProcessCommandLine �汾�� PCMDBUFFER_T ���������Ͷ��壨Unicode �� Ansi����
	*/
	WCHAR lpUnicodeBuffer[2048];
	SIZE_T nCommandLineSize = NULL;
	if (GetProcessCommandLine(hProcess, NULL, NULL, &nCommandLineSize)) // �� lpcBuffer �� nSize ����Ϊ NULL �Ի�ȡ���黺������С��nCommandLineSize��
	{

		/* ʹ�� memset���� WINAPI ZeroMemory��������� Unicode ��������ʼ��Ϊ zero */
		memset(lpUnicodeBuffer, NULL, 2048);

		/* �ٴε���  GetProcessCommandLine ������������� Unicode ����������ȡ��ʵ������ */
		GetProcessCommandLine(hProcess, lpUnicodeBuffer, nCommandLineSize, &nCommandLineSize);
	}
	std::wstring wstr(lpUnicodeBuffer);
	return std::string(wstr.begin(), wstr.end());
}