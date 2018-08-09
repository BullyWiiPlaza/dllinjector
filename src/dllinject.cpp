/*
	dllinjector - 
		brad.antoniewicz@foundstone.com

		This tool aims to implement various DLL injection 
		techniques. For more information on DLL injection
		see http://blog.opensecurityresearch.com
		
		This was built using Microsoft Visual Studio 2010

		dllInjector currently supports using:

		DLL Memory Allocation and Execution Techniques:
			1. Allocate memory for DLL Path and use LoadLibraryA().
			2. Allocate memory for full DLL and jump to the DLL's 
				entry point. 

		DLL Injection Techniques 
			1. CreateRemoteThread()
			2. NtCreateThreadEx()
			3. Suspend, Inject, and Resume
			4. RtlCreateUserThread()

		Todo:
			1. Implement SetWindowsHookEx() Method
				http://www.kdsbest.com/?p=179
			2. Implement QueueUserAPC() Method
				http://webcache.googleusercontent.com/search?q=cache:G8i5oxOWbDMJ:www.hackforums.net/archive/index.php/thread-2442150.html+&cd=3&hl=en&ct=clnk&gl=us&client=firefox-a
			3. Implement PrivEscalation as per: 
				https://github.com/rapid7/metasploit-framework/tree/master/external/source/meterpreter/source/extensions/priv/server/elevate
				/metasploit/msf3/external/source/meterpreter/source/extensions/priv/server/elevate

		Credits:
			vminjector - https://github.com/batistam/VMInjector
			ReflectiveDLLInjection - https://github.com/stephenfewer/ReflectiveDLLInjection

*/

#include <cstdlib>
#include <Windows.h>
#include <cstdio>
#include <TlHelp32.h>
#include "ExecThread.h"
#include "AllocWriteDLL.h"

#pragma comment(lib,"Advapi32.lib")

#define VERSION 0.2
#define BUFSIZE 512

int set_debug_privileges()
{
	TOKEN_PRIVILEGES priv = {0};
	HANDLE h_token = nullptr;

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &h_token))
	{
		priv.PrivilegeCount = 1;
		priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		if (LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &priv.Privileges[0].Luid))
		{
			if (AdjustTokenPrivileges(h_token, FALSE, &priv, 0, nullptr, nullptr) == 0)
			{
				printf("AdjustTokenPrivilege Error! [%u]\n", GetLastError());
			}
		}

		CloseHandle(h_token);
	}
	return GetLastError();
}

HANDLE attach_to_process(const DWORD proc_id)
{
	OSVERSIONINFO osver;

	// SetDebugPrivileges SE_DEBUG_NAME
	printf("[+] Setting Debug Privileges [%d]\n", set_debug_privileges());

	osver.dwOSVersionInfoSize = sizeof(osver);
	if (GetVersionEx(&osver))
	{
		if (osver.dwMajorVersion == 5)
		{
			printf("\t[+] Detected Windows XP\n");
			return OpenProcess(
				PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE |
				PROCESS_CREATE_THREAD, 0, proc_id);
		}
		if (osver.dwMajorVersion == 6 && osver.dwMinorVersion == 0)
		{
			printf("\t[+] Detected Windows Vista\n");
			return nullptr;
		}
		if (osver.dwMajorVersion == 6 && osver.dwMinorVersion == 1)
		{
			printf("\t[+] Detected Windows 7\n");
			printf("\t[+] Attaching to Process ID: %d\n", proc_id);
			return OpenProcess(
				PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
				PROCESS_VM_READ, FALSE, proc_id);
		}
		if (osver.dwMajorVersion == 6 && osver.dwMinorVersion == 2)
		{
			printf("\t[+] Detected Windows 10\n");
			printf("\t[+] Attaching to Process ID: %d\n", proc_id);
			return OpenProcess(
				PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
				PROCESS_VM_READ, FALSE, proc_id);
		}
	}
	else
	{
		printf("\n[!] Could not detect OS version\n");
	}
	return nullptr;
}

int injectDLL(HANDLE hTargetProcHandle, unsigned int injectMethod, LPTHREAD_START_ROUTINE lpStartExecAddr,
              LPVOID lpExecParam)
{
	HANDLE rThread = nullptr;

	switch (injectMethod)
	{
	case 1: // NtCreateThreadEx
		printf("\n[+] Using NtCreateThreadEx() to Create Thread\n");
		rThread = bCreateRemoteThread(hTargetProcHandle, lpStartExecAddr, lpExecParam);
		if (rThread == nullptr)
		{
			printf("\n[!] NtCreateThreadEx Failed! [%lu] Exiting....\n", GetLastError());
			return -1;
		}
		printf("\t[+] Remote Thread created! [%lu]\n", GetLastError());
		WaitForSingleObject(rThread, INFINITE);
		break;
	case 2: // CreateRemoteThread
		printf("\n[+] Using CreateRemoteThread() to Create Thread\n");
		rThread = CreateRemoteThread(hTargetProcHandle, nullptr, 0, lpStartExecAddr, lpExecParam, 0, nullptr);
		if (rThread == nullptr)
		{
			printf("\n[!] CreateRemoteThread Failed! [%lu] Exiting....\n", GetLastError());
			return -1;
		}
		printf("\t[+] Remote Thread created! [%lu]\n", GetLastError());
		WaitForSingleObject(rThread, INFINITE);
		break;
	case 3: // Suspend/Inject/Resume
		printf("\n[+] Using the Suspend/Inject/Resume Method to Create Thread\n");
#ifdef _WIN64 // Need to fix this! 
		printf("\n[+] Suspend/Inject/Resume Method Not currently supported on x64 :(\n");
		return -1;

#else
			suspendInjectResume(hTargetProcHandle, lpStartExecAddr, lpExecParam);
#endif
	case 4: //RtlCreateUserThread
		printf("\n[+] Using RtlCreateUserThread() to Create Thread\n");
		rThread = bCreateUserThread(hTargetProcHandle, lpStartExecAddr, lpExecParam);
		if (rThread == nullptr)
		{
			printf("\n[!] RtlCreateUserThread Failed! [%lu] Exiting....\n", GetLastError());
			return -1;
		}
		printf("\t[+] Remote Thread created! [%lu]\n", GetLastError());
		WaitForSingleObject(rThread, INFINITE);
		break;
	default:
		printf("\n[!] Unknown Injection Method WTF?!\n");
		return -1;
	}
	return 0;
}

void dump_procs(void)
{
	PROCESSENTRY32 pe32 = {sizeof(PROCESSENTRY32)};
	const auto h_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	printf("[+] Dumping processes and PIDs..\n");

	if (h_snapshot == INVALID_HANDLE_VALUE)
		exit(-1);

	if (! Process32First(h_snapshot, &pe32))
	{
		CloseHandle(h_snapshot);
		exit(-1);
	}

	do
	{
		printf("\t[%lu]\t%s\n", pe32.th32ProcessID, pe32.szExeFile);
	}
	while (Process32Next(h_snapshot, &pe32));

	CloseHandle(h_snapshot);
}

void help(char* processname)
{
	printf("\n");
	printf("\t-d\t\tDump Process Excutables and IDs\n");
	printf("\t-p PID\t\tPID to inject into (from -d)\n");
	printf("\t-l file.dll\tDLL to inject\n");
	printf("\t-h\t\tthis help\n");

	printf("\nMemory Allocation Methods:\n");
	printf("\t-P\tAllocate memory for just the file path (Implies LoadLibrary)\n"); // allocMethod = 1 
	printf("\t-F\tAllocate memory for the full DLL (Implies Reflective)\n"); // allocMethod = 2 

	printf("\nInjection Methods:\n");
	printf("\t-n\t\tUse NtCreateThreadEx()\n");
	printf("\t-c\t\tUse CreateRemoteThread()\n");
	printf("\t-s\t\tUse Suspend/Inject/Resume\n");
	printf("\t-r\t\tUse RtlCreateUserThread()\n");

	printf("\n");

	printf("Usage:\n");
	printf("\t%s -d (To Dump processes and get the PID)\n", processname);
	printf("\t%s -p 1234 -l something.dll -P -c (Inject something.dll into process 1234)\n", processname);
	printf("\n");
}

int main(const int argc, char* argv[])
{
	DWORD dw_pid = 0;
	DWORD dw_inject_method = 1;
	DWORD dw_alloc_method = 1;

	LPTHREAD_START_ROUTINE lp_start_exec_addr = nullptr;
	LPVOID lp_exec_param = nullptr;
	HANDLE h_target_proc_handle;

	LPCTSTR lpc_dll = nullptr;
	TCHAR tc_dll_path[BUFSIZE] = TEXT("");
#ifdef _WIN64
	TCHAR tc_arch[4] = TEXT("x64");
#else
		TCHAR tcArch[4] = TEXT("x32");
#endif

	printf("\nFoundstone DLL Injector v%1.1f (%s)\n", VERSION, tc_arch);
	printf("brad.antoniewicz@foundstone.com\n");
	printf("--------------------------------------------------------\n");

	for (DWORD dw_count = 1; dw_count < static_cast<DWORD>(argc); dw_count++)
	{
		if (strcmp(argv[dw_count], "-d") == 0)
		{
			dump_procs();
			return 0;
		}
		else if (strcmp(argv[dw_count], "-p") == 0)
		{
			if (dw_count + 1 != argc)
			{
				dw_pid = atol(argv[dw_count + 1]);
				printf("[+] Targeting PID: %d\n", dw_pid);
				dw_count++;
			}
		}
		else if (strcmp(argv[dw_count], "-l") == 0)
		{
			if (dw_count + 1 != argc)
			{
				lpc_dll = TEXT(argv[dw_count+1]);
				printf("[+] Injecting DLL: %s\n", lpc_dll);
				dw_count++;
			}
		}
		else if (strcmp(argv[dw_count], "-n") == 0)
		{
			dw_inject_method = 1;
		}
		else if (strcmp(argv[dw_count], "-c") == 0)
		{
			dw_inject_method = 2;
		}
		else if (strcmp(argv[dw_count], "-s") == 0)
		{
			dw_inject_method = 3;
		}
		else if (strcmp(argv[dw_count], "-r") == 0)
		{
			dw_inject_method = 4;
		}
		else if (strcmp(argv[dw_count], "-P") == 0)
		{
			dw_alloc_method = 1;
		}
		else if (strcmp(argv[dw_count], "-F") == 0)
		{
			dw_alloc_method = 2;
		}
		else
		{
			help(argv[0]);
			exit(0);
		}
	}

	if (dw_pid == 0 || lpc_dll == nullptr)
	{
		help(argv[0]);
		printf("\n[!] ERROR: Must define PID and DLL\n");
		return -1;
	}

	GetFullPathName(lpc_dll, BUFSIZE, tc_dll_path, nullptr);
	printf("[+] Full DLL Path: %s\n", tc_dll_path);

	// Attach to process with OpenProcess()
	h_target_proc_handle = attach_to_process(dw_pid);
	if (h_target_proc_handle == nullptr)
	{
		printf("\n[!] ERROR: Could not Attach to Process!!\n");
		return -1;
	}

	// Copy the DLL via allocMethod
	switch (dw_alloc_method)
	{
	case 1:
		lp_start_exec_addr = alloc_write_path(h_target_proc_handle, tc_dll_path, &lp_exec_param);
		break;
	case 2:
		lp_start_exec_addr = alloc_write_dll(h_target_proc_handle, tc_dll_path);
		break;
	default:
		printf("\n[!] ERROR: Unknown allocMethod\n");
		break;
	}

	if (lp_start_exec_addr == nullptr)
	{
		printf("\n[!] ERROR: Could not allocate memory!!\n");
		return -1;
	}

	// Inject the DLL into process via injectMethod.  lpExecParam may be NULL
	injectDLL(h_target_proc_handle, dw_inject_method, lp_start_exec_addr, lp_exec_param);

	CloseHandle(h_target_proc_handle);

	return 0;
}
