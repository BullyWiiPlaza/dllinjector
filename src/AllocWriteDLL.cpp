/*
 	AllocWriteMethods.cpp
		brad.antoniewicz@foundstone.com

		These functions return the value to start execution, and set value of lpExecParam
	
*/
#include "LoadLibraryR.h"
#include <cstdio>

LPTHREAD_START_ROUTINE alloc_write_dll(HANDLE h_target_proc_handle, LPCSTR dll_path)
{
	DWORD dw_bytes_read = 0;

	printf("\t[+] Allocating space for entire DLL\n");

	const auto h_file = CreateFileA(dll_path, GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (h_file == INVALID_HANDLE_VALUE)
	{
		printf("\n[!] ERROR: Could not open DLL!\n");
		return nullptr;
	}

	const auto dw_length = GetFileSize(h_file, nullptr);
	if (dw_length == INVALID_FILE_SIZE || dw_length == 0)
	{
		printf("\n[!] ERROR: Invalid DLL file size!\n");
		return nullptr;
	}
	const auto lp_write_buff = HeapAlloc(GetProcessHeap(), 0, dw_length);
	if (!lp_write_buff)
	{
		printf("\n[!] ERROR: Failed to allocate memory for DLL!\n");
		return nullptr;
	}

	if (ReadFile(h_file, lp_write_buff, dw_length, &dw_bytes_read, nullptr) == FALSE)
	{
		printf("\n[!] ERROR: Failed to read DLL!\n");
		return nullptr;
	}

	auto lp_dll_addr = VirtualAllocEx(h_target_proc_handle, nullptr, dw_length, MEM_RESERVE | MEM_COMMIT,
	                                    PAGE_EXECUTE_READWRITE);

	printf("\t\t[+] Writing into the current process space at 0x%8p\n", lp_dll_addr);

	if (WriteProcessMemory(h_target_proc_handle, lp_dll_addr, lp_write_buff, dw_length, nullptr) == 0)
	{
		printf("\n[!] WriteProcessMemory Failed [%lu]\n", GetLastError());
		return nullptr;
	}

	const auto dw_reflective_loader_offset = GetReflectiveLoaderOffset(lp_write_buff);

	HeapFree(GetProcessHeap(), 0, lp_write_buff);

	if (!dw_reflective_loader_offset)
	{
		printf("\n[!] Error calculating Offset - Wrong Architecture?\n");
		return nullptr;
	}

	return reinterpret_cast<LPTHREAD_START_ROUTINE>(reinterpret_cast<ULONG_PTR>(lp_dll_addr) + dw_reflective_loader_offset);
}

LPTHREAD_START_ROUTINE alloc_write_path(HANDLE h_target_proc_handle, LPCSTR dll_path, LPVOID* lp_exec_param)
{
	unsigned int write_len = 0;
	LPVOID lp_write_val = nullptr;

	printf("\t[+] Allocating space for the path of the DLL\n");

	const auto lp_dll_addr = VirtualAllocEx(h_target_proc_handle, nullptr, strlen(dll_path), MEM_RESERVE | MEM_COMMIT,
	                                    PAGE_EXECUTE_READWRITE);

	printf("\t\t[+] Writing into the current process space at 0x%8p\n", lp_dll_addr);
	if (WriteProcessMemory(h_target_proc_handle, lp_dll_addr, dll_path, strlen(dll_path), nullptr) == 0)
	{
		printf("\n[!] WriteProcessMemory Failed [%lu]\n", GetLastError());
		return nullptr;
	}

	*lp_exec_param = static_cast<LPVOID *>(lp_dll_addr);

	printf("\t\t[+] Looking for LoadLibrary in kernel32\n");
	const LPVOID load_lib_addr = GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "LoadLibraryA");
	if (load_lib_addr == nullptr)
	{
		printf("\n[!] Failed to find LoadLibrary in Kernel32! Quiting...\n");
		return nullptr;
	}
	printf("\t\t[+] Found at 0x%8p\n", load_lib_addr);

	return static_cast<LPTHREAD_START_ROUTINE>(load_lib_addr);
}
