/*
 	AllocWriteDLL.h
		brad.antoniewicz@foundstone.com
		
		Contains headers for the Alloc/Write/Determine Address functions.
		See AllocWriteDLL.cpp for more information 

*/

#pragma once

LPTHREAD_START_ROUTINE alloc_write_dll(HANDLE h_target_proc_handle, LPCSTR dll_path);
LPTHREAD_START_ROUTINE alloc_write_path(HANDLE h_target_proc_handle, LPCSTR dll_path, LPVOID *lp_exec_param);