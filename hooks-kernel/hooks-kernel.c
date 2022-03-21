#include <windows.h>
#include <stdio.h>

#include "beacon.h"
#include "hooks-kernel.h"

/*BOF Entry Point*/

void go(char* args, int length) {
	BeaconPrintf(CALLBACK_OUTPUT, "\n[?] kernel32.dll\n");
	check_hooks("kernel32.dll");
	BeaconPrintf(CALLBACK_OUTPUT, "\n[?] kernelbase.dll\n");
	check_hooks("kernelbase.dll");
}


void check_hooks(LPCSTR dllName) {//Attempts to detect userland hooks by AV/EDR

        //Variables
	size_t size = 65535;
	char* returnData = (char*)intAlloc(size);
	memset(returnData, 0, size);
	unsigned int returnDataLen;
	PDWORD functionAddress = (PDWORD)0;
	
	//Get ntdll base address
	HMODULE libraryBase = KERNEL32$LoadLibraryA(dllName);

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)libraryBase;
	PIMAGE_NT_HEADERS imageNTHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)libraryBase + dosHeader->e_lfanew);

	//Locate export address table
	DWORD_PTR exportDirectoryRVA = imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	PIMAGE_EXPORT_DIRECTORY imageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)libraryBase + exportDirectoryRVA);

	//Offsets to list of exported functions and their names
	PDWORD addresOfFunctionsRVA = (PDWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfFunctions);
	PDWORD addressOfNamesRVA = (PDWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfNames);
	PWORD addressOfNameOrdinalsRVA = (PWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfNameOrdinals);
	
	//Iterate through exported functions of the dll
	for (DWORD i = 0; i < imageExportDirectory->NumberOfNames; i++)
	{
		//Resolve exported function name
		DWORD functionNameRVA = addressOfNamesRVA[i];
		DWORD_PTR functionNameVA = (DWORD_PTR)libraryBase + functionNameRVA;
		char* functionName = (char*)functionNameVA;

		//Resolve exported function address
		DWORD_PTR functionAddressRVA = 0;
		functionAddressRVA = addresOfFunctionsRVA[addressOfNameOrdinalsRVA[i]];
		functionAddress = (PDWORD)((DWORD_PTR)libraryBase + functionAddressRVA);

		// looking for JMPs instead
		BYTE* opcode = (BYTE*)functionAddress;

		// Check if the first 4 instructions of the exported function are the same as the sycall's prologue
		if (*opcode == 0xe9) {
				
			//Convert versions/buildNumber to string
			returnDataLen = MSVCRT$_snprintf(NULL, 0, "%s\n", functionName);
			MSVCRT$_snprintf(returnData + MSVCRT$strlen(returnData), returnDataLen + 1, "%s\n", functionName);
					
		}
	}

	if (MSVCRT$strlen(returnData) == 0)
	{
		//No hooks found
		BeaconPrintf(CALLBACK_OUTPUT, "\n[+] No Hooks Found\n");
	}
	else
	{
		//Send hook output back to CS
		BeaconPrintf(CALLBACK_OUTPUT, "\n[!] %s\n", returnData);
	}
}
