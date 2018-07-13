#include <windows.h>
#include <iostream>
#include <string>
#include <TlHelp32.h>
#include <string>
#include <psapi.h>
#include <iomanip>
#pragma comment(lib, "psapi")

using namespace std;

int GetPid(string processName) {
    PROCESSENTRY32 pe32;
    HANDLE hSnapshot = NULL;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    
    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (processName.compare(pe32.szExeFile) == 0)
                break;
        } while (Process32Next(hSnapshot, &pe32));
    }
    
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        CloseHandle(hSnapshot);
    }

    return pe32.th32ProcessID;
}

BOOL SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege) {
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!LookupPrivilegeValue(NULL, lpszPrivilege, &luid)) {
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if (bEnablePrivilege)
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    else
        tp.Privileges[0].Attributes = 0;

    if (!AdjustTokenPrivileges(hToken, 
                               FALSE, 
                               &tp, 
                               sizeof(TOKEN_PRIVILEGES), 
                               (PTOKEN_PRIVILEGES) NULL, 
                               (PDWORD) NULL)) 
                               {
          return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
          return FALSE;
    }

    return TRUE;
}

BOOL GetDebugPrivileges(void) {
	HANDLE hToken = NULL;
    if(!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
        return FALSE;
    
    if(!SetPrivilege(hToken, SE_DEBUG_NAME, TRUE))
        return FALSE;
	
	return TRUE;
}

int GetModuleBase(HANDLE processHandle, string &sModuleName) 
{ 
    HMODULE *hModules = NULL; 
    char szBuf[50]; 
    DWORD cModules; 
    DWORD dwBase = -1;

    EnumProcessModules(processHandle, hModules, 0, &cModules); 
    hModules = new HMODULE[cModules/sizeof(HMODULE)]; 
    
    if(EnumProcessModules(processHandle, hModules, cModules/sizeof(HMODULE), &cModules)) { 
       for(size_t i = 0; i < cModules/sizeof(HMODULE); i++) { 
          if(GetModuleBaseName(processHandle, hModules[i], szBuf, sizeof(szBuf))) { 
             if(sModuleName.compare(szBuf) == 0) { 
                dwBase = (DWORD_PTR)hModules[i]; 
                break; 
             } 
          } 
       } 
    } 
    
    delete[] hModules;
    return dwBase; 
}

int ReadInt(HANDLE processHandle, int address) {
    if (address == -1)
        return -1;
    int buffer = 0;
    SIZE_T NumberOfBytesToRead = sizeof(buffer); //this is equal to 4
    SIZE_T NumberOfBytesActuallyRead;
    BOOL success = ReadProcessMemory(processHandle, 
                                    (LPCVOID)address, 
                                    &buffer, 
                                    NumberOfBytesToRead, 
                                    &NumberOfBytesActuallyRead);
    if (!success || NumberOfBytesActuallyRead != NumberOfBytesToRead) {
        cout << "Memory Error!" << endl;
        return -1;
    }

    return buffer; 
}

int GetPointerAddress(HANDLE processHandle, int startAddress, int offsets[], int offsetCount) {
    if (startAddress == -1)
        return -1;
	int ptr = ReadInt(processHandle, startAddress);
	for (int i = 0; i < offsetCount - 1; i++) {
		ptr += offsets[i];
		ptr = ReadInt(processHandle, ptr);
	}
	ptr += offsets[offsetCount-1];

	return ptr;
}

int ReadPointerInt(HANDLE processHandle, int startAddress, int offsets[], int offsetCount) {
    if (startAddress == -1)
        return -1;
	return ReadInt(processHandle, 
           GetPointerAddress(processHandle, startAddress, offsets, offsetCount));
}

BOOL WriteInt(HANDLE processHandle, int address, int buffer) {
    if (address == -1)
        return -1;
    SIZE_T NumberOfBytesToWrite = sizeof(buffer); //this is equal to 4
    SIZE_T NumberOfBytesActuallyWrite;

    BOOL ok = WriteProcessMemory(processHandle,
                                 (LPCVOID)address,
                                 &buffer,
                                 NumberOfBytesToWrite, 
                                 &NumberOfBytesActuallyWrite);
    if (!ok || NumberOfBytesToWrite != NumberOfBytesActuallyWrite) {
        return FALSE;
    }
    return TRUE;

}

BOOL WritePointerInt(HANDLE processHandle, int startAddress, int offsets[], int offsetCount, int buffer) {
    if (startAddress == -1)
        return -1;
    return WriteInt(processHandle,
           GetPointerAddress(processHandle, startAddress, offsets, offsetCount),
           buffer);
}

int main() {
    ////// Players addresses ////////
    int PLAYER_PTR_OFFSET = 0x7030;
    int PLAYER_HP_OFFSET[] = {0x24};
    ////// New values ///////////////
    int maxHP = 100;
    /////////////////////////////////
    int pid;
    int baseAddress;
    BOOL ok;
    HANDLE processHandle;
    string processName = "a.exe";

    if (GetDebugPrivileges() == false) {
        cout << "Could not get debug privileges." << endl;
        return 1;
    }

    pid = GetPid(processName);
    cout << "PID: " << pid << endl;

    processHandle = OpenProcess(PROCESS_ALL_ACCESS, false, pid);

    baseAddress = GetModuleBase(processHandle, processName);
    cout << "Base address: " 
         << showbase // show the 0x prefix
         << internal // fill between the prefix and the number
         << setfill('0') // fill with 0s
         << hex << baseAddress << endl;

    int playersAddress = baseAddress + PLAYER_PTR_OFFSET; // a.exe+0x7030
    int ptrOffset[] = {0x0};
    int playersHpAddress = ReadPointerInt(processHandle, 
                                          playersAddress, 
                                          PLAYER_HP_OFFSET, 
                                          1); // playersAddress+0x24 <-- hp
    cout << "Players hp = " << dec << playersHpAddress << endl;

    cout << "Setting players HP to 100...." << endl;
    ok = WritePointerInt(processHandle,
                         playersAddress,
                         PLAYER_HP_OFFSET,
                         1,
                         maxHP);
    if (!ok) {
        cout << "Failed to write memory" << endl;
        return 1;
    }
        
    return 0;
}
