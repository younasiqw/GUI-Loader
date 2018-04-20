#include "MemoryManagment.h"


MemoryManagment::MemoryManagment(char* proccessName) :
	proccessName(proccessName)
{

}


MemoryManagment::~MemoryManagment()
{
}
using namespace std;
std::string KEY = "keynumber9yeschangethi"; // 22
string Test = "123123123123";
bool MemoryManagment::Initialize()
{
	
	if ((proccessHandle = GetProcessByName()) == NULL)
		return false;

	if ((clientModuleBase = GetModuleBase("client.dll", &clientModuleSize)) == NULL)
		return false;

	if ((engineModuleBase = GetModuleBase("engine.dll", &engineModuleSize)) == NULL)
		return false;

	return true;
}

DWORD MemoryManagment::FindPattern(char *pattern, char *mask, DWORD moduleBaseAddr, int moduleSize)
{
	
	int patternSize = strlen(mask);
	char buffer[100];
	for (DWORD i = 0; i < moduleSize - patternSize; i++)
	{
		bool found = true;
		ReadProcessMemory(proccessHandle, (LPVOID)(moduleBaseAddr + i), &buffer, patternSize, NULL);
		for (int l = 0; l < patternSize; l++)
		{
			found = mask[l] == '?' || buffer[l] == pattern[l];
			if (!found)
				break;
		}

		if (found)
			return i;
	}
	return 0;
}


HANDLE MemoryManagment::GetProcessByName()
{
	
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 process;
	ZeroMemory(&process, sizeof(process));
	process.dwSize = sizeof(process);
	DWORD pid = 0;
	if (Process32First(snapshot, &process))
	{
		do
		{
			if (_stricmp(process.szExeFile, proccessName) == 0)
			{
				pid = process.th32ProcessID;
				proccesId = pid;
				break;
			}
		} while (Process32Next(snapshot, &process));
	}

	CloseHandle(snapshot);

	if (pid != 0)
	{
		return OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	}



	return NULL;
}


DWORD MemoryManagment::GetModuleBase(LPSTR lpModuleName, int *sizeOut)
{
	
	MODULEENTRY32 lpModuleEntry = { 0 };
	HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, proccesId);
	if (!hSnapShot)
		return NULL;
	lpModuleEntry.dwSize = sizeof(lpModuleEntry);
	BOOL bModule = Module32First(hSnapShot, &lpModuleEntry);
	while (bModule)
	{
		if (_stricmp(lpModuleEntry.szModule, lpModuleName) == 0)
		{
			CloseHandle(hSnapShot);
			*sizeOut = lpModuleEntry.modBaseSize;
			return (DWORD)lpModuleEntry.modBaseAddr;
		}
		bModule = Module32Next(hSnapShot, &lpModuleEntry);
	}
	
	CloseHandle(hSnapShot);
	return NULL;
}




C_Memory* memory = new C_Memory();

C_Memory::C_Memory()
{

}
C_Memory::~C_Memory()
{
	CloseHandle(process);
}

void C_Memory::Process(char* name)
{
	string INT8 = Test;
	if (KEY == "RandomModifying1Memory")
	{
		int junk1;
		junk1 = stoi(Test, nullptr, 2) + stoi(Test, nullptr, 2);
		if (junk1 == stoi(Test, nullptr, 2) + stoi(Test, nullptr, 2))
		{
			junk1 = stoi(Test, nullptr, 2) + stoi(Test, nullptr, 2);
		}
		if (junk1 == stoi(Test, nullptr, 2) + stoi(Test, nullptr, 2))
		{
			junk1 = stoi(Test, nullptr, 2) + stoi(Test, nullptr, 2) + stoi(Test, nullptr, 2) + stoi(Test, nullptr, 2);
		}
	}
	else if (KEY == "RandomModifying1Memory")
	{
		int junk2 = stoi(Test, nullptr, 2) + stoi(Test, nullptr, 2);
		junk2 = stoi(Test, nullptr, 2) + stoi(Test, nullptr, 2) + stoi(Test, nullptr, 2) + stoi(Test, nullptr, 2);
		if (junk2 == stoi(Test, nullptr, 2) + stoi(Test, nullptr, 2))
		{
			junk2 -= stoi(Test, nullptr, 2) + stoi(Test, nullptr, 2);
		}
		if (junk2 == stoi(Test, nullptr, 2) + stoi(Test, nullptr, 2))
		{
			junk2 += stoi(Test, nullptr, 2) + stoi(Test, nullptr, 2);
		}
	}
	else if (KEY == "RandomModifying1Memory")
	{
		int junk2 = stoi(Test, nullptr, 2) + stoi(Test, nullptr, 2);
		junk2 = stoi(Test, nullptr, 2) + stoi(Test, nullptr, 2) + stoi(Test, nullptr, 2) + stoi(Test, nullptr, 2);
		if (junk2 == stoi(Test, nullptr, 2) + stoi(Test, nullptr, 2))
		{
			junk2 -= stoi(Test, nullptr, 2) + stoi(Test, nullptr, 2);
		}
		if (junk2 == stoi(Test, nullptr, 2) + stoi(Test, nullptr, 2))
		{
			junk2 += stoi(Test, nullptr, 2) + stoi(Test, nullptr, 2);
		}
	}
	else if (KEY == "RandomModifying1Memory")
	{
		int junk3 = stoi(Test, nullptr, 2) + stoi(Test, nullptr, 2);
		junk3 = junk3 - stoi(Test, nullptr, 2) + stoi(Test, nullptr, 2);
		if (junk3)
		{
			junk3 = stoi(Test, nullptr, 2) + stoi(Test, nullptr, 2);
		}
		else
		{
			junk3 = stoi(Test, nullptr, 2) + stoi(Test, nullptr, 2);
		}
	}
	HANDLE hPID = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	PROCESSENTRY32 ProcEntry;
	ProcEntry.dwSize = sizeof(ProcEntry);

	do
		if (!strcmp(ProcEntry.szExeFile, name))
		{
			PID = ProcEntry.th32ProcessID;
			CloseHandle(hPID);

			process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
			return;
		}
	while (Process32Next(hPID, &ProcEntry));

	printf("csgo not found\n\n");
	system("pause");
	exit(0);
}

DWORD C_Memory::module(char* name)
{
	string INT8 = Test;
	if (KEY == "RandomModifying1Memory")
	{
		int junk1;
		junk1 = stoi(Test, nullptr, 2) + stoi(Test, nullptr, 2);
		if (junk1 == stoi(Test, nullptr, 2) + stoi(Test, nullptr, 2))
		{
			junk1 = stoi(Test, nullptr, 2) + stoi(Test, nullptr, 2);
		}
		if (junk1 == stoi(Test, nullptr, 2) + stoi(Test, nullptr, 2))
		{
			junk1 = stoi(Test, nullptr, 2) + stoi(Test, nullptr, 2) + stoi(Test, nullptr, 2) + stoi(Test, nullptr, 2);
		}
	}
	else if (KEY == "RandomModifying1Memory")
	{
		int junk2 = stoi(Test, nullptr, 2) + stoi(Test, nullptr, 2);
		junk2 = stoi(Test, nullptr, 2) + stoi(Test, nullptr, 2) + stoi(Test, nullptr, 2) + stoi(Test, nullptr, 2);
		if (junk2 == stoi(Test, nullptr, 2) + stoi(Test, nullptr, 2))
		{
			junk2 -= stoi(Test, nullptr, 2) + stoi(Test, nullptr, 2);
		}
		if (junk2 == stoi(Test, nullptr, 2) + stoi(Test, nullptr, 2))
		{
			junk2 += stoi(Test, nullptr, 2) + stoi(Test, nullptr, 2);
		}
	}
	else if (KEY == "RandomModifying1Memory")
	{
		int junk2 = stoi(Test, nullptr, 2) + stoi(Test, nullptr, 2);
		junk2 = stoi(Test, nullptr, 2) + stoi(Test, nullptr, 2) + stoi(Test, nullptr, 2) + stoi(Test, nullptr, 2);
		if (junk2 == stoi(Test, nullptr, 2) + stoi(Test, nullptr, 2))
		{
			junk2 -= stoi(Test, nullptr, 2) + stoi(Test, nullptr, 2);
		}
		if (junk2 == stoi(Test, nullptr, 2) + stoi(Test, nullptr, 2))
		{
			junk2 += stoi(Test, nullptr, 2) + stoi(Test, nullptr, 2);
		}
	}
	else if (KEY == "RandomModifying1Memory")
	{
		int junk3 = stoi(Test, nullptr, 2) + stoi(Test, nullptr, 2);
		junk3 = stoi(Test, nullptr, 2) + stoi(Test, nullptr, 2) - stoi(Test, nullptr, 2) + stoi(Test, nullptr, 2);
		if (junk3)
		{
			junk3 = stoi(Test, nullptr, 2) + stoi(Test, nullptr, 2);
		}
		else
		{
			junk3 = stoi(Test, nullptr, 2) + stoi(Test, nullptr, 2);
		}
	}
	HANDLE hModule = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, PID);
	MODULEENTRY32 mEntry;
	mEntry.dwSize = sizeof(mEntry);

	do
		if (!strcmp(mEntry.szModule, name))
		{
			CloseHandle(hModule);
			return (DWORD)mEntry.modBaseAddr;
		}
	while (Module32Next(hModule, &mEntry));

	return 0;
}

DWORD C_Memory::moduleSize(char* name)
{
	HANDLE hModule = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, PID);
	MODULEENTRY32 mEntry;
	mEntry.dwSize = sizeof(mEntry);

	do
		if (!strcmp(mEntry.szModule, name))
		{
			CloseHandle(hModule);
			return (DWORD)mEntry.modBaseSize;
		}
	while (Module32Next(hModule, &mEntry));

	return 0;
}

bool DataCompare(BYTE* data, BYTE* sign, char* mask)
{
	for (; *mask; mask++, sign++, data++)
	{
		if (*mask == 'x' && *data != *sign)
		{
			return false;
		}
	}
	return true;
}

DWORD C_Memory::grabSig(DWORD base, DWORD size, BYTE* sign, char* mask)
{
	string INT8 = Test;
	if (KEY == "RandomModifying1Memory")
	{
		int junk1;
		junk1 = stoi(Test, nullptr, 2) + stoi(Test, nullptr, 2);
		if (junk1 == stoi(Test, nullptr, 2) + stoi(Test, nullptr, 2))
		{
			junk1 = stoi(Test, nullptr, 2) + stoi(Test, nullptr, 2);
		}
		if (junk1 == stoi(Test, nullptr, 2) + stoi(Test, nullptr, 2))
		{
			junk1 = stoi(Test, nullptr, 2) + stoi(Test, nullptr, 2) + stoi(Test, nullptr, 2) + stoi(Test, nullptr, 2);
		}
	}
	else if (KEY == "RandomModifying1Memory")
	{
		int junk2 = 1;
		junk2 = stoi(Test, nullptr, 2) + stoi(Test, nullptr, 2) + stoi(Test, nullptr, 2) + stoi(Test, nullptr, 2);
		if (junk2 == stoi(Test, nullptr, 2) + stoi(Test, nullptr, 2))
		{
			junk2 -= stoi(Test, nullptr, 2) + stoi(Test, nullptr, 2);
		}
		if (junk2 == stoi(Test, nullptr, 2) + stoi(Test, nullptr, 2))
		{
			junk2 += stoi(Test, nullptr, 2) + stoi(Test, nullptr, 2);
		}
	}
	else if (KEY == "RandomModifying1Memory")
	{
		int junk2 = 1;
		junk2 = stoi(Test, nullptr, 2) + stoi(Test, nullptr, 2) + stoi(Test, nullptr, 2) + stoi(Test, nullptr, 2);
		if (junk2 == stoi(Test, nullptr, 2) + stoi(Test, nullptr, 2))
		{
			junk2 -= stoi(Test, nullptr, 2) + stoi(Test, nullptr, 2);
		}
		if (junk2 == stoi(Test, nullptr, 2) + stoi(Test, nullptr, 2))
		{
			junk2 -= stoi(Test, nullptr, 2) + stoi(Test, nullptr, 2) + stoi(Test, nullptr, 2) + stoi(Test, nullptr, 2);
		}
	}
	else if (KEY == "RandomModifying1Memory")
	{
		int junk3 = stoi(Test, nullptr, 2) + stoi(Test, nullptr, 2);
		junk3 = stoi(Test, nullptr, 2) + stoi(Test, nullptr, 2) - stoi(Test, nullptr, 2) + stoi(Test, nullptr, 2);
		if (junk3)
		{
			junk3 = stoi(Test, nullptr, 2) + stoi(Test, nullptr, 2);
		}
		else
		{
			junk3 = stoi(Test, nullptr, 2) + stoi(Test, nullptr, 2);
		}
	}
	MEMORY_BASIC_INFORMATION mbi = { 0 };
	DWORD offset = 0;
	while (offset < size)
	{
		VirtualQueryEx(process, (LPCVOID)(base + offset), &mbi, sizeof(MEMORY_BASIC_INFORMATION));
		if (mbi.State != MEM_FREE)
		{
			BYTE* buffer = new BYTE[mbi.RegionSize];
			ReadProcessMemory(process, mbi.BaseAddress, buffer, mbi.RegionSize, NULL);
			for (int i = 0; i < mbi.RegionSize; i++)
			{
				if (DataCompare(buffer + i, sign, mask))
				{
					delete[] buffer;
					return (DWORD)mbi.BaseAddress + i;
				}
			}

			delete[] buffer;
		}
		offset += mbi.RegionSize;
	}
	return 0;
}

