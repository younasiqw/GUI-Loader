#pragma once
#include <Windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <cstdlib>
#include <string>
#include <sstream>

class C_Memory
{
public:
	C_Memory();
	~C_Memory();

	DWORD PID;
	HANDLE process;

	virtual void Process(char* name);
	virtual DWORD module(char* name);
	virtual DWORD moduleSize(char* name);
	DWORD grabSig(DWORD base, DWORD size, BYTE* sign, char* mask);
};

extern C_Memory* memory;

class MemoryManagment
{
public:
	MemoryManagment(char* proccesName);
	~MemoryManagment();


	bool Initialize();
	bool Initialize2();
	bool Initialize3();
	bool Initialize4();
	DWORD FindPattern(char *pattern, char *mask, DWORD moduleBaseAddr, int moduleSize);

	template<class T>
	inline T Read(DWORD address);

	template<class T>
	inline void Write(DWORD address, T value);

	int clientModuleSize;
	DWORD clientModuleBase;

	int engineModuleSize;
	DWORD engineModuleBase;

	void command(const char* command);
	void spam();

private:
	char* proccessName;
	HANDLE proccessHandle;
	int proccesId;

	HANDLE GetProcessByName();
	DWORD GetModuleBase(LPSTR lpModuleName, int* sizeOut);

};




template<class T>
T MemoryManagment::Read(DWORD address)
{
	T temp;
	ReadProcessMemory(proccessHandle, (LPVOID)address, &temp, sizeof(T), NULL);
	return temp;
}


template<class T>
void MemoryManagment::Write(DWORD address, T value)
{
	WriteProcessMemory(proccessHandle, (LPVOID)address, &value, sizeof(T), NULL);
}
