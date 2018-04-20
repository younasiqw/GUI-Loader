#pragma once
#include <Windows.h>
#include <string>
#include <iostream>
#include <time.h> 
#include <msclr\marshal_cppstd.h>
#include "MemoryManagment.h"
#include "ManualMap.h"
#include <fstream>
#include "AntiLeak.h"
#include <algorithm>  //for std::generate_n
#pragma comment(lib, "wldap32.lib" )
#pragma comment(lib, "crypt32.lib" )
#define CURL_STATICLIB
#define VersionNumber 4
#include <curl.h>
#include <Strsafe.h>
#define SELF_REMOVE_STRING  TEXT("cmd.exe /C ping 1.1.1.1 -n 1 -w 3000 > Nul & Del \"%s\"")

std::string UsernameGlobal;
std::string PasswordGlobal;
#define A 12312
#define B 23423
#define C 34534
#define FIRSTH 37
#define FIRSTH 37
unsigned hash_str(const char* s)
{
	unsigned h = FIRSTH;
	while (*s) {
		h = (h * A) ^ (s[0] * B);
		s++;
	}
	return h; // or return h % C;
}

inline std::string encrypt(std::string msg, std::string key)
{
	// Make sure the key is at least as long as the message
	std::string tmp(key);
	while (key.size() < msg.size())
		key += tmp;

	// And now for the encryption part
	for (std::string::size_type i = 0; i < msg.size(); ++i)
		msg[i] ^= key[i];
	return msg;
}
inline std::string decrypt(std::string msg, std::string key)
{
	return encrypt(msg, key); // lol
}

std::string data; //will hold the url's contents
void mParseUrl(char *mUrl, std::string &serverName, std::string &filepath, std::string &filename)
{
	using namespace std;
	string::size_type n;
	string url = mUrl;

	if (url.substr(0, 7) == "http://")
		url.erase(0, 7);

	if (url.substr(0, 8) == "https://")
		url.erase(0, 8);

	n = url.find('/');
	if (n != string::npos)
	{
		serverName = url.substr(0, n);
		filepath = url.substr(n);
		n = filepath.rfind('/');
		filename = filepath.substr(n + 1);
	}

	else
	{
		serverName = url;
		filepath = "/";
		filename = "";
	}
}

SOCKET connectToServer(char *szServerName, WORD portNum)
{
	struct hostent *hp;
	unsigned int addr;
	struct sockaddr_in server;
	SOCKET conn;

	conn = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (conn == INVALID_SOCKET)
		return NULL;

	if (inet_addr(szServerName) == INADDR_NONE)
	{
		hp = gethostbyname(szServerName);
	}
	else
	{
		addr = inet_addr(szServerName);
		hp = gethostbyaddr((char*)&addr, sizeof(addr), AF_INET);
	}

	if (hp == NULL)
	{
		closesocket(conn);
		return NULL;
	}

	server.sin_addr.s_addr = *((unsigned long*)hp->h_addr);
	server.sin_family = AF_INET;
	server.sin_port = htons(portNum);
	if (connect(conn, (struct sockaddr*)&server, sizeof(server)))
	{
		closesocket(conn);
		return NULL;
	}
	return conn;
}

int getHeaderLength(char *content)
{
	const char *srchStr1 = "\r\n\r\n", *srchStr2 = "\n\r\n\r";
	char *findPos;
	int ofset = -1;

	findPos = strstr(content, srchStr1);
	if (findPos != NULL)
	{
		ofset = findPos - content;
		ofset += strlen(srchStr1);
	}

	else
	{
		findPos = strstr(content, srchStr2);
		if (findPos != NULL)
		{
			ofset = findPos - content;
			ofset += strlen(srchStr2);
		}
	}
	return ofset;
}

char *readUrl2(char *szUrl, long &bytesReturnedOut, char **headerOut)
{
	using namespace std;
	const int bufSize = 512;
	char readBuffer[bufSize], sendBuffer[bufSize], tmpBuffer[bufSize];
	char *tmpResult = NULL, *result;
	SOCKET conn;
	string server, filepath, filename;
	long totalBytesRead, thisReadSize, headerLen;

	mParseUrl(szUrl, server, filepath, filename);

	///////////// step 1, connect //////////////////////
	conn = connectToServer((char*)server.c_str(), 80);

	///////////// step 2, send GET request /////////////
	sprintf(tmpBuffer, "GET %s HTTP/1.0", filepath.c_str());
	strcpy(sendBuffer, tmpBuffer);
	strcat(sendBuffer, "\r\n");
	sprintf(tmpBuffer, "Host: %s", server.c_str());
	strcat(sendBuffer, tmpBuffer);
	strcat(sendBuffer, "\r\n");
	strcat(sendBuffer, "\r\n");
	send(conn, sendBuffer, strlen(sendBuffer), 0);

	//    SetWindowText(edit3Hwnd, sendBuffer);
	printf("Buffer being sent:\n%s", sendBuffer);

	///////////// step 3 - get received bytes ////////////////
	// Receive until the peer closes the connection
	totalBytesRead = 0;
	while (1)
	{
		memset(readBuffer, 0, bufSize);
		thisReadSize = recv(conn, readBuffer, bufSize, 0);

		if (thisReadSize <= 0)
			break;

		tmpResult = (char*)realloc(tmpResult, thisReadSize + totalBytesRead);

		memcpy(tmpResult + totalBytesRead, readBuffer, thisReadSize);
		totalBytesRead += thisReadSize;
	}

	headerLen = getHeaderLength(tmpResult);
	long contenLen = totalBytesRead - headerLen;
	result = new char[contenLen + 1];
	memcpy(result, tmpResult + headerLen, contenLen);
	result[contenLen] = 0x0;
	char *myTmp;

	myTmp = new char[headerLen + 1];
	strncpy(myTmp, tmpResult, headerLen);
	myTmp[headerLen] = NULL;
	delete(tmpResult);
	*headerOut = myTmp;

	bytesReturnedOut = contenLen;
	closesocket(conn);
	return(result);
}
static size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
	((std::string*)userp)->append((char*)contents, size * nmemb);
	return size * nmemb;
}
std::string GetData()
{
	CURL *curl;
	CURLcode res;
	std::string readBuffer;
	std::string empty = "";

	curl = curl_easy_init();
	if (curl) {
		curl_easy_setopt(curl, CURLOPT_URL, "https://data/r4h65WDH46Wr4had65f4h65EDSF4H4w94r8hwsf46h21wr65h1WR65H98W.php");
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
		res = curl_easy_perform(curl);
		curl_easy_cleanup(curl);

		return readBuffer;
	}
	return empty;

}
size_t write_data(void *ptr, size_t size, size_t nmemb, FILE *stream)
{
	size_t written;
	written = fwrite(ptr, size, nmemb, stream);
	return written;
}
int currentDateTime()
{
	using namespace std;
	time_t theTime = time(NULL);
	struct tm *aTime = localtime(&theTime);

	int day = aTime->tm_mday;
	int month = aTime->tm_mon + 1; // Month is 0 – 11, add 1 to get a jan-dec 1-12 concept
	int year = aTime->tm_year + 1900; // Year is # years since 1900
	int hour = aTime->tm_hour;
	int min = aTime->tm_min;

	int Time = year + month + day + hour + min;
	return Time;
}
std::string random_string(size_t length)
{
	auto randchar = []() -> char
	{
		const char charset[] =
			"0123456789"
			"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
			"abcdefghijklmnopqrstuvwxyz";
		const size_t max_index = (sizeof(charset) - 1);
		return charset[rand() % max_index];
	};
	std::string str(length, 0);
	std::generate_n(str.begin(), length, randchar);
	return str;
}


std::string HWIDCombine;
std::string HWID()
{
	using namespace std;

	SYSTEM_INFO siSysInfo;
	string UserComputerName;
	string test;
	string UserOsGUID;
	// Copy the hardware information to the SYSTEM_INFO structure. 
	// GetVolumeInformationA
	DWORD DriveSerial;

	// GetComputerNameA
	TCHAR ComputerName[MAX_COMPUTERNAME_LENGTH + 1];
	DWORD size = sizeof(ComputerName) / sizeof(ComputerName[0]);
	// OS GUID
	string OsGUID;
	GetVolumeInformationA(0, nullptr, '\0', &DriveSerial, nullptr, nullptr, nullptr, 0);
	GetComputerNameA(ComputerName, &size);
	//UserDriveSerial = to_string(DriveSerial);
	HW_PROFILE_INFO hwProfileInfo;
	if (GetCurrentHwProfile(&hwProfileInfo))
	{
		UserOsGUID = hwProfileInfo.szHwProfileGuid;
		test = hwProfileInfo.szHwProfileName;
	}
	UserComputerName = ComputerName;

	string Messer = "sda23ad";
	GetSystemInfo(&siSysInfo);
	HWIDCombine = Messer + UserComputerName + UserOsGUID;
	return HWIDCombine;

}
template<typename Out>
void split(const std::string &s, char delim, Out result)
{
	std::stringstream ss;
	ss.str(s);
	std::string item;
	while (std::getline(ss, item, delim)) {
		*(result++) = item;
	}
}
std::vector<std::string> split(const std::string &s, char delim)
{
	std::vector<std::string> elems;
	split(s, delim, std::back_inserter(elems));
	return elems;
}
bool DownloadHacks = false;
std::string Username;
std::string Password;
std::string Email;
bool isInCharString(char *str1, char *search)
{
	for (int i = 0; i < strlen(str1); ++i)
	{
		if (strncmp(&str1[i], search, strlen(search)) == 0)
			return true;
	}

	return false;
}
bool UserIsPremiumEmail()
{
	using namespace std;
	HINSTANCE hInst;
	WSADATA wsaData;

	int x = 0;
	string SplitEmail1;
	string SplitEmail2;
	const int bufLen = 1024;
	std::vector<std::string> SplitEmail = split(Email, '@');
	for (const auto& text : SplitEmail)
	{

		if (x == 0)
		{
			SplitEmail1 = text;
		}
		if (x == 1)
		{
			SplitEmail2 = text;
		}
		x++;
	}
	string SplitEmail3 = SplitEmail1 + "%40" + SplitEmail2;
	string URL = "https://EMAILCHCER/7f0739a6a256f48d79fd44c72f2e22ec12312323132123123132/emailcheck_get.php?email=" + SplitEmail3 + "&submit=Submit";
	char *szUrl = new char[URL.length() + 1];
	strcpy(szUrl, URL.c_str());

	long fileSize;
	char *memBuffer, *headerBuffer;
	FILE *fp;

	memBuffer = headerBuffer = NULL;

	if (WSAStartup(0x101, &wsaData) != 0)
		exit(1);

	memBuffer = readUrl2(szUrl, fileSize, &headerBuffer);
	delete[] szUrl;
	WSACleanup();
	/*
	'Admin---------------------4
	'Premium Garry's Mod-------11
	'Premium CS:GO Lite--------9
	'Premium CS:GO Beta--------10
	'Premium CS:GO-------------8
	'Banned--------------------7
	'Not-----------------------2
	*/
	std::vector<std::string> websiteData = split(memBuffer, ',');
	for (const auto& text : websiteData)
	{
		char *testchar = new char[text.length() + 1];
		strcpy(testchar, text.c_str());
		std::vector<std::string> Something = split(text, ',');
		if (isInCharString(testchar, "8") || isInCharString(testchar, "4")) // checks the .txt file if you are allowed
		{
			return true;
		}
		delete[] testchar;
	}
	return false;
}
bool UserIsPremium()
{
	using namespace std;
	HINSTANCE hInst;
	WSADATA wsaData;

	const int bufLen = 1024;
	string URL = "http://YOURWEBSITETOCHECKPREMIUM/7f0739a6a256f48d79fd44c72f2e22ec12312323132123123132/usercheck_get.php?username=" + Username + "&submit=Submit";
	char *szUrl = new char[URL.length() + 1];
	strcpy(szUrl, URL.c_str());

	long fileSize;
	char *memBuffer, *headerBuffer;
	FILE *fp;

	memBuffer = headerBuffer = NULL;

	if (WSAStartup(0x101, &wsaData) != 0)
		exit(1);

	memBuffer = readUrl2(szUrl, fileSize, &headerBuffer);
	delete[] szUrl;
	WSACleanup();
	/*
	'Admin---------------------4
	'Premium Garry's Mod-------11
	'Premium CS:GO Lite--------9
	'Premium CS:GO Beta--------10
	'Premium CS:GO-------------8
	'Banned--------------------7
	'Not-----------------------2
	*/
	std::vector<std::string> websiteData = split(memBuffer, ',');
	for (const auto& text : websiteData)
	{
		char *testchar = new char[text.length() + 1];
		strcpy(testchar, text.c_str());
		std::vector<std::string> Something = split(text, ',');
		if (isInCharString(testchar, "8") || isInCharString(testchar, "4")) // checks the .txt file if you are allowed
		{
			return true;
		}
		delete[] testchar;
	}
	return false;
}
HINSTANCE hInst;
WSADATA wsaData;
std::string GetFileSize()
{
	CURL *curl;
	CURLcode res;
	std::string readBuffer;
	std::string empty = "";

	curl = curl_easy_init();
	if (curl) {
		curl_easy_setopt(curl, CURLOPT_URL, "FILE SIZE OF THE HACK");
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
		res = curl_easy_perform(curl);
		curl_easy_cleanup(curl);

		return readBuffer;
	}
	return empty;
}
int get_file_size(std::string filename) // path to file
{
	FILE *p_file = NULL;
	p_file = fopen(filename.c_str(), "rb");
	fseek(p_file, 0, SEEK_END);
	int size = ftell(p_file);
	fclose(p_file);
	return size;
}
void DownloadHACKS()
{
	remove("C:\\Windows\\Proxy.dll");
	CURL *curl;
	FILE *fp;
	CURLcode res;
	char *url = "HACK FOLDER"; // downloads the hack
																																									//char outfilename[FILENAME_MAX] = "C:\\Windows\\Proxy.dll"; // where will it be stored
	curl = curl_easy_init();
	if (curl)
	{
		system("CLS");
		fp = fopen("C:\\Windows\\Proxy.dll", "wb");
		system("CLS");
		curl_easy_setopt(curl, CURLOPT_URL, url);
		system("CLS");
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
		system("CLS");
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
		system("CLS");
		curl_easy_setopt(curl, CURLOPT_VERBOSE, 0L);
		system("CLS");
		res = curl_easy_perform(curl);
		system("CLS");
		curl_easy_cleanup(curl);
		system("CLS");
		fclose(fp);
		system("CLS");
	}
	if (std::to_string(get_file_size("C://Windows//Proxy.dll")) != GetFileSize())
	{
		remove("C:\\Windows\\Proxy.dll");
		CheckForDebuggers();
		CheckForDebugger();
		AntiLeak->ErasePE();
		exit(1);
	}
}
void CheckHWID()
{
	using namespace std;
	/*std::vector<std::string> websiteData = split(GetData(), '::');
	for (const auto& text : websiteData)
	{
		std::vector<std::string> Something = split(text, ' ');
		string DataSplit = to_string(hash_str(Email.c_str())) + " " + to_string(hash_str(Username.c_str())) + " " + to_string(hash_str(HWID().c_str()));
		if (text == DataSplit) // checks the .txt file if you are allowed
		{
			DownloadHacks = true;
			break;
		}

			CheckForDebuggers();
			CheckForDebugger();
			using namespace System;
			using namespace System::ComponentModel;
			using namespace System::Collections;
			using namespace System::Windows::Forms;
			using namespace System::Data;
			using namespace System::Drawing;
			ofstream Communication;
			srand(time(NULL));
			int v1 = rand() % 1012340;         // v1 in the range 0 to 99
			int v2 = rand() % 1012340 + 11243;     // v2 in the range 1 to 100
			int v3 = rand() % 312340 + 19851234;   // v3 in the range 1985-2014
			int v4 = rand() % 1012340;         // v1 in the range 0 to 99
			int v5 = rand() % 1012340 + 123;     // v2 in the range 1 to 100
			int v6 = rand() % 31230 + 1912385;   // v3 in the range 1985-2014
			int v7 = rand() % 112300;         // v1 in the range 0 to 99
			int v8 = rand() % 101230 +1231;     // v2 in the range 1 to 100
			int v9 = rand() % 31230 + 1985;   // v3 in the range 1985-2014
			int v10 = rand() % 112300;         // v1 in the range 0 to 99
			int v11= rand() % 101230 + 1231;     // v2 in the range 1 to 100
			int v12  = rand() % 31230 + 1123985;   // v3 in the range 1985-2014
			Communication.open("Logs.txt");
			Communication << "UserName: " << Username << "-" << v7 << "-0912359213492134-21356-253164923-8146-29135680-" << v10 <<"-2508921364-21356-9234012356921-34-2135623040-" << v11 << "-213568219-651-23640921358692-134462301945902314-" << hash_str(HWID().c_str());
			Communication.close();
			exit(1);

	}*/
	using namespace System;
	using namespace System::ComponentModel;
	using namespace System::Collections;
	using namespace System::Windows::Forms;
	using namespace System::Data;
	using namespace System::Drawing;
	const int bufLen = 1024;
	string URL = "http://YOURWEBSITE/7f0739a6a256f48d79fd44c72f2e22ec12312323132123123132/hwid_get.php?username=" + Username + "&hwidin=" + HWID() + "&submit=Submit";
	char *szUrl = new char[URL.length() + 1];
	strcpy(szUrl, URL.c_str());

	long fileSize;
	char *memBuffer, *headerBuffer;
	FILE *fp;

	memBuffer = headerBuffer = NULL;

	if (WSAStartup(0x101, &wsaData) != 0)
		exit(1);


	bool DownloadHacks1 = false;
	bool DownloadHacks2 = false;
	memBuffer = readUrl2(szUrl, fileSize, &headerBuffer);
	delete[] szUrl;
	WSACleanup();

	if (isInCharString(memBuffer, "HWID is correct"))
	{
		DownloadHacks1 = true;
	}
	else
	{
		remove("C:\\Windows\\Proxy.dll");
		CheckForDebuggers();
		CheckForDebugger();
		AntiLeak->ErasePE();
		MessageBox::Show("0xvlfcfff - Critical Error", "ERROR", MessageBoxButtons::OK, MessageBoxIcon::Exclamation);
		exit(1);
	}

	if (UserIsPremium() && DownloadHacks1 && UserIsPremiumEmail())
	{
		DownloadHacks = true;
	}

}
void DelMe()
{
	TCHAR szModuleName[MAX_PATH];
	TCHAR szCmd[2 * MAX_PATH];
	STARTUPINFO si = { 0 };
	PROCESS_INFORMATION pi = { 0 };

	GetModuleFileName(NULL, szModuleName, MAX_PATH);

	StringCbPrintf(szCmd, 2 * MAX_PATH, SELF_REMOVE_STRING, szModuleName);

	CreateProcess(NULL, szCmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);

	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);
}
std::string GetVersionNumber()
{
	CURL *curl;
	CURLcode res;
	std::string readBuffer;
	std::string empty = "";

	curl = curl_easy_init();
	if (curl) {
		curl_easy_setopt(curl, CURLOPT_URL, "GET THE VERSION NUMBER LINK");
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
		res = curl_easy_perform(curl);
		curl_easy_cleanup(curl);

		return readBuffer;
	}
	return empty;
}
std::string GetStatusNumber()
{
	CURL *curl;
	CURLcode res;
	std::string readBuffer;
	std::string empty = "";

	curl = curl_easy_init();
	if (curl) {
		curl_easy_setopt(curl, CURLOPT_URL, "YOUR WEBSITE FOR SHOWING STATUS");
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
		res = curl_easy_perform(curl);
		curl_easy_cleanup(curl);

		return readBuffer;
	}
	return empty;
}

void DownloadLoaderUpdate()
{
	CURL *curl;
	FILE *fp;
	CURLcode res;

	char *url = "THE LINK TO DOWNLOAD THE LOADER"; // dwonlaod link to the txt
	char outfilename[FILENAME_MAX]; // where will it be stored
	sprintf(outfilename, "loader v%s.exe", GetVersionNumber().c_str());
	curl = curl_easy_init();
	if (curl)
	{
		system("CLS");
		fp = fopen(outfilename, "wb");
		system("CLS");
		curl_easy_setopt(curl, CURLOPT_URL, url);
		system("CLS");
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
		system("CLS");
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
		system("CLS");
		curl_easy_setopt(curl, CURLOPT_VERBOSE, 0L);
		system("CLS");
		res = curl_easy_perform(curl);
		system("CLS");
		curl_easy_cleanup(curl);
		system("CLS");
		fclose(fp);
		system("CLS");
	}
}
void CheckLoaderVersion()
{
	if (stoi(GetVersionNumber()) > 1)
	{
		system("CLS");
		CheckHWID();
		char buffer[FILENAME_MAX];
		sprintf(buffer, "loader v%s.exe", GetVersionNumber().c_str());
		ShellExecute(NULL, "open", buffer, NULL, NULL, SW_SHOWDEFAULT);
		DelMe();
		exit(1);
	}

}
void injectCodeUsingThreadInjection(HANDLE process, LPVOID func, int times, const char* string)
{
	BYTE codeCave[20] = {
		0xFF, 0x74, 0x24, 0x04, // PUSH DWORD PTR[ESP+0x4]
		0x68, 0x00, 0x00, 0x00, 0x00, // PUSH 0
		0xB8, 0x00, 0x00, 0x00, 0x00, // MOV EAX, 0x0
		0xFF, 0xD0, // CALL EAX
		0x83, 0xC4, 0x08, // ADD ESP, 0x08
		0xC3 // RETN
	};

	// copy values to the shellcode
	memcpy(&codeCave[5], &times, 4);
	memcpy(&codeCave[10], &func, 4);


	// allocate memory for the code cave
	int stringlen = strlen(string) + 1;
	int fulllen = stringlen + sizeof(codeCave);
	LPVOID remoteString = VirtualAllocEx(process, NULL, fulllen, MEM_COMMIT, PAGE_EXECUTE);
	LPVOID remoteCave = (LPVOID)((DWORD)remoteString + stringlen);

	// write the code cave
	WriteProcessMemory(process, remoteString, string, stringlen, NULL);
	WriteProcessMemory(process, remoteCave, codeCave, sizeof(codeCave), NULL);

	// run the thread
	HANDLE thread = CreateRemoteThread(process, NULL, NULL,
		(LPTHREAD_START_ROUTINE)remoteCave,
		remoteString, NULL, NULL);
	WaitForSingleObject(thread, INFINITE);
	CloseHandle(thread);
}
DWORD GetProcessThreadID(HANDLE Process)
{
	THREADENTRY32 entry;
	entry.dwSize = sizeof(THREADENTRY32);
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

	if (Thread32First(snapshot, &entry) == TRUE)
	{
		DWORD PID = GetProcessId(Process);
		while (Thread32Next(snapshot, &entry) == TRUE)
		{
			if (entry.th32OwnerProcessID == PID)
			{
				CloseHandle(snapshot);
				return entry.th32ThreadID;
			}
		}
	}
	CloseHandle(snapshot);
	return NULL;
}
void injectCodeUsingThreadHijacking(HANDLE process, LPVOID func, int times, const char* string)
{
	BYTE codeCave[31] = {
		0x60, //PUSHAD
		0x9C, //PUSHFD
		0x68, 0x00, 0x00, 0x00, 0x00, // PUSH 0
		0x68, 0x00, 0x00, 0x00, 0x00, // PUSH 0
		0xB8, 0x00, 0x00, 0x00, 0x00, // MOV EAX, 0x0
		0xFF, 0xD0, // CALL EAX
		0x83, 0xC4, 0x08, // ADD ESP, 0x08
		0x9D, //POPFD
		0x61, //POPAD
		0x68, 0x00, 0x00, 0x00, 0x00, // PUSH 0
		0xC3 // RETN
	};

	// allocate memory for the coe cave
	int stringlen = strlen(string) + 1;
	int fulllen = stringlen + sizeof(codeCave);
	LPVOID remoteString = VirtualAllocEx(process, NULL, fulllen, MEM_COMMIT, PAGE_EXECUTE);
	LPVOID remoteCave = (LPVOID)((DWORD)remoteString + stringlen);

	// suspend the thread and query its control context
	DWORD threadID = GetProcessThreadID(process);
	HANDLE thread = OpenThread((THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_SET_CONTEXT), false, threadID);
	SuspendThread(thread);

	CONTEXT threadContext;
	threadContext.ContextFlags = CONTEXT_CONTROL;
	GetThreadContext(thread, &threadContext);

	// copy values to the shellcode (happens late because we need values from allocation)
	memcpy(&codeCave[3], &remoteString, 4);
	memcpy(&codeCave[8], &times, 4);
	memcpy(&codeCave[13], &func, 4);
	memcpy(&codeCave[25], &threadContext.Eip, 4);


	// write the code cave
	WriteProcessMemory(process, remoteString, string, stringlen, NULL);
	WriteProcessMemory(process, remoteCave, codeCave, sizeof(codeCave), NULL);


	//hijack the thread
	threadContext.Eip = (DWORD)remoteCave;
	threadContext.ContextFlags = CONTEXT_CONTROL;
	SetThreadContext(thread, &threadContext);
	ResumeThread(thread);

	//clean
	CloseHandle(thread);
}
DWORD printStringManyTimes(int times, const char* string)
{
	for (int i = 0; i < times; i++)
		printf(string);
	return 0;
}
DWORD WINAPI hijackThread(LPVOID lpParam)
{
	injectCodeUsingThreadHijacking((HANDLE)lpParam, &printStringManyTimes, 2, "hijacked\n");
	return 1;
}
void LoadDll(HANDLE process, const wchar_t* dllPath)
{
	// write the dll name to memory
	int namelen = wcslen(dllPath) + 1;
	LPVOID remoteString = VirtualAllocEx(process, NULL, namelen * 2, MEM_COMMIT, PAGE_EXECUTE);
	WriteProcessMemory(process, remoteString, dllPath, namelen * 2, NULL);

	// get the address of LoadLibraryW()
	HMODULE k32 = GetModuleHandleA("kernel32.dll");
	LPVOID funcAdr = GetProcAddress(k32, "LoadLibraryW");

	// create the thread
	HANDLE thread =
		CreateRemoteThread(process, NULL, NULL, (LPTHREAD_START_ROUTINE)funcAdr, remoteString, NULL, NULL);

	// let the thread finish and clean up
	WaitForSingleObject(thread, INFINITE);
	CloseHandle(thread);
}
DWORD GetTargetThreadIDFromProcName(const char * ProcName)
{
	PROCESSENTRY32 pe;
	HANDLE thSnapShot;
	BOOL retval, ProcFound = false;

	thSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (thSnapShot == INVALID_HANDLE_VALUE)
	{
		//MessageBox(NULL, "Error: Unable to create toolhelp snapshot!", "2MLoader", MB_OK); 
		return false;
	}

	pe.dwSize = sizeof(PROCESSENTRY32);

	retval = Process32First(thSnapShot, &pe);
	while (retval)
	{
		if (strstr(pe.szExeFile, ProcName))
		{
			return pe.th32ProcessID;
		}
		retval = Process32Next(thSnapShot, &pe);
	}
	return 0;
}
BOOL Inject(DWORD pID, const char * DLL_NAME)
{
	HANDLE Proc;
	HMODULE hLib;
	char buf[50] = { 0 };
	LPVOID RemoteString, LoadLibAddy;

	if (!pID)
		return false;

	Proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pID);
	if (!Proc)
	{
		return false;
	}

	LoadLibAddy = (LPVOID)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");

	// Allocate space in the process for our DLL 
	RemoteString = (LPVOID)VirtualAllocEx(Proc, NULL, strlen(DLL_NAME), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	// Write the string name of our DLL in the memory allocated 
	WriteProcessMemory(Proc, (LPVOID)RemoteString, DLL_NAME, strlen(DLL_NAME), NULL);

	// Load our DLL 
	CreateRemoteThread(Proc, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibAddy, (LPVOID)RemoteString, NULL, NULL);

	CloseHandle(Proc);
	return true;
}



void InjectedCSGO()
{
	
	// Get the dll's full path name 
	char buf[MAX_PATH] = { 0 };
	GetFullPathName("C:\\Windows\\Proxy.dll", MAX_PATH, buf, NULL);
	HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetTargetThreadIDFromProcName("csgo.exe"));
	const wchar_t* DLLPATH = (const wchar_t*)"C:\\Windows\\Proxy.dll";
	Inject(GetTargetThreadIDFromProcName("csgo.exe"), "C:\\Windows\\Proxy.dll");

	using namespace std;
	//string proccessname;
	//string dllname;
	//string InjectionMethodTemp;
	//proccessname = "csgo.exe";
	//dllname = "C:\\Windows\\Proxy.dll";
	//manual_map->manualmapmain(proccessname.c_str(), dllname.c_str(), 0);


}

namespace LoaderUI {

	using namespace System;
	using namespace System::ComponentModel;
	using namespace System::Collections;
	using namespace System::Windows::Forms;
	using namespace System::Data;
	using namespace System::Drawing;

	/// <summary>
	/// Summary for Login
	/// </summary>
	public ref class Login : public System::Windows::Forms::Form
	{
	public:
		Login(void)
		{
			MemoryManagment Mem("csgo.exe");
			using namespace std;

			remove("C:\\Windows\\username.txt");
			remove("C:\\Windows\\email.txt");
			remove("C:\\Windows\\password.txt");
			remove("C:\\Windows\\Proxy.dll");
			remove("C:\\Windows\\communication.txt");

			ofstream Communication;
			Communication.open("C:\\Windows\\communication.txt");
			Communication << "12312487213681263";
			Communication.close();

			if (Mem.Initialize())
			{
				remove("C:\\Windows\\Proxy.dll");
				CheckForDebuggers();
				CheckForDebugger();
				InitializeComponent();
			}
			else
			{
				remove("C:\\Windows\\Proxy.dll");
				CheckForDebuggers();
				CheckForDebugger();
				AntiLeak->ErasePE();
				MessageBox::Show("0x000aaa - Critical Error (CS:GO Not Open)", "ERROR", MessageBoxButtons::OK, MessageBoxIcon::Exclamation);
				exit(1);
			}
			//
			//TODO: Add the constructor code here
			//
		}

	protected:
		/// <summary>
		/// Clean up any resources being used.
		/// </summary>
		~Login()
		{
			if (components)
			{
				delete components;
			}
		}

	private: System::Windows::Forms::Button^  button1;
	private: System::Windows::Forms::Button^  button2;
	private: System::Windows::Forms::TextBox^  textBox1;
	private: System::Windows::Forms::Label^  label1;
	private: System::Windows::Forms::Label^  label2;
	private: System::Windows::Forms::TextBox^  textBox2;
	private: System::Windows::Forms::Label^  label3;
	private: System::Windows::Forms::TextBox^  textBox3;
	private: System::Windows::Forms::CheckBox^  checkBox1;
	private: System::Windows::Forms::CheckBox^  checkBox2;
	private: System::Windows::Forms::Label^  label4;
	private: System::Windows::Forms::Label^  label5;
	private: System::Windows::Forms::Label^  label6;




	protected:

	private:
		/// <summary>
		/// Required designer variable.
		/// </summary>
		System::ComponentModel::Container ^components;

#pragma region Windows Form Designer generated code
		/// <summary>
		/// Required method for Designer support - do not modify
		/// the contents of this method with the code editor.
		/// </summary>
		void InitializeComponent(void)
		{
			this->button1 = (gcnew System::Windows::Forms::Button());
			this->button2 = (gcnew System::Windows::Forms::Button());
			this->textBox1 = (gcnew System::Windows::Forms::TextBox());
			this->label1 = (gcnew System::Windows::Forms::Label());
			this->label2 = (gcnew System::Windows::Forms::Label());
			this->textBox2 = (gcnew System::Windows::Forms::TextBox());
			this->label3 = (gcnew System::Windows::Forms::Label());
			this->textBox3 = (gcnew System::Windows::Forms::TextBox());
			this->checkBox1 = (gcnew System::Windows::Forms::CheckBox());
			this->checkBox2 = (gcnew System::Windows::Forms::CheckBox());
			this->label4 = (gcnew System::Windows::Forms::Label());
			this->label5 = (gcnew System::Windows::Forms::Label());
			this->label6 = (gcnew System::Windows::Forms::Label());
			this->SuspendLayout();
			// 
			// button1
			// 
			this->button1->BackColor = System::Drawing::SystemColors::AppWorkspace;
			this->button1->FlatStyle = System::Windows::Forms::FlatStyle::Popup;
			this->button1->ForeColor = System::Drawing::SystemColors::ActiveCaptionText;
			this->button1->Location = System::Drawing::Point(12, 359);
			this->button1->Name = L"button1";
			this->button1->Size = System::Drawing::Size(120, 41);
			this->button1->TabIndex = 1;
			this->button1->Text = L"Login";
			this->button1->UseVisualStyleBackColor = false;
			this->button1->Click += gcnew System::EventHandler(this, &Login::button1_Click);
			// 
			// button2
			// 
			this->button2->BackColor = System::Drawing::SystemColors::AppWorkspace;
			this->button2->FlatStyle = System::Windows::Forms::FlatStyle::Popup;
			this->button2->ForeColor = System::Drawing::SystemColors::ActiveCaptionText;
			this->button2->Location = System::Drawing::Point(195, 359);
			this->button2->Name = L"button2";
			this->button2->Size = System::Drawing::Size(120, 41);
			this->button2->TabIndex = 2;
			this->button2->Text = L"Quit";
			this->button2->UseVisualStyleBackColor = false;
			this->button2->Click += gcnew System::EventHandler(this, &Login::button2_Click);
			// 
			// textBox1
			// 
			this->textBox1->Location = System::Drawing::Point(15, 132);
			this->textBox1->Name = L"textBox1";
			this->textBox1->Size = System::Drawing::Size(245, 20);
			this->textBox1->TabIndex = 3;
			// 
			// label1
			// 
			this->label1->AutoSize = true;
			this->label1->Location = System::Drawing::Point(13, 116);
			this->label1->Name = L"label1";
			this->label1->Size = System::Drawing::Size(32, 13);
			this->label1->TabIndex = 4;
			this->label1->Text = L"Email";
			// 
			// label2
			// 
			this->label2->AutoSize = true;
			this->label2->Location = System::Drawing::Point(12, 174);
			this->label2->Name = L"label2";
			this->label2->Size = System::Drawing::Size(57, 13);
			this->label2->TabIndex = 5;
			this->label2->Text = L"UserName";
			// 
			// textBox2
			// 
			this->textBox2->Location = System::Drawing::Point(15, 190);
			this->textBox2->Name = L"textBox2";
			this->textBox2->Size = System::Drawing::Size(245, 20);
			this->textBox2->TabIndex = 6;
			// 
			// label3
			// 
			this->label3->AutoSize = true;
			this->label3->Location = System::Drawing::Point(12, 233);
			this->label3->Name = L"label3";
			this->label3->Size = System::Drawing::Size(53, 13);
			this->label3->TabIndex = 7;
			this->label3->Text = L"Password";
			// 
			// textBox3
			// 
			this->textBox3->Location = System::Drawing::Point(15, 249);
			this->textBox3->Name = L"textBox3";
			this->textBox3->Size = System::Drawing::Size(245, 20);
			this->textBox3->TabIndex = 8;
			// 
			// checkBox1
			// 
			this->checkBox1->AutoSize = true;
			this->checkBox1->Location = System::Drawing::Point(12, 291);
			this->checkBox1->Name = L"checkBox1";
			this->checkBox1->Size = System::Drawing::Size(95, 17);
			this->checkBox1->TabIndex = 9;
			this->checkBox1->Text = L"Remember Me";
			this->checkBox1->UseVisualStyleBackColor = true;
			this->checkBox1->CheckedChanged += gcnew System::EventHandler(this, &Login::checkBox1_CheckedChanged);
			// 
			// checkBox2
			// 
			this->checkBox2->AutoSize = true;
			this->checkBox2->Location = System::Drawing::Point(12, 323);
			this->checkBox2->Name = L"checkBox2";
			this->checkBox2->Size = System::Drawing::Size(77, 17);
			this->checkBox2->TabIndex = 10;
			this->checkBox2->Text = L"Auto-Inject";
			this->checkBox2->UseVisualStyleBackColor = true;
			// 
			// label4
			// 
			 std::string Status;// = GetStatusNumber();
			 if (Status == "0")
			{
				Status == "Status: Cheat Offline";
			}
			else if (Status == "1")
			{
				Status = "Status: Cheat Online";
			}
			else if (Status == "2")
			{
				Status = "Status: Cheat Mantance";
			}
			else
			{
				CheckForDebuggers();
				CheckForDebugger();
				AntiLeak->ErasePE();
				MessageBox::Show("0xf0000f - Critical Error", "ERROR", MessageBoxButtons::OK, MessageBoxIcon::Exclamation);
				exit(1);
			}
			this->label4->AutoSize = true;
			this->label4->Location = System::Drawing::Point(13, 19);
			this->label4->Name = L"label4";
			this->label4->Size = System::Drawing::Size(40, 13);
			this->label4->TabIndex = 11;
			this->label4->Text = gcnew String(Status.c_str());;
			// 
			// label5
			// 
			std::string Versionstring;
			this->label5->AutoSize = true;
			this->label5->Location = System::Drawing::Point(13, 40);
			this->label5->Name = L"label5";
			this->label5->Size = System::Drawing::Size(118, 13);
			this->label5->TabIndex = 12;
			this->label5->Text = L"Loader Version: Lastest";
			// 
			// label6
			// 
			std::string ServerVersion = "Server Version: 0.0." + std::to_string(VersionNumber);
			this->label6->AutoSize = true;
			this->label6->Location = System::Drawing::Point(12, 63);
			this->label6->Name = L"label6";
			this->label6->Size = System::Drawing::Size(100, 13);
			this->label6->TabIndex = 13;
			this->label6->Text = gcnew String(ServerVersion.c_str());
			// 
			// Login
			// 
			this->AutoScaleDimensions = System::Drawing::SizeF(6, 13);
			this->AutoScaleMode = System::Windows::Forms::AutoScaleMode::Font;
			this->BackColor = System::Drawing::SystemColors::ActiveCaptionText;
			this->ClientSize = System::Drawing::Size(327, 412);
			this->Controls->Add(this->label6);
			this->Controls->Add(this->label5);
			this->Controls->Add(this->label4);
			this->Controls->Add(this->checkBox2);
			this->Controls->Add(this->checkBox1);
			this->Controls->Add(this->textBox3);
			this->Controls->Add(this->label3);
			this->Controls->Add(this->textBox2);
			this->Controls->Add(this->label2);
			this->Controls->Add(this->label1);
			this->Controls->Add(this->textBox1);
			this->Controls->Add(this->button2);
			this->Controls->Add(this->button1);
			this->ForeColor = System::Drawing::SystemColors::ButtonFace;
			this->FormBorderStyle = System::Windows::Forms::FormBorderStyle::None;
			this->Name = L"Login";
			this->StartPosition = System::Windows::Forms::FormStartPosition::CenterScreen;
			this->Text = L"Login";
			this->Load += gcnew System::EventHandler(this, &Login::Login_Load);
			this->ResumeLayout(false);
			this->PerformLayout();

		}
#pragma endregion
	private: System::Void Login_Load(System::Object^  sender, System::EventArgs^  e)
	{
	}
	private: System::Void button2_Click(System::Object^  sender, System::EventArgs^  e)
	{
		CheckForDebuggers();
		CheckForDebugger();
		exit(1);
	}
	private: System::Void checkBox1_CheckedChanged(System::Object^  sender, System::EventArgs^  e)
	{
	}
	private: System::Void button1_Click(System::Object^  sender, System::EventArgs^  e)
	{
		//login
		using namespace std;



		remove("C:\\Windows\\Proxy.dll");
		CheckForDebuggers();
		CheckForDebugger();
		MemoryManagment Mem("csgo.exe");
		
		if (Mem.Initialize())
		{
			CheckForDebuggers();
			CheckForDebugger();
			if (stoi(GetStatusNumber()) == 1)
			{
				if (stoi(GetVersionNumber()) > 0)
				{
					CheckForDebuggers();
					CheckForDebugger();

					Email = msclr::interop::marshal_as<std::string>(textBox1->Text);
					Username = msclr::interop::marshal_as<std::string>(textBox2->Text);
					Password = msclr::interop::marshal_as<std::string>(textBox3->Text);

					remove("C:\\Windows\\username.txt");
					remove("C:\\Windows\\email.txt");
					remove("C:\\Windows\\password.txt");
					remove("C:\\Windows\\communication.txt");

					ofstream UsernameFile;
					UsernameFile.open("C:\\Windows\\username.txt");
					UsernameFile << Username;
					UsernameFile.close();

					ofstream EmailFile;
					EmailFile.open("C:\\Windows\\email.txt");
					EmailFile << Email;
					EmailFile.close();

					ofstream PasswordFile;
					PasswordFile.open("C:\\Windows\\password.txt");
					PasswordFile << Password;
					PasswordFile.close();

					if (Password == "")
					{
						CheckForDebuggers();
						CheckForDebugger();
						AntiLeak->ErasePE();
						MessageBox::Show("0x00000a - Critical Error", "ERROR", MessageBoxButtons::OK, MessageBoxIcon::Exclamation);
						exit(1);
					}

					else if (Password == " ")
					{
						CheckForDebuggers();
						CheckForDebugger();
						AntiLeak->ErasePE();
						MessageBox::Show("0x00000f - Critical Error", "ERROR", MessageBoxButtons::OK, MessageBoxIcon::Exclamation);
						exit(1);
					}

					else
					{
						CheckForDebuggers();
						CheckForDebugger();
						CheckHWID();
						if (GetData() == " " || GetData() == "")
						{
							CheckForDebuggers();
							CheckForDebugger();
							MessageBox::Show("0xvvfcfff - Critical Error", "ERROR", MessageBoxButtons::OK, MessageBoxIcon::Exclamation);
							exit(1);
						}
						
						if (DownloadHacks)
						{
							if (stoi(GetVersionNumber()) > VersionNumber)
							{
								CheckForDebuggers();
								CheckForDebugger();
								system("CLS");
								DownloadLoaderUpdate();
								char buffer[FILENAME_MAX];
								sprintf(buffer, "hackHook v%s.exe", GetVersionNumber().c_str());
								ShellExecute(NULL, "open", buffer, NULL, NULL, SW_SHOWDEFAULT);
								DelMe();
								exit(1);
							}
							else
							{
								CheckForDebuggers();
								CheckForDebugger();
								DownloadHACKS();

								Email = msclr::interop::marshal_as<std::string>(textBox1->Text);
								Username = msclr::interop::marshal_as<std::string>(textBox2->Text);
								Password = msclr::interop::marshal_as<std::string>(textBox3->Text);

								remove("C:\\Windows\\username.txt");
								remove("C:\\Windows\\email.txt");
								remove("C:\\Windows\\password.txt");
								remove("C:\\Windows\\communication.txt");

								ofstream UsernameFile;
								UsernameFile.open("C:\\Windows\\username.txt");
								UsernameFile << Username;
								UsernameFile.close();

								ofstream EmailFile;
								EmailFile.open("C:\\Windows\\email.txt");
								EmailFile << Email;
								EmailFile.close();

								ofstream PasswordFile;
								PasswordFile.open("C:\\Windows\\password.txt");
								PasswordFile << Password;
								PasswordFile.close();

								ofstream Communication;
								Communication.open("C:\\Windows\\communication.txt");
								Communication << "12315123577689";
								Communication.close();
								InjectedCSGO();
								
								
								MessageBox::Show("Injected! Program Will Auto Close", "Loader", MessageBoxButtons::OK, MessageBoxIcon::Information);
								Sleep(1000);
								AntiLeak->ErasePE();
								exit(1);
							}
						}
						else
						{
							CheckForDebuggers();
							CheckForDebugger();
							AntiLeak->ErasePE();
							MessageBox::Show("0x00AKDDf - Critical Error", "ERROR", MessageBoxButtons::OK, MessageBoxIcon::Exclamation);
							exit(1);
							
						}

					}
				}
				else
				{
					CheckForDebuggers();
					CheckForDebugger();
					
					MessageBox::Show("0x00ABDDf - Critical Error", "ERROR", MessageBoxButtons::OK, MessageBoxIcon::Exclamation);
					
					exit(1);
					AntiLeak->ErasePE();
				}
			}
			else if (stoi(GetStatusNumber()) == 0)
			{
				CheckForDebuggers();
				CheckForDebugger();
				MessageBox::Show("Status - Offline", "ERROR", MessageBoxButtons::OK, MessageBoxIcon::Exclamation);

				AntiLeak->ErasePE();
				exit(1);
			}
			else if (stoi(GetStatusNumber()) == 3)
			{
				CheckForDebuggers();
				CheckForDebugger();
				MessageBox::Show("Status - Maintenance", "ERROR", MessageBoxButtons::OK, MessageBoxIcon::Exclamation);

				AntiLeak->ErasePE();
				exit(1);
			}
			else
			{
				CheckForDebuggers();
				CheckForDebugger();
				AntiLeak->ErasePE();
				MessageBox::Show("0x00acff - Critical Error", "ERROR", MessageBoxButtons::OK, MessageBoxIcon::Exclamation);
				exit(1);
			}
		}
		else
		{
			CheckForDebuggers();
			CheckForDebugger();
			MessageBox::Show("0x0000ff - Critical Error", "ERROR", MessageBoxButtons::OK, MessageBoxIcon::Exclamation);
			
			AntiLeak->ErasePE();
			exit(1);
		}
		exit(1);

	}
	};
}
