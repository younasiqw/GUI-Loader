#include "Login1.h"
#include <Windows.h>
using namespace System;
using namespace System::Windows::Forms;



[STAThreadAttribute]
int main(array < String^ > ^ args)
{
	FreeConsole();
	Application::EnableVisualStyles();
	Application::SetCompatibleTextRenderingDefault(false);
	LoaderUI::Login form;
	Application::Run(%form);
	return 0;
}
