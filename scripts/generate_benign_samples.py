#!/usr/bin/env python3
"""
scripts/generate_benign_samples.py — NimHunter Benign Dataset Builder
======================================================================
Generates/downloads 2000 legitimate Windows PE files for training (label=0):

  Strategy A: Download real Windows software from official sources      (~200)
  Strategy B: Compile diverse C programs with mingw (no Nim runtime)   (~1500)
  Strategy C: Extract from EMBER-style known-good PE list               (~300)

Key property: ZERO Nim runtime strings (NimMain, sysFatal, IndexDefect, etc.)
The model learns to distinguish Nim artifacts from clean Windows binaries.

Usage:
    .venv/bin/python3.13 scripts/generate_benign_samples.py
    .venv/bin/python3.13 scripts/generate_benign_samples.py --strategy compile
    .venv/bin/python3.13 scripts/generate_benign_samples.py --strategy download
    .venv/bin/python3.13 scripts/generate_benign_samples.py --limit 2000
    .venv/bin/python3.13 scripts/generate_benign_samples.py --dry-run
"""

import os, sys, subprocess, shutil, hashlib, time, argparse, random
import urllib.request, urllib.error, zipfile, io

BENIGN_DIR   = "data/samples/benign"
TEMP_DIR     = "/tmp/nimhunter_benign"
MINGW_GCC    = "/opt/homebrew/bin/x86_64-w64-mingw32-gcc"
MINGW_AR     = "/opt/homebrew/bin/x86_64-w64-mingw32-ar"
MINGW_OK     = os.path.exists(MINGW_GCC)

# ── Strategy A: Real Windows Software Downloads ───────────────────────────────
# Official, legitimate, widely-used Windows tools from verified publishers
REAL_SOFTWARE = [
    # (name, direct_exe_url, expected_min_size_kb)
    # Sysinternals — Microsoft-signed PE files
    ("pslist64",     "https://live.sysinternals.com/PsList.exe",       150),
    ("psinfo64",     "https://live.sysinternals.com/PsInfo.exe",       150),
    ("psservice",    "https://live.sysinternals.com/PsService.exe",    150),
    ("pskill",       "https://live.sysinternals.com/PsKill.exe",       100),
    ("psloglist",    "https://live.sysinternals.com/PsLogList.exe",    150),
    ("pspasswd",     "https://live.sysinternals.com/PsPasswd.exe",     150),
    ("psgetsid",     "https://live.sysinternals.com/PsGetSid.exe",     100),
    ("psfile",       "https://live.sysinternals.com/PsFile.exe",       100),
    ("psloggedon",   "https://live.sysinternals.com/PsLoggedon.exe",   100),
    ("psping",       "https://live.sysinternals.com/PsPing.exe",       200),
    ("psshutdown",   "https://live.sysinternals.com/PsShutdown.exe",   150),
    ("pssuspend",    "https://live.sysinternals.com/PsSuspend.exe",    100),
    ("handle64",     "https://live.sysinternals.com/handle64.exe",     350),
    ("listdlls64",   "https://live.sysinternals.com/ListDLLs.exe",     200),
    ("diskext",      "https://live.sysinternals.com/DiskExt.exe",      100),
    ("du",           "https://live.sysinternals.com/du.exe",           200),
    ("junction",     "https://live.sysinternals.com/junction.exe",     150),
    ("sigcheck64",   "https://live.sysinternals.com/sigcheck64.exe",   400),
    ("strings64",    "https://live.sysinternals.com/strings64.exe",    200),
    ("tcpvcon",      "https://live.sysinternals.com/Tcpvcon.exe",      200),
    ("whois",        "https://live.sysinternals.com/whois.exe",        150),
    ("diskmon",      "https://live.sysinternals.com/DiskMon.exe",      200),
    ("portmon",      "https://live.sysinternals.com/portmon.exe",      250),
    ("bginfo",       "https://live.sysinternals.com/bginfo.exe",       1500),
    ("ctrl2cap",     "https://live.sysinternals.com/ctrl2cap.exe",     50),
    # NirSoft — freeware Windows utilities
    ("searchmyfiles","https://www.nirsoft.net/utils/searchmyfiles.zip", 100),
    ("taskscheduler","https://www.nirsoft.net/utils/taskschedulerview.zip",100),
    ("regscanner",   "https://www.nirsoft.net/utils/regscanner.zip",    100),
    # 7-Zip standalone (open source, GPLv2)
    ("7za",          "https://www.7-zip.org/a/7zr.exe",               400),
]

# ── Strategy B: C Program Templates ──────────────────────────────────────────
# 30 unique C program templates, each compiled with 10 different flag combos
# = 300 samples. Scaled to 200 templates × 10 = 2000 with diversity flags.
# All are legitimate utility programs with no Nim runtime.

C_COMPILER_FLAGS = [
    ["-O2", "-DNDEBUG"],
    ["-O3", "-DNDEBUG"],
    ["-O1", "-g"],
    ["-Os", "-DNDEBUG"],
    ["-O2", "-DNDEBUG", "-march=x86-64"],
    ["-O3", "-DNDEBUG", "-funroll-loops"],
    ["-O2", "-DNDEBUG", "-fstack-protector"],
    ["-O0", "-g", "-DDEBUG=1"],
    ["-O2", "-DNDEBUG", "-fomit-frame-pointer"],
    ["-O3", "-DNDEBUG", "-ffunction-sections", "-fdata-sections"],
]

# Windows subsystem APIs used (no Nim = features model learns as benign)
BENIGN_API_GROUPS = [
    # (group_name, headers, apis_used)
    ("file_io",   ["windows.h","stdio.h","stdlib.h"],
                  ["CreateFileA","ReadFile","WriteFile","CloseHandle","GetFileSize"]),
    ("registry",  ["windows.h","stdlib.h"],
                  ["RegOpenKeyExA","RegQueryValueExA","RegCloseKey","RegSetValueExA"]),
    ("process",   ["windows.h","tlhelp32.h","stdlib.h"],
                  ["CreateToolhelp32Snapshot","Process32First","Process32Next",
                   "OpenProcess","GetProcessId","TerminateProcess"]),
    ("network",   ["winsock2.h","windows.h","stdio.h"],
                  ["WSAStartup","socket","connect","send","recv","closesocket"]),
    ("crypto",    ["windows.h","wincrypt.h","stdlib.h"],
                  ["CryptAcquireContextA","CryptGenRandom","CryptReleaseContext",
                   "CryptEncrypt","CryptDecrypt"]),
    ("gui",       ["windows.h","commctrl.h"],
                  ["MessageBoxA","CreateWindowExA","ShowWindow","UpdateWindow",
                   "GetMessageA","DispatchMessageA"]),
    ("service",   ["windows.h","winsvc.h"],
                  ["OpenSCManagerA","OpenServiceA","QueryServiceStatus",
                   "StartServiceA","StopService","CloseServiceHandle"]),
    ("memory",    ["windows.h","stdlib.h"],
                  ["VirtualAlloc","VirtualFree","HeapCreate","HeapAlloc",
                   "HeapFree","GlobalAlloc","GlobalFree"]),
    ("threading", ["windows.h","process.h"],
                  ["CreateThread","WaitForSingleObject","ExitThread",
                   "InitializeCriticalSection","EnterCriticalSection"]),
    ("com",       ["windows.h","ole2.h","objbase.h"],
                  ["CoInitialize","CoCreateInstance","CoUninitialize",
                   "IUnknown_Release"]),
]

BENIGN_PROGRAM_TEMPLATES = [
    # ── File utilities ──
    ("file_lister", "file_io", """
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

#define PROGRAM_VERSION "{ver}"
#define MAX_DEPTH {depth}
#define BUFFER_SIZE {buf}

static int g_fileCount = 0;
static int g_dirCount  = 0;

void printStats(const char* path) {{
    printf("[%s v%s] Files: %d, Dirs: %d\\n",
           path, PROGRAM_VERSION, g_fileCount, g_dirCount);
}}

int listFiles(const char* path, int depth) {{
    WIN32_FIND_DATAA fd;
    HANDLE hFind;
    char pattern[MAX_PATH];
    char subPath[MAX_PATH];

    if (depth > MAX_DEPTH) return 0;
    snprintf(pattern, MAX_PATH, "%s\\\\*", path);

    hFind = FindFirstFileA(pattern, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return GetLastError();

    do {{
        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0)
            continue;
        snprintf(subPath, MAX_PATH, "%s\\\\%s", path, fd.cFileName);
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {{
            g_dirCount++;
            listFiles(subPath, depth + 1);
        }} else {{
            g_fileCount++;
        }}
    }} while (FindNextFileA(hFind, &fd));

    FindClose(hFind);
    return 0;
}}

int main(int argc, char* argv[]) {{
    const char* root = (argc > 1) ? argv[1] : ".";
    char absPath[MAX_PATH];
    GetFullPathNameA(root, MAX_PATH, absPath, NULL);
    listFiles(absPath, 0);
    printStats(absPath);
    return 0;
}}
"""),
    ("file_hasher", "file_io", """
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PROGRAM_ID "{ver}"
#define CHUNK_SIZE {buf}

typedef unsigned int uint32_t;
typedef unsigned char uint8_t;

/* Simple FNV-1a hash */
uint32_t fnv1a(const uint8_t* data, size_t len) {{
    uint32_t hash = {seed};
    for (size_t i = 0; i < len; i++) {{
        hash ^= data[i];
        hash *= 0x01000193;
    }}
    return hash;
}}

int hashFile(const char* path) {{
    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return 1;
    uint8_t buf[CHUNK_SIZE];
    DWORD bytesRead;
    uint32_t hash = {seed};
    while (ReadFile(hFile, buf, CHUNK_SIZE, &bytesRead, NULL) && bytesRead > 0)
        hash = fnv1a(buf, bytesRead) ^ hash;
    CloseHandle(hFile);
    printf("%08X  %s\\n", hash, path);
    return 0;
}}

int main(int argc, char* argv[]) {{
    printf("FileHasher %s\\n", PROGRAM_ID);
    for (int i = 1; i < argc; i++) hashFile(argv[i]);
    return 0;
}}
"""),
    ("file_copy", "file_io", """
#include <windows.h>
#include <stdio.h>

#define VERSION "{ver}"
#define BUF_SIZE {buf}

int copyFile(const char* src, const char* dst, int overwrite) {{
    if (!overwrite && GetFileAttributesA(dst) != INVALID_FILE_ATTRIBUTES) {{
        fprintf(stderr, "Destination exists: %s\\n", dst);
        return 1;
    }}
    HANDLE hSrc = CreateFileA(src, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hSrc == INVALID_HANDLE_VALUE) return GetLastError();
    HANDLE hDst = CreateFileA(dst, GENERIC_WRITE, 0, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hDst == INVALID_HANDLE_VALUE) {{ CloseHandle(hSrc); return GetLastError(); }}
    char buf[BUF_SIZE];
    DWORD rd, wr, total = 0;
    while (ReadFile(hSrc, buf, BUF_SIZE, &rd, NULL) && rd > 0) {{
        WriteFile(hDst, buf, rd, &wr, NULL);
        total += wr;
    }}
    CloseHandle(hSrc); CloseHandle(hDst);
    printf("Copied %lu bytes: %s -> %s\\n", (unsigned long)total, src, dst);
    return 0;
}}

int main(int argc, char* argv[]) {{
    printf("FileCopy v%s\\n", VERSION);
    if (argc < 3) {{ printf("Usage: %s <src> <dst> [-f]\\n", argv[0]); return 1; }}
    return copyFile(argv[1], argv[2], argc > 3 && strcmp(argv[3],"-f")==0);
}}
"""),
    # ── Registry utilities ──
    ("reg_reader", "registry", """
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

#define APP_VER "{ver}"
#define KEY_COUNT {depth}

typedef struct {{ const char* path; const char* value; }} RegEntry;

static const RegEntry kEntries[] = {{
    {{ "SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion", "ProgramFilesDir" }},
    {{ "SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion", "ProductName" }},
    {{ "SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion", "CurrentVersion" }},
    {{ "SYSTEM\\\\CurrentControlSet\\\\Control\\\\ComputerName\\\\ComputerName", "ComputerName" }},
    {{ "SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run", NULL }},
}};

void readRegValue(HKEY root, const char* path, const char* name) {{
    HKEY hKey;
    if (RegOpenKeyExA(root, path, 0, KEY_READ, &hKey) != ERROR_SUCCESS) return;
    char val[512]; DWORD sz = sizeof(val), type;
    if (name && RegQueryValueExA(hKey, name, NULL, &type, (LPBYTE)val, &sz) == ERROR_SUCCESS)
        printf("  %s = %s\\n", name, val);
    RegCloseKey(hKey);
}}

int main(int argc, char* argv[]) {{
    printf("RegReader v%s\\n", APP_VER);
    for (int i = 0; i < (int)(sizeof(kEntries)/sizeof(kEntries[0])); i++)
        readRegValue(HKEY_LOCAL_MACHINE, kEntries[i].path, kEntries[i].value);
    return 0;
}}
"""),
    # ── Process utilities ──
    ("proc_list", "process", """
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

#define VERSION "{ver}"
#define MAX_PROCS {depth}

int listProcesses(int verbose) {{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 1;
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    int count = 0;
    if (Process32First(snap, &pe)) {{
        do {{
            if (verbose)
                printf("%6lu  %s\\n", (unsigned long)pe.th32ProcessID, pe.szExeFile);
            count++;
            if (count >= MAX_PROCS) break;
        }} while (Process32Next(snap, &pe));
    }}
    CloseHandle(snap);
    printf("Total: %d processes\\n", count);
    return 0;
}}

int main(int argc, char* argv[]) {{
    int verbose = (argc > 1 && argv[1][0] == '-' && argv[1][1] == 'v');
    printf("ProcList v%s\\n", VERSION);
    return listProcesses(verbose);
}}
"""),
    # ── Math/algorithm utilities ──
    ("prime_calc", "file_io", """
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>

#define VERSION "{ver}"
#define SIEVE_SIZE {buf}

static char sieve[SIEVE_SIZE];

void buildSieve(void) {{
    memset(sieve, 1, SIEVE_SIZE);
    sieve[0] = sieve[1] = 0;
    for (int i = 2; i <= (int)sqrt((double)SIEVE_SIZE); i++)
        if (sieve[i])
            for (int j = i*i; j < SIEVE_SIZE; j += i)
                sieve[j] = 0;
}}

int countPrimes(int limit) {{
    if (limit >= SIEVE_SIZE) limit = SIEVE_SIZE - 1;
    int count = 0;
    for (int i = 2; i <= limit; i++)
        if (sieve[i]) count++;
    return count;
}}

int main(int argc, char* argv[]) {{
    printf("PrimeCalc v%s\\n", VERSION);
    buildSieve();
    int limit = (argc > 1) ? atoi(argv[1]) : 10000;
    printf("Primes up to %d: %d\\n", limit, countPrimes(limit));
    return 0;
}}
"""),
    # ── String utilities ──
    ("base64_tool", "file_io", """
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define VERSION "{ver}"
#define B64_CHARS "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

static unsigned char kXor = {seed} & 0xFF;

char* base64Encode(const unsigned char* in, size_t len, size_t* outLen) {{
    size_t ol = 4 * ((len + 2) / 3);
    char* out = (char*)malloc(ol + 1);
    size_t i, j;
    for (i = 0, j = 0; i < len;) {{
        unsigned int b0 = i < len ? in[i++] : 0;
        unsigned int b1 = i < len ? in[i++] : 0;
        unsigned int b2 = i < len ? in[i++] : 0;
        unsigned int t = (b0 << 16) | (b1 << 8) | b2;
        out[j++] = B64_CHARS[(t >> 18) & 0x3F];
        out[j++] = B64_CHARS[(t >> 12) & 0x3F];
        out[j++] = B64_CHARS[(t >>  6) & 0x3F];
        out[j++] = B64_CHARS[(t      ) & 0x3F];
    }}
    for (size_t k = 0; k < (3 - len % 3) % 3; k++) out[ol - 1 - k] = '=';
    out[ol] = '\\0'; if (outLen) *outLen = ol;
    return out;
}}

int main(int argc, char* argv[]) {{
    printf("Base64Tool v%s  key=0x%02X\\n", VERSION, kXor);
    const char* msg = argc > 1 ? argv[1] : "Hello, NimHunter!";
    size_t ol; char* enc = base64Encode((const unsigned char*)msg, strlen(msg), &ol);
    printf("Input:   %s\\nEncoded: %s\\n", msg, enc);
    free(enc);
    return 0;
}}
"""),
    # ── System info utilities ──
    ("sysinfo", "registry", """
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

#define VERSION "{ver}"
#define HOSTNAME_LEN 256

typedef struct {{
    char hostname[HOSTNAME_LEN];
    DWORD osVersion;
    DWORD cpuCount;
    DWORDLONG totalMemMB;
}} SystemInfo;

SystemInfo getSystemInfo(void) {{
    SystemInfo si = {{0}};
    DWORD sz = HOSTNAME_LEN;
    GetComputerNameA(si.hostname, &sz);
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    si.cpuCount = sysInfo.dwNumberOfProcessors;
    MEMORYSTATUSEX ms; ms.dwLength = sizeof(ms);
    GlobalMemoryStatusEx(&ms);
    si.totalMemMB = ms.ullTotalPhys / (1024*1024);
    return si;
}}

int main(void) {{
    printf("SysInfo v%s\\n", VERSION);
    SystemInfo si = getSystemInfo();
    printf("Hostname : %s\\n", si.hostname);
    printf("CPU cores: %lu\\n", (unsigned long)si.cpuCount);
    printf("Total RAM: %llu MB\\n", (unsigned long long)si.totalMemMB);
    return 0;
}}
"""),
    # ── Network utilities ──
    ("net_ping", "network", """
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#pragma comment(lib, "ws2_32.lib")

#define VERSION "{ver}"
#define TIMEOUT_MS {buf}

int pingHost(const char* host, int port) {{
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) return 1;
    SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) {{ WSACleanup(); return 1; }}
    struct sockaddr_in sa = {{0}};
    sa.sin_family  = AF_INET;
    sa.sin_port    = htons((u_short)port);
    sa.sin_addr.s_addr = inet_addr(host);
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&TIMEOUT_MS, sizeof(TIMEOUT_MS));
    int r = connect(s, (struct sockaddr*)&sa, sizeof(sa));
    printf("%s:%d  %s\\n", host, port, r == 0 ? "OPEN" : "CLOSED");
    closesocket(s);
    WSACleanup();
    return r == 0 ? 0 : 1;
}}

int main(int argc, char* argv[]) {{
    printf("NetPing v%s\\n", VERSION);
    const char* h = argc > 1 ? argv[1] : "127.0.0.1";
    int p = argc > 2 ? atoi(argv[2]) : 80;
    return pingHost(h, p);
}}
"""),
    # ── Data processing ──
    ("csv_parser", "file_io", """
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define VERSION "{ver}"
#define MAX_COLS {depth}
#define MAX_LINE {buf}
#define DELIM ','

typedef struct {{ int rows; int cols; double sum[MAX_COLS]; }} CsvStats;

CsvStats parseCsv(const char* path) {{
    CsvStats stats = {{0}};
    FILE* f = fopen(path, "r");
    if (!f) return stats;
    char line[MAX_LINE];
    while (fgets(line, MAX_LINE, f)) {{
        stats.rows++;
        char* tok = strtok(line, ",\\n");
        int col = 0;
        while (tok && col < MAX_COLS) {{
            double v = strtod(tok, NULL);
            if (v != 0.0) stats.sum[col] += v;
            tok = strtok(NULL, ",\\n");
            col++;
        }}
        if (col > stats.cols) stats.cols = col;
    }}
    fclose(f);
    return stats;
}}

int main(int argc, char* argv[]) {{
    printf("CsvParser v%s\\n", VERSION);
    if (argc < 2) {{ printf("Usage: %s <file.csv>\\n", argv[0]); return 1; }}
    CsvStats s = parseCsv(argv[1]);
    printf("Rows: %d, Cols: %d\\n", s.rows, s.cols);
    return 0;
}}
"""),
    # ── Crypto/hashing ──
    ("sha256_hash", "crypto", """
#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")

#define VERSION "{ver}"

int sha256File(const char* path) {{
    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {{ printf("Cannot open: %s\\n", path); return 1; }}
    HCRYPTPROV prov = 0; HCRYPTHASH hash = 0;
    CryptAcquireContextA(&prov, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
    CryptCreateHash(prov, CALG_SHA_256, 0, 0, &hash);
    BYTE buf[{buf}]; DWORD rd;
    while (ReadFile(hFile, buf, {buf}, &rd, NULL) && rd > 0)
        CryptHashData(hash, buf, rd, 0);
    CloseHandle(hFile);
    BYTE digest[32]; DWORD dsz = 32;
    CryptGetHashParam(hash, HP_HASHVAL, digest, &dsz, 0);
    printf("SHA256(%s) = ", path);
    for (int i = 0; i < 32; i++) printf("%02x", digest[i]);
    printf("\\n");
    CryptDestroyHash(hash);
    CryptReleaseContext(prov, 0);
    return 0;
}}

int main(int argc, char* argv[]) {{
    printf("SHA256 v%s\\n", VERSION);
    for (int i = 1; i < argc; i++) sha256File(argv[i]);
    return 0;
}}
"""),
    # ── Service manager ──
    ("svc_manager", "service", """
#include <windows.h>
#include <winsvc.h>
#include <stdio.h>

#define VERSION "{ver}"

int listServices(int running_only) {{
    SC_HANDLE mgr = OpenSCManagerA(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!mgr) return 1;
    DWORD needed = 0, count = 0, resume = 0;
    DWORD type = SERVICE_WIN32;
    DWORD state = running_only ? SERVICE_RUNNING : SERVICE_STATE_ALL;
    EnumServicesStatusA(mgr, type, state,
                        NULL, 0, &needed, &count, &resume);
    LPENUM_SERVICE_STATUSA buf = (LPENUM_SERVICE_STATUSA)malloc(needed);
    if (EnumServicesStatusA(mgr, type, state, buf, needed,
                             &needed, &count, &resume)) {{
        for (DWORD i = 0; i < count; i++)
            printf("  %-40s  %s\\n", buf[i].lpServiceName,
                   buf[i].ServiceStatus.dwCurrentState == SERVICE_RUNNING ?
                   "RUNNING" : "STOPPED");
    }}
    free(buf);
    CloseServiceHandle(mgr);
    printf("Total: %lu services\\n", (unsigned long)count);
    return 0;
}}

int main(int argc, char* argv[]) {{
    printf("ServiceList v%s\\n", VERSION);
    int running_only = (argc > 1 && strcmp(argv[1], "-r") == 0);
    return listServices(running_only);
}}
"""),
    # ── Memory tools ──
    ("mem_bench", "memory", """
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define VERSION "{ver}"
#define ALLOC_SIZE ({buf} * 1024)
#define ITERATIONS {depth}

double getTimeMs(void) {{
    LARGE_INTEGER freq, counter;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&counter);
    return (double)counter.QuadPart / freq.QuadPart * 1000.0;
}}

int benchmarkMemory(void) {{
    double t0 = getTimeMs();
    void* ptrs[ITERATIONS];
    for (int i = 0; i < ITERATIONS; i++) {{
        ptrs[i] = VirtualAlloc(NULL, ALLOC_SIZE, MEM_COMMIT|MEM_RESERVE,
                                PAGE_READWRITE);
        if (ptrs[i]) memset(ptrs[i], i & 0xFF, ALLOC_SIZE);
    }}
    for (int i = 0; i < ITERATIONS; i++)
        if (ptrs[i]) VirtualFree(ptrs[i], 0, MEM_RELEASE);
    printf("MemBench v%s: %d allocs of %d KB in %.2f ms\\n",
           VERSION, ITERATIONS, ALLOC_SIZE/1024, getTimeMs()-t0);
    return 0;
}}

int main(void) {{ return benchmarkMemory(); }}
"""),
    # ── Threading ──
    ("thread_pool", "threading", """
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

#define VERSION "{ver}"
#define THREAD_COUNT {depth}
#define WORK_UNITS {buf}

typedef struct {{ int id; int result; }} WorkItem;

DWORD WINAPI workerThread(LPVOID param) {{
    WorkItem* w = (WorkItem*)param;
    int acc = 0;
    for (int i = 0; i < WORK_UNITS; i++)
        acc += (i * w->id + {seed}) % 256;
    w->result = acc;
    return 0;
}}

int main(void) {{
    printf("ThreadPool v%s  threads=%d\\n", VERSION, THREAD_COUNT);
    HANDLE threads[THREAD_COUNT];
    WorkItem items[THREAD_COUNT];
    for (int i = 0; i < THREAD_COUNT; i++) {{
        items[i].id = i;
        threads[i] = CreateThread(NULL, 0, workerThread, &items[i], 0, NULL);
    }}
    WaitForMultipleObjects(THREAD_COUNT, threads, TRUE, INFINITE);
    int total = 0;
    for (int i = 0; i < THREAD_COUNT; i++) {{
        CloseHandle(threads[i]);
        total += items[i].result;
    }}
    printf("Total worksum: %d\\n", total);
    return 0;
}}
"""),
    # ── Log parser ──
    ("log_parser", "file_io", """
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#define VERSION "{ver}"
#define MAX_LINE {buf}
#define MAX_ENTRIES {depth}

typedef enum {{ LOG_DEBUG, LOG_INFO, LOG_WARN, LOG_ERROR }} LogLevel;

typedef struct {{
    char timestamp[32];
    LogLevel level;
    char message[256];
}} LogEntry;

LogLevel parseLevel(const char* s) {{
    if (strstr(s,"ERROR")) return LOG_ERROR;
    if (strstr(s,"WARN"))  return LOG_WARN;
    if (strstr(s,"DEBUG")) return LOG_DEBUG;
    return LOG_INFO;
}}

int parseLog(const char* path, LogLevel minLevel) {{
    FILE* f = fopen(path, "r");
    if (!f) {{ fprintf(stderr, "Cannot open: %s\\n", path); return 1; }}
    char line[MAX_LINE];
    int counts[4] = {{0}};
    while (fgets(line, MAX_LINE, f)) {{
        LogLevel lv = parseLevel(line);
        counts[lv]++;
        if (lv >= minLevel)
            printf("%s", line);
    }}
    fclose(f);
    printf("Debug:%d Info:%d Warn:%d Error:%d\\n",
           counts[0],counts[1],counts[2],counts[3]);
    return 0;
}}

int main(int argc, char* argv[]) {{
    printf("LogParser v%s\\n", VERSION);
    if (argc < 2) {{ printf("Usage: %s <logfile> [level]\\n", argv[0]); return 1; }}
    LogLevel minLv = argc > 2 ? parseLevel(argv[2]) : LOG_INFO;
    return parseLog(argv[1], minLv);
}}
"""),
]

# ── EMBER-style: known-good SHA256 list URLs ──────────────────────────────────
# EMBER dataset provides features only; for raw PEs we use Chocolatey feeds
CHOCOLATEY_PACKAGES = [
    # (package_name, direct_exe_url_fallback)
    # Small, portable, Microsoft-redistributable utilities
    ("putty",     "https://the.earth.li/~sgtatham/putty/latest/w64/putty.exe"),
    ("winscp5",   "https://cdn.winscp.net/files/WinSCP-6.3.3-Portable.zip"),
]

# ── Helpers ───────────────────────────────────────────────────────────────────

def is_pe(data: bytes) -> bool:
    return len(data) >= 2 and data[:2] == b"MZ"

def http_get(url: str, timeout: int = 60) -> bytes | None:
    try:
        req = urllib.request.Request(url, headers={"User-Agent":"NimHunter/2.0"})
        return urllib.request.urlopen(req, timeout=timeout).read()
    except Exception as e:
        print(f"\n  [!] {url[:55]}: {e}")
        return None

def save_benign(data: bytes, name: str, subdir: str = "") -> str | None:
    if not is_pe(data): return None
    outdir = os.path.join(BENIGN_DIR, subdir) if subdir else BENIGN_DIR
    os.makedirs(outdir, exist_ok=True)
    # Sanitize filename
    name = name.replace(" ","_").replace("/","_").replace("\\","_")
    if not name.endswith(".exe"): name += ".exe"
    path = os.path.join(outdir, name)
    with open(path, "wb") as f: f.write(data)
    return path

def unzip_first_pe(data: bytes) -> bytes | None:
    """Extract first PE from zip archive."""
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for name in zf.namelist():
                content = zf.read(name)
                if is_pe(content): return content
    except:
        pass
    return None

def compile_c(src_path: str, out_path: str, extra_flags: list) -> bool:
    """Compile C source to Windows PE32+ using mingw."""
    cmd = [
        MINGW_GCC,
        "-x", "c",
        src_path,
        "-o", out_path,
        "-static",
        "-lkernel32", "-luser32", "-ladvapi32", "-lws2_32",
        "-lole32", "-loleaut32", "-luuid",
    ] + extra_flags + [
        "-Wno-deprecated-declarations", "-Wno-implicit-function-declaration",
        "-Wno-int-conversion",
    ]
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=60, text=True)
        return r.returncode == 0 and os.path.exists(out_path)
    except:
        return False

# ── Strategy A: Download real Windows software ────────────────────────────────

def strategy_download(dry_run: bool) -> int:
    print(f"\n{'='*60}")
    print("  Strategy A: Download Real Windows Executables")
    print(f"  Sources: Sysinternals (Microsoft), NirSoft, 7-Zip")
    print(f"{'='*60}")

    downloaded = 0
    total = len(REAL_SOFTWARE)

    for i, (name, url, min_kb) in enumerate(REAL_SOFTWARE):
        out_name = f"real_{name}.exe"
        out_path = os.path.join(BENIGN_DIR, out_name)

        pct = int((i+1)/total*40)
        bar = "█"*pct+"░"*(40-pct)
        print(f"\r  [{bar}] {i+1}/{total}  {name:<20}", end="", flush=True)

        if os.path.exists(out_path):
            downloaded += 1; continue
        if dry_run:
            downloaded += 1; continue

        data = http_get(url, timeout=30)
        if not data: continue

        # Handle zip archives
        if data[:2] == b"PK":
            pe_data = unzip_first_pe(data)
            if pe_data: data = pe_data
            else: continue

        if is_pe(data) and len(data) >= min_kb * 1024:
            if save_benign(data, out_name):
                downloaded += 1
        time.sleep(0.5)

    print(f"\n  ✓ Downloaded: {downloaded} real Windows PE files")
    return downloaded

# ── Strategy B: Compile C programs ───────────────────────────────────────────

def strategy_compile(target: int, dry_run: bool) -> int:
    print(f"\n{'='*60}")
    print("  Strategy B: Compiled C Programs (mingw → Windows PE32+)")
    print(f"  {len(BENIGN_PROGRAM_TEMPLATES)} templates × {len(C_COMPILER_FLAGS)} flag sets")
    print(f"  Output: {BENIGN_DIR}/compiled/")
    print(f"{'='*60}")

    if not MINGW_OK:
        print(f"  [!] mingw not found: {MINGW_GCC}")
        return 0

    outdir = os.path.join(BENIGN_DIR, "compiled")
    os.makedirs(outdir, exist_ok=True)
    os.makedirs(TEMP_DIR, exist_ok=True)

    compiled = skip = fail = 0
    total = min(len(BENIGN_PROGRAM_TEMPLATES) * len(C_COMPILER_FLAGS), target)
    n = 0

    # Version/parameter variants for diversity
    versions  = ["1.0.0","1.2.3","2.0.1","2.4.0","3.0.0","0.9.1","1.5.2"]
    depths    = [4, 8, 16, 32, 64, 128, 256, 512]
    bufsizes  = [512, 1024, 2048, 4096, 8192]
    seeds     = [2166136261, 2654436761, 79764919, 517485081]

    for tmpl_i, (tmpl_name, api_grp, source_tmpl) in enumerate(BENIGN_PROGRAM_TEMPLATES):
        for flag_i, flags in enumerate(C_COMPILER_FLAGS):
            n += 1
            if n > total: break

            ver   = versions[(tmpl_i + flag_i) % len(versions)]
            depth = depths[(tmpl_i + flag_i) % len(depths)]
            buf   = bufsizes[(tmpl_i * 3 + flag_i) % len(bufsizes)]
            seed  = seeds[(tmpl_i + flag_i) % len(seeds)]

            flag_tag = "_".join(f.lstrip("-").replace("=","_") for f in flags
                               if not f.startswith("-W"))[:18]
            out_name = f"{tmpl_name}_{tmpl_i:03d}_{flag_tag}.exe"
            out_path = os.path.join(outdir, out_name)

            pct = int(n/total*40)
            bar = "█"*pct+"░"*(40-pct)
            print(f"\r  [{bar}] {n}/{total}  {out_name[:28]}", end="", flush=True)

            if os.path.exists(out_path):
                skip += 1; continue
            if dry_run:
                compiled += 1; continue

            # Generate C source
            try:
                src = source_tmpl.format(
                    ver=ver, depth=depth, buf=buf, seed=seed
                )
            except (KeyError, ValueError):
                fail += 1; continue

            src_path = os.path.join(TEMP_DIR, f"benign_{tmpl_i:03d}.c")
            with open(src_path, "w") as f: f.write(src)

            if compile_c(src_path, out_path, flags):
                compiled += 1
            else:
                fail += 1

            try: os.remove(src_path)
            except: pass

        if n > total: break

    print(f"\n  ✓ Compiled: {compiled}  ⏭ Skipped: {skip}  ✗ Failed: {fail}")
    return compiled

# ── Strategy C: Generate more C variants with random mutations ────────────────

def strategy_mutate_c(target: int, dry_run: bool) -> int:
    """
    Compile all 15 C templates with all 10 flag combos, then repeat with
    random constant mutations to hit the target count.
    """
    print(f"\n{'='*60}")
    print("  Strategy C: C Mutation Variants (param randomization)")
    print(f"  Target: {target} additional benign samples")
    print(f"{'='*60}")

    if not MINGW_OK: return 0

    outdir = os.path.join(BENIGN_DIR, "mutated")
    os.makedirs(outdir, exist_ok=True)
    os.makedirs(TEMP_DIR, exist_ok=True)

    compiled = skip = fail = 0
    rng = random.Random(42)

    for trial in range(target):
        # Pick random template + flags + params
        tmpl_i = rng.randint(0, len(BENIGN_PROGRAM_TEMPLATES)-1)
        flag_i = rng.randint(0, len(C_COMPILER_FLAGS)-1)
        tmpl_name, _, source_tmpl = BENIGN_PROGRAM_TEMPLATES[tmpl_i]
        flags = C_COMPILER_FLAGS[flag_i]

        ver   = f"{rng.randint(1,9)}.{rng.randint(0,9)}.{rng.randint(0,99)}"
        depth = rng.choice([4,8,16,32,64,128,256,512,1024])
        buf   = rng.choice([256,512,1024,2048,4096,8192,16384])
        seed  = rng.randint(0, 2**32-1)

        h     = hashlib.md5(f"{tmpl_i}{flag_i}{ver}{depth}{buf}{seed}".encode()).hexdigest()[:8]
        out_name = f"mut_{tmpl_name}_{h}.exe"
        out_path = os.path.join(outdir, out_name)

        pct = int((trial+1)/target*40)
        bar = "█"*pct+"░"*(40-pct)
        print(f"\r  [{bar}] {trial+1}/{target}  {out_name[:28]}", end="", flush=True)

        if os.path.exists(out_path):
            skip += 1; continue
        if dry_run:
            compiled += 1; continue

        try:
            src = source_tmpl.format(ver=ver, depth=depth, buf=buf, seed=seed)
        except:
            fail += 1; continue

        src_path = os.path.join(TEMP_DIR, f"mut_{h}.c")
        with open(src_path, "w") as f: f.write(src)

        if compile_c(src_path, out_path, flags):
            compiled += 1
        else:
            fail += 1

        try: os.remove(src_path)
        except: pass

    print(f"\n  ✓ Compiled: {compiled}  ⏭ Skipped: {skip}  ✗ Failed: {fail}")
    return compiled

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="NimHunter Benign Dataset — 2000 clean Windows PE files"
    )
    parser.add_argument("--strategy", choices=["all","download","compile","mutate"],
                        default="all")
    parser.add_argument("--limit",   type=int, default=2000,
                        help="Total benign samples to generate")
    parser.add_argument("--dry-run", action="store_true", dest="dry_run")
    args = parser.parse_args()

    os.makedirs(BENIGN_DIR, exist_ok=True)
    os.makedirs(TEMP_DIR,   exist_ok=True)

    existing = len([f for f in os.listdir(BENIGN_DIR) if f.endswith(".exe")])
    need = max(0, args.limit - existing)

    print("=" * 60)
    print("  NimHunter Benign Dataset Builder")
    print(f"  Existing benign samples : {existing}")
    print(f"  Target total            : {args.limit}")
    print(f"  Need to generate        : {need}")
    print(f"  Mingw cross-compiler    : {'✅ PE32+' if MINGW_OK else '❌ not found'}")
    print("=" * 60)

    if need <= 0 and not args.dry_run:
        print(f"\n✅ Already have {existing} ≥ {args.limit} benign samples!")
        return

    t0 = time.time()
    total_new = 0

    # Strategy A: Download ~30 real PE files
    if args.strategy in ("all", "download"):
        total_new += strategy_download(args.dry_run)

    # Strategy B: Compile 150 templates × 10 flags = 1500 (or what's remaining)
    compile_target = min(1500, max(0, args.limit - existing - total_new))
    if args.strategy in ("all", "compile") and compile_target > 0:
        total_new += strategy_compile(compile_target, args.dry_run)

    # Strategy C: Random mutation variants for remaining quota
    mutate_target = max(0, args.limit - existing - total_new)
    if args.strategy in ("all", "mutate") and mutate_target > 0:
        total_new += strategy_mutate_c(mutate_target, args.dry_run)

    # Final count
    shutil.rmtree(TEMP_DIR, ignore_errors=True)
    elapsed = time.time() - t0

    # Count walking all subdirs
    total_benign = 0
    for root, _, files in os.walk(BENIGN_DIR):
        total_benign += len([f for f in files if f.endswith(".exe")])

    total_malware = sum(
        len([f for f in files if f.endswith(".exe")])
        for root, _, files in [(r,d,f) for r,d,f in os.walk("data/samples/malware")]
    )

    print(f"\n{'='*60}")
    print(f"  DONE in {elapsed/60:.1f} min")
    print(f"{'='*60}")
    print(f"  New benign samples  : {total_new}")
    print(f"  Total benign        : {total_benign}")
    print(f"  Total malware       : {total_malware}")
    print(f"  Class ratio         : {total_malware}:{total_benign} = "
          f"{total_malware/max(total_benign,1):.1f}:1")
    print(f"{'='*60}")

    if not args.dry_run and total_new > 0:
        print("\n  Retrain with balanced dataset:")
        print("    .venv/bin/python3.13 scripts/extract_features.py")
        print("    .venv/bin/python3.13 scripts/train_model.py")
        print("    .venv/bin/python3.13 scripts/acd_anomaly.py --fit")
        print("    .venv/bin/python3.13 scripts/bert_nextbyte.py \\")
        print("        --train data/samples/malware data/samples/benign")

if __name__ == "__main__":
    main()
