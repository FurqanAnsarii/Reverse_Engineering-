import sys
import os
import hashlib
import binascii
from elftools.elf.elffile import ELFFile
from capstone import *
from colorama import Fore, Style, init

# Professional UI Initialization
init(autoreset=True)

class NexusReverser:
    def __init__(self, target):
        self.target = target
        self.author = "Furqan Ansari"

    def banner(self):
        os.system('clear')
        # Style.BOLD use kiya hy yahan fix karne ke liye
        print(f"{Fore.RED}{'='*80}")
        print(f"{Style.BRIGHT}{Fore.WHITE}   DEVELOPED BY: {self.author.upper()}")
        print(f"{Style.BRIGHT}{Fore.YELLOW}   THE NEXUS - EXTREME BINARY EXPLOITATION & REVERSE ENGINE")
        print(f"{Style.BRIGHT}{Fore.RED}   STATUS:| CTF READY | PRIVATE EDITION")
        print(f"{Fore.RED}{'='*80}\n")

    def get_hashes(self):
        with open(self.target, "rb") as f:
            data = f.read()
            return hashlib.md5(data).hexdigest(), hashlib.sha256(data).hexdigest()

    def disassemble_logic(self, elf):
        """Converting Machine Code to Assembly."""
        print(f"{Fore.CYAN}[ SECTION: CODE DISASSEMBLY ]")
        code_section = elf.get_section_by_name('.text')
        if code_section:
            ops = code_section.data()
            addr = code_section['sh_addr']
            
            # Setup Capstone for x86_64
            md = Cs(CS_ARCH_X86, CS_MODE_64)
            print(f"{Fore.YELLOW}{'ADDRESS':12} | {'MNEMONIC':10} | {'OPERANDS'}")
            print("-" * 45)
            # Pehli 20 instructions dikhayega
            for i in md.disasm(ops[:100], addr):
                print(f"{Fore.WHITE}{hex(i.address):12} | {Fore.GREEN}{i.mnemonic:10} | {Fore.WHITE}{i.op_str}")
        else:
            print(f"{Fore.RED}[!] No executable .text section found.")

    def run_nexus(self):
        self.banner()
        if not os.path.exists(self.target):
            print(f"{Fore.RED}[!] Error: Target {self.target} is missing.")
            return

        try:
            md5, sha = self.get_hashes()
            print(f"{Fore.BLUE}[*] MD5: {Fore.WHITE}{md5}")
            print(f"{Fore.BLUE}[*] SHA256: {Fore.WHITE}{sha}\n")

            with open(self.target, 'rb') as f:
                elf = ELFFile(f)
                self.disassemble_logic(elf)
                
            print(f"\n{Fore.RED}{'='*80}")
            print(f"{Fore.GREEN}[✔] ANALYSIS COMPLETE BY {self.author.upper()}")
            print(f"{Fore.RED}{'='*80}")
        except Exception as e:
            print(f"{Fore.RED}[!] Error Analyzing Binary: {e}")
            print(f"{Fore.YELLOW}[Tip] Make sure you are testing on an actual Linux Binary (ELF).")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"{Fore.YELLOW}Usage: python3 l.py <binary_file>")
    else:
        engine = NexusReverser(sys.argv[1])
        engine.run_nexus()
