"""
wanyunpeng
"""
import logging

l = logging.getLogger("rex.Crash")

import os
import angr
import angrop
import random
import tracer
import hashlib
import operator
from .trace_additions import ChallRespInfo, ZenPlugin
from rex.exploit import CannotExploit, CannotExplore, ExploitFactory, CGCExploitFactory
from rex.vulnerability import Vulnerability
from simuvex import SimMemoryError, s_options as so

class GenPath(object):
	def __init__(self, binary, crash=None, pov_file=None, aslr=None, constrained_addrs=None, crash_state=None,
                 prev_path=None, hooks=None, format_infos=None, rop_cache_tuple=None, use_rop=True,
                 explore_steps=0, angrop_object=None):
        '''
        :binary: path to the binary which crashed   
        binary:待检测的程序
        :crash: string of input which crashed the binary  
        crash:造成程序崩溃的输入
        :pov_file: CGC PoV describing a crash   
        pov_file:CGC PoV文件，描述一个crash
        :aslr: analyze the crash with aslr on or off   
        aslr:aslr开或关
        :constrained_addrs: list of addrs which have been constrained during exploration  
        constrained_addrs:在探索路径过程中被限制的地址
        :crash_state: an already traced crash state       
        crash_state:已经追踪过的crash状态
        :prev_path: path leading up to the crashing block      
        prev_path:到达crash块的路径
        :hooks: dictionary of simprocedure hooks, addresses to simprocedures    
        hooks:哪些地址不被执行
        :format_infos: a list of atoi FormatInfo objects that should be used when analyzing the crash  
        format_infos:aoti FormatInfo 对象，在分析crash时被使用
        :rop_cache_tuple: a angrop tuple to load from        
        rop_cache_tuple:angrop——rop gadget finder and chain builder
        :use_rop: whether or not to use rop           
        use_rop:是否使用rop
        :explore_steps: number of steps which have already been explored, should only set by exploration methods       
        explore_steps:已经被探索过的步数，只能被探索方法赋值
        :angrop_object: an angrop object, should only be set by exploration methods      
        angrop_object:angrop对象，只能被探索方法赋值
        '''

        self.binary = binary
        self.crash  = crash
        self.pov_file = pov_file
        self.constrained_addrs = [ ] if constrained_addrs is None else constrained_addrs
        self.hooks = hooks
        self.explore_steps = explore_steps

        if self.explore_steps > 10:
            raise CannotExploit("Too many steps taken during crash exploration")

        self.project = angr.Project(binary)

        # we search for ROP gadgets now to avoid the memory exhaustion bug in pypy   现在寻找rop gadget，以防内存耗尽
        # hash binary contents for rop cache name                                    binhash存放rop缓存名
        binhash = hashlib.md5(open(self.binary).read()).hexdigest()
        rop_cache_path = os.path.join("/tmp", "%s-%s-rop" % (os.path.basename(self.binary), binhash))

        if use_rop:
            if angrop_object is not None:
                self.rop = angrop_object
            else:
                self.rop = self.project.analyses.ROP()
                if rop_cache_tuple is not None:
                    l.info("loading rop gadgets from cache tuple")
                    self.rop._load_cache_tuple(rop_cache_tuple)
                elif os.path.exists(rop_cache_path):
                    l.info("loading rop gadgets from cache '%s'", rop_cache_path)
                    self.rop.load_gadgets(rop_cache_path)
                else:
                    self.rop.find_gadgets()
                    self.rop.save_gadgets(rop_cache_path)
        else:
            self.rop = None

        self.os = self.project.loader.main_bin.os

        # determine the aslr of a given os and arch
        if aslr is None:
            if self.os == "cgc": # 本例没有CGC。cgc has no ASLR, but we don't assume a stackbase
                self.aslr = False
            else: # we assume linux is going to enfore stackbased aslr
                self.aslr = True
        else:
            self.aslr = aslr
		


# coding: utf-8

#
# This file solves the problem `nobranch` from 9447 CTF 2015. It got the first blood solution!
# It takes a VERY long time to run! I took a well-deserved nap while it was solving :)
#

import angr, simuvex, claripy
p = angr.Project('nobranch')
all_blocks = []
mainaddr = 0x400400
outaddr = 0x616050

shouldbe = 'HMQhQLi6VqgeOj78AbiaqquK3noeJt'

def main():
    state = p.factory.blank_state(addr=mainaddr)                                                    # set up the initial state at the start of main
    state.memory.store(state.regs.rsp, claripy.BVV(0x4141414141414141, 64), endness='Iend_LE')      # set fake return address
    state.memory.store(state.regs.rsp + 8, state.regs.rsp + 64, endness='Iend_LE')                  # I can't remember if I even need this... better safe than sorry
    state.memory.store(state.regs.rsp + 16, claripy.BVV(0, 64), endness='Iend_LE')                  # see above

    state.memory.store(state.regs.rsp + 64, state.regs.rsp + 128, endness='Iend_LE')                # set first argv string pointer
    state.memory.store(state.regs.rsp + 72, state.regs.rsp + 129, endness='Iend_LE')                # set second argv string pointer
    state.memory.store(state.regs.rsp + 80, claripy.BVV(0, 64), endness='Iend_LE')

    state.memory.store(state.regs.rsp + 128, claripy.BVV(0, 8))                                     # set first argv string to the empty string
    flag = claripy.BVS('flag', 18*8)
    state.memory.store(state.regs.rsp + 129, flag)                                                  # set second argv string to symbolic flag!

    state.regs.rdi = 2                                                                              # set argc = 2
    state.regs.rsi = state.regs.rsp + 64                                                            # set argv = args
    state.regs.rdx = state.regs.rsp + 80                                                            # set envp = empty list

    path = p.factory.path(state)
    i = 0
    while path.jumpkind == 'Ijk_Boring':                                                            # symbolically execute until we hit the syscall at the end
        i += 1
        print i
        path.step(num_inst=1)                                                                       # only step one instruction at a time
        opath = path
        path = path.successors[0]
        reg_names = ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']

        assert not path.state.regs.rsp.symbolic

        for reg_name in reg_names:                                                                  # for each register and memory location that matters in the program,
            val = path.state.registers.load(reg_name)                                               # after each step, if the symbolic AST for that value has become larger than
            if val.symbolic and val.depth > 3:                                                      # three nodes deep, stub it out by replacing it with a single symbolic value
                newval = claripy.BVS('replacement', len(val))                                       # constrained to be equal to the original value. This makes the constraints much
                path.state.se.add(newval == val)                                                    # easier for z3 to bite into in smaller chunks. It might also indicate that there
                path.state.registers.store(reg_name, newval)                                        # some issues with angr's current usage of z3 :-)

        for mem_addr in range(outaddr, outaddr + 0x1f) + [path.state.regs.rsp - x for x in xrange(0x40)]:
            val = path.state.memory.load(mem_addr, 1)
            if val.symbolic and val.depth > 3:
                newval = claripy.BVS('replacement', len(val))
                path.state.se.add(newval == val)
                path.state.memory.store(mem_addr, newval)

    fstate = path.state.copy()
    fstate.se._solver.timeout = 0xfffffff                                                           # turn off z3's timeout for solving :^)
    for i, c in enumerate(shouldbe):
        fstate.se.add(fstate.memory.load(0x616050 + i, 1) == ord(c))                                # constrain the output to what we were told it should be

    cflag = hex(fstate.se.any_int(flag))[2:-1].decode('hex')                                        # solve for the flag!
    return cflag

def test():
    f = main()
    assert f.startswith('9447{') and f.endswith('}')
    # lol I don't have the flag onhand and I don't want to wait hours for it to re-solve :P
    # you can verify it by running ./nobranch `cat flag`
    # and verifying that it prints out the shouldbe value at the top

if __name__ == '__main__':
    print main()		
		
