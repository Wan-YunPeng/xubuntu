"""
Copyright 2016 iscas 
author: @dy
"""

import angr
import simuvex
import logging
import sys
import os
import time
import argparse
import array
from simuvex.s_cache import global_cache

l = logging.getLogger("find_newpath")

class PathFinder(object):
    """
    find newpath
    """
    queue_index = 0             #  index of created queue file
    def __init__(self, exe_file, bitmap_file, static_file, output_queuedir, args, size_restrict = None, lm = 'FULL', skip_libs = [], nop_funcs = [], check_libs = [], opexpr = False, bp = None):
        self.exec_file = exe_file
        self.bitmap_file = bitmap_file
        self.static_file = static_file
        self.output_queuedir = output_queuedir
        self.args = args
        self.size_restrict = size_restrict
        self.bp = bp
        self.queue_prefix = 'id:'        #  prefix of queue name   
        self.path_queued = {}            #  path which newinput has been generated
        self.path_unqueued = {}          #  path which constraints unsat
        # self.loop_mode = 'FULL'        #  'FULL': solve the same newpath everytime
        self.loop_mode = lm              #  'LOG':  solve the same newpath at log time .ie. 1,2,4,8,16...
        self.skip_libs = skip_libs
        self.nop_funcs = nop_funcs
        self.check_libs = check_libs
        self.exclude_addrs = []
        self.opexpr = opexpr
        self.mult_conspath = False
# 'ld-linux.so.2', 'libfontconfig.so.1', 'libfreetype.so.6'

    def is_path_queued(self, key):
        return self.path_queued.has_key(key)


    def should_check_unqueued(self, key):
        if self.path_unqueued.has_key(key):
            return (self.path_unqueued[key] & (self.path_unqueued[key] - 1)) == 0
        else:
            return True


    def conc_step_func(self, pg):
        self.mult_conspath = False
        if len(pg.active) > 1:
            self.mult_conspath = True
            l.warning("there are two or more path in concrete run at 0x%x, drop it" % pg.active[1].addr)
        pg.drop(filter_func = lambda p: pg.active.index(p) > 0)

        # sys.stdout.write("cur_add:0x%x\n" % pg.active[0].addr)

        # if global_pathdone & 0x7f == 0:
        #     sys.stdout.write("\rBasic blocks have executed: %d current loc: 0x%x\r" % (global_pathdone, pg.active[0].addr))
        #     sys.stdout.flush()
        return pg


    def generate_queuename(self, srcaddr, dstaddr, index, queue_index):
        queue_name = self.queue_prefix + "%06u,0x%x->0x%x:%06d" % (queue_index, (srcaddr & 0xffffffff), (dstaddr & 0xffffffff),index)
        return queue_name


    def execute_one_file(self, input_file):
        """
        :param input_file:       
        """
        starttime = time.clock()
        l.debug("input: %s nopfunc %s skiplibs:%s" % (input_file, repr(self.nop_funcs), repr(self.skip_libs)))

        # init
        self.path_unqueued.clear()
        global_cache.clear()

        load_options = {}
        load_options['skip_libs'] = self.skip_libs

        p = angr.Project(self.exec_file, load_options = load_options)

        for nopf in self.nop_funcs:
            l.debug("hook %x with nop" % int(nopf, 16))
            p.hook(int(nopf, 16), simuvex.SimProcedures['stubs']['Nop'])

        for k in p.loader.shared_objects.keys():
            if k not in self.check_libs and k != os.path.basename(self.exec_file):
                self.exclude_addrs.append((p.loader.shared_objects[k].get_min_addr(),p.loader.shared_objects[k].get_max_addr()))

        global_cache.set_exclude_addrs(self.exclude_addrs)
                    
        # import IPython
        # IPython.embed()
        args = [input_file if x == "@@" else x for x in self.args]


        if self.opexpr:
            add_options_c = {simuvex.s_options.CACHE_OP_EXPR,simuvex.s_options.CONCRETE_RUN}
            add_options_s = {simuvex.s_options.CACHE_OP_EXPR,simuvex.s_options.SYMBOLIC_RUN}
        else:
            add_options_c = {simuvex.s_options.CONCRETE_RUN}
            add_options_s = {simuvex.s_options.SYMBOLIC_RUN}

        if self.size_restrict == 0 or self.size_restrict == 1:
            add_options_c.update({simuvex.s_options.CACHE_WRITE_ADDRESS,simuvex.s_options.CACHE_READ_ADDRESS})
            add_options_s.update({simuvex.s_options.CACHE_WRITE_ADDRESS,simuvex.s_options.CACHE_READ_ADDRESS})
            add_options_c.add(simuvex.s_options.CACHE_SIMPROCEDURE_PARMS)
            add_options_s.add(simuvex.s_options.CACHE_SIMPROCEDURE_PARMS)


        # if not self.size_restrict is None:
        # add_options_c.add(simuvex.s_options.CACHE_SIMPROCEDURE_PARMS)
        # add_options_s.add(simuvex.s_options.CACHE_SIMPROCEDURE_PARMS)

        # init concrete running
        init_state = p.factory.entry_state(concrete_fs = True, args = args, add_options = add_options_c, remove_options={simuvex.s_options.LAZY_SOLVES})
        pg = p.factory.path_group(init_state)

        # init symbolic running
        init_state_s = p.factory.entry_state(args = args, add_options = add_options_s)
        # constraint file content
        try:
            with open(input_file, "rb") as fp:
                inputbytes = fp.read()
        except IOError: # if the file doesn't exist return error
            l.error("open queue %s failed" % input_file)
            return
        # symbyte = []
        # for i in xrange(len(inputbytes)):
        #     symbyte.append(init_state_s.se.BVS("queue_%d" % i,8))
            # import ipdb
            # ipdb.set_trace()
            # init_state_s.add_constraints(symbyte[-1] == inputbytes[i])
        # symbytes = init_state_s.se.Concat(*symbyte)
        # backing = simuvex.SimSymbolicMemory(memory_id = "file_%s" % input_file)
        # backing.set_state(init_state_s)
        # backing.store(0, symbytes)

        # constraint file length
        if self.size_restrict == 0:
            inputsize = os.path.getsize(input_file)
            sym_inputfile = simuvex.SimFile(input_file, 'rw', size = inputsize)
        else:
            sym_inputfile = simuvex.SimFile(input_file, 'rw')
        sym_inputfile.set_state(init_state_s)
        fs = {
            input_file: sym_inputfile
        }
        init_state_s.posix.fs = fs
        path0 = p.factory.path(init_state_s)

        # set breakpoint for debug
        if self.bp:
            import ipdb
            init_state.inspect.b('instruction',when=simuvex.BP_BEFORE, instruction = self.bp, action = 'ipdb')
            init_state_s.inspect.b('instruction',when=simuvex.BP_BEFORE, instruction = self.bp, action = 'ipdb')

        # init bitmap
        try:
            with open(self.bitmap_file, "r") as fp:
                bitmap = fp.read()
        except IOError: # if the file doesn't exist return error
            l.error("open bitmap file failed")
            sys.exit(1)
        l.debug("bitmap length: %d" % len(filter(lambda x: True if ord(x) != 0xff else False, bitmap)))

        try:
            with open(self.static_file, "r") as fp:
                staticmap = fp.read()
        except IOError: # if the file doesn't exist return error
            l.info("static_map doesn't exsit, use general mode")
            staticmap = array.array('c',[chr(0xff) for x in range(65536)])
        l.debug("staticmap length: %d" % len(filter(lambda x: True if ord(x) == 0xff else False, staticmap)))

        # start explore
        index = 0 
        while True:
            index += 1
            global_cache.switch_enable(True)

            # concrete run
            pg.step(n=1, step_func=self.conc_step_func)
            if len(pg.active) == 0:
                if len(pg.errored) > 0:
                    l.warning("path ended with an error " + repr(pg.errored[0].error))
                break
            target = pg.active[0].addr
            nextpaths = path0.step()
            l.debug("index: %d size: %d path0: %x" % (index,len(nextpaths),path0.addr))
            if(len(nextpaths) < 1):
                l.error("symbolic execution has none path!")
                return

            # symbolic run
            found = None
            for np in nextpaths:
                l.debug("nextpath: %x target: %x" % (np.addr, target))

                matched = self.checkpath_withtrace(np.addr, target)
                matchstatic = self.checkpath_withbitmap(path0.addr, np.addr, staticmap)
                # no match count
                
                checkall = False
                if matched:
                    found = np
                    l.debug("path %x has matched" % np.addr)

                    nmc = 0
                    if matchstatic is None and not global_cache.is_addr_in_exclude(np.addr):
                        nmc += 1
                    else:
                        nmc = 0
                    if nmc > 5:
                        l.info('Trace out of staticmap, abort!')
                        return
                    if self.mult_conspath == True and self.size_restrict is None:
                        checkall = True
                if (not matched or checkall) and matchstatic is not None:
                    pathkey = self.checkpath_withbitmap(path0.addr, np.addr, bitmap)
                    if not pathkey is None:
                        
                        if global_cache.is_addr_in_exclude(np.addr):
                            l.debug("path %x out of check range" % np.addr)
                        else:
                            l.info("new path %x has found" % np.addr)
                            # retrieve the input symbolic file
                            infiles = [v for k, v in np.state.posix.files.items() if v.name == input_file] #and v.closed == False]
                            if len(infiles) > 1:
                                openinfiles = filter(lambda x: x.closed == False, infiles)
                                if len(openinfiles) == 1:
                                    infiles  = openinfiles
                                else:
                                    l.warning("There are %d inputfiles found, It must be one!" % len(infiles))
                                    infiles = infiles[-1:]

                            if len(infiles) != 1:
                                l.error("There are %d inputfiles found, It must be one!" % len(infiles))
                                
                            # solve constrants and generate input
                            elif not self.is_path_queued(pathkey):
                                if self.loop_mode == 'FULL' or (self.loop_mode == 'LOG' and self.should_check_unqueued(pathkey)):  
                                    def try_generate():
                                        try:
                                            # np.state.se.remove_constraints(len(inputbytes))
                                            # import ipdb
                                            # ipdb.set_trace()
                                            input = np.state.se.any_str(infiles[0].all_bytes())
                                            l.info("new input has generated")
                                            l.debug("input is: " + input)
                                        except Exception as e:
                                            l.debug("path is unsat. reason is: " + repr(e))
                                            if self.path_unqueued.has_key(pathkey):
                                                self.path_unqueued[pathkey] += 1
                                            else:
                                                self.path_unqueued[pathkey] = 1
                                            return
                                        try:
                                            queue_index = 0
                                            for _, _, files in os.walk(self.output_queuedir):
                                                for file in files:
                                                    if file[0:3] == 'id:':
                                                        queue_index += 1
                                            queue_name = self.generate_queuename(path0.addr, np.addr, index, queue_index)
                                            with open(os.path.join(self.output_queuedir, queue_name), "wb") as fp:
                                                fp.write(input)
                                                self.path_queued[pathkey] = None
                                        except IOError:
                                            l.error("create queue %s failed!" % queue_name)
                                            return
                                    try_generate()
                                    pass
                                else:
                                    self.path_unqueued[pathkey] += 1

                            else:
                                l.debug("path %x has generated queue" % np.addr)
                    else:
                        l.debug("path %x has tested by afl" % np.addr)

            if found is None:
                l.error("symbolic execution can't find same path as concretely run!")
                for x in nextpaths:
                    if x.errored:
                        l.error("path ended with an error " + repr(x.error))
                return
            else:
                path0 = found

        l.info("The path length: %d with input %s" % (index, input_file))
        l.info("execution time: %f" % (time.clock() - starttime))


    def checkpath_withtrace(self, pathaddr, target):
        return pathaddr == target


    def checkpath_withbitmap(self, srcaddr, dstaddr, bitmap):
        # calculate tuple hash as same as afl
        prev = ((srcaddr >> 4) ^ (srcaddr << 8)) & 0xffff
        cur = ((dstaddr >> 4) ^ (dstaddr << 8)) & 0xffff
        loc = (prev >> 1) ^ cur
        l.debug("cur: %x prev: %x bitmap[%x] = %x" % (cur, (prev>>1),loc, ord(bitmap[loc])))
        return loc if ord(bitmap[loc]) == 0xff else None


def main(argv):
    l.setLevel(logging.DEBUG)

    l.info("test findnewpath start:")

    # l1 = logging.getLogger("simuvex.s_cache")
    # l1.setLevel(logging.DEBUG)

    parser = argparse.ArgumentParser()

    parser.add_argument("binargs",
                        help = "test binary command, use '' to enclose")
    parser.add_argument("inputfile",
                        help = "inputfile")
    parser.add_argument("bitmap",
                        help = "afl bitmap")
    parser.add_argument("outputdir",
                        help = "output dir")
    parser.add_argument("-s", "--size", type = int,
                        help = "size to change")
    parser.add_argument("-b", "--bp",
                        help = "breakpoint")
    parser.add_argument("-l", "--log", action = 'store_true',
                        help = "loop_mode")
    parser.add_argument("-f", "--nopfuncs", dest = "nopfuncs",
                        help = "skip functions (Default: [])!", default = "")
    parser.add_argument("-k", "--skiplibs", dest = "skiplibs",
                        help = "skip libraries (Default: [])!", default = "")
    parser.add_argument("-c", "--checklibs", dest = "checklibs",
                        help = "try to generate newinput when execute in libraries (Default: [])!", default = "")
    parser.add_argument("-p", "--opexpr", dest = "opexpr", action="store_true",
                        help = "use op_expr cache in exclude_libs (Default: false)!", default = False)
    parser.add_argument("-m", "--map", dest = "map",
                        help = "staticmap!", default = '')
 
    args = parser.parse_args(argv[1:])

    binargs = filter(None, args.binargs.strip('"').strip("'").split(" "))
    exefile = binargs[0]
    if not os.path.isdir(args.outputdir):
        l.error("%s dir is not exsit" % args.outputdir)
        sys.exit(1)
    rargs = [args.inputfile if x == "@@" else x for x in binargs]

    if args.bp:
        args.bp = int(args.bp, 16)

    if args.log:
        loop_mode = 'LOG'
    else:
        loop_mode = 'FULL'

    if args.nopfuncs:
        args.nopfuncs = filter(None, args.nopfuncs.strip('"').strip("'").split(","))
    if args.skiplibs:
        args.skiplibs = filter(None, args.skiplibs.strip('"').strip("'").split(","))
    if args.checklibs:
        args.checklibs = filter(None, args.checklibs.strip('"').strip("'").split(","))

    pf = PathFinder(exefile, args.bitmap, args.map, args.outputdir, rargs, args.size, loop_mode, args.skiplibs, args.nopfuncs, args.checklibs, args.opexpr, args.bp)
    pf.execute_one_file(args.inputfile)

if __name__ == "__main__":
    main(sys.argv)
