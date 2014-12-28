import subprocess
import sys
import re

function_intro_re = re.compile(r'^(?P<addr>[0-9a-fA-F]{8}) <(?P<name>[a-zA-Z0-9\._]+)>:$')
insn_re = re.compile(r'^\s+(?P<addr>[0-9a-fA-F]+):\s+(?P<insn>[0-9a-fA-F ]+)\s+\t(?P<op>.*)$')

class Instruction:
    def __init__(self, addr, insn, op):
        self.addr = long(addr, 16)
        self.insn = insn

        args = op.split('\t', 1)
        
        self.op = args[0].strip()
        comment = args[1].strip().split(';', 1)

        self.args = comment[0].strip()

        if len(comment) == 2:
            self.comment = comment[1].strip()
        else:
            self.comment = ''

def literal_branch_target(t):
    return ' <' in t

class Function:
    def __init__(self, addr, name):
        self.name = name
        self.addr = long(addr, 16)
        self.insns = []
        self.calls = []

    def __repr__(self):
        return '<%s %d instructions>' % (self.name, len(self.insns))

    def add_insn(self, insn):
        self.insns.append(Instruction(**insn))

    def contains_addr(self, addr):
        if self.insns:
            return addr >= self.addr and addr <= self.insns[-1].addr
        else:
            return addr == self.addr

    def dump(self):
        print self.name + ':'
        for insn in self.insns:
            print '  ', insn.op, insn.args, '\t;', insn.comment

    def analyse(self, prog):
        self.stack_guess = 0

        for insn in self.insns:
            if insn.op == 'sub' and insn.args.startswith('sp, '):
                sz = int(insn.args.split('#', 1)[1])
                self.stack_guess = sz

            if insn.op[0] == 'b' and literal_branch_target(insn.args):
                target = long(insn.args.split(' <', 1)[0], 16)

                targetf = prog.function_at_addr(target)

                if targetf:
                    self.calls.append(targetf)

    def stack_usage(self, hints, prog, depth = 0):
        hinted_calls = []
        print '    ' * depth, 'stack:', self.name, self.stack_guess, 'bytes'

        our_hints = [h for h in hints if h and h[0] == self.name]
        if our_hints:
            hints = [h[1:] for h in our_hints]
            hinted_calls = [prog.function_by_name(h[0]) for h in hints if h]

        if self.calls + hinted_calls:
            call_usage = max([f.stack_usage(hints, prog, depth + 1) for f in self.calls + hinted_calls])
        else:
            call_usage = 0
        return self.stack_guess + call_usage

class Program:
    def __init__(self):
        self.functions = []

        # sequence of tuples naming a call sequence known to occur
        # this allows working out calls through pointers
        self.call_hints = []

    def read_elf(self, elf):
        current_fn = None

        for x in subprocess.Popen(['arm-none-eabi-objdump', '-d', elf],
                stdout = subprocess.PIPE).stdout:
            x = x.rstrip('\n')
            m = function_intro_re.match(x)
            if m:
                fn = Function(**m.groupdict())
                current_fn = fn
                self.functions.append(fn)

            m = insn_re.match(x)
            if m:
                assert current_fn
                current_fn.add_insn(m.groupdict())

    def analyse(self):
        for f in self.functions:
            f.analyse(self)

    def function_by_name(self, name):
        fns = [fn for fn in self.functions if fn.name == name]
        if len(fns) == 0:
            return None
        elif len(fns) == 1:
            return fns[0]
        else:
            print 'warn: more than one function named', name
            return None

    def function_at_addr(self, addr):
        for f in self.functions:
            if f.addr == addr:
                return f
        return None

    def add_call_hint(self, *seq):
        self.call_hints.append(seq)

    def measure_stack(self, name):
        fn = self.function_by_name(name)
        if fn is None:
            return 0

        return fn.stack_usage(self.call_hints, self)

p = Program()
p.read_elf(sys.argv[-1])

p.analyse()
p.add_call_hint('cf_sha224_update', 'cf_blockwise_accumulate', 'cf_blockwise_accumulate_final', 'sha256_update_block')
p.add_call_hint('cf_sha256_update', 'cf_blockwise_accumulate', 'cf_blockwise_accumulate_final', 'sha256_update_block')
p.add_call_hint('cf_sha384_update', 'cf_blockwise_accumulate', 'cf_blockwise_accumulate_final', 'sha512_update_block')
p.add_call_hint('cf_sha512_update', 'cf_blockwise_accumulate', 'cf_blockwise_accumulate_final', 'sha512_update_block')

print 'stack', 'hashtest_sha256', '=', p.measure_stack('hashtest_sha256')
print 'stack', 'hashtest_sha512', '=', p.measure_stack('hashtest_sha512')
print 'stack', 'stack_8w', '=', p.measure_stack('stack_8w')
print 'stack', 'stack_64w', '=', p.measure_stack('stack_64w')
