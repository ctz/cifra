archs = 'stm32f0 stm32f1 stm32f3'.split()
tests = """
aes128block_test
aes256block_test
aes128sched_test
aes256sched_test
hashtest_sha256
hashtest_sha512
aes128gcm_test
aes128eax_test
salsa20_test
chacha20_test
do_nothing
""".split()

arch_names = dict(
        stm32f0 = 'Cortex-M0',
        stm32f1 = 'Cortex-M3',
        stm32f3 = 'Cortex-M4F'
        )

base_test = 'do_nothing'

def extract(arch, test):
    fn = 'run.%s.%s.log' % (test, arch)

    code_size = None
    cycle_count = None
    stack_usage = None

    try:
        lines = open(fn).readlines()
    except IOError:
        return None

    for l in lines:
        if 'LOAD' in l:
            parts = l.split()
            assert len(parts) >= 8
            assert 'LOAD' == parts[0]
            if parts[6] == 'RWE':
                code_size = long(parts[5], 16)
        
        if l.startswith('cycles = '):
            cycle_count = long(l.split(' = ')[1].strip(), 16)
        
        if l.startswith('stack = '):
            stack_usage = long(l.split(' = ')[1].strip(), 16)

    return dict(
            code_size = code_size,
            cycle_count = cycle_count,
            stack_usage = stack_usage
            )

def print_table(rows):
    header, rows = rows[0], rows[1:]
    assert not [True for r in rows if len(r) != len(header)]
    widths = []
    for i, h in enumerate(header):
        widths.append(max([len(h)] + [len(r[i]) for r in rows]))

    def print_row(row):
        print ' | '.join(c + (' ' * (widths[i] - len(c))) for i, c in enumerate(row))
    
    print_row(header)
    print_row(['-' * w for w in widths])
    for r in rows:
        print_row(r)

results = {}

for arch in archs:
    for test in tests:
        inf = extract(arch, test)
        if inf:
            results.setdefault(arch, {})[test] = inf

for arch in results.keys():
    if base_test not in results[arch]:
        print 'need', base_test, 'results to report for', arch
        continue

    base_result = results[arch][base_test]

    for test in results[arch].keys():
        if test == base_test:
            continue

        results[arch][test]['code_size'] -= base_result['code_size']

def print_aes(label, block_test, sched_test):
    print '* **%s**:' % label
    print '    * **Cycles (key schedule + block)**: %d' % block_test['cycle_count']
    print '    * **Cycles (key schedule)**: %d' % sched_test['cycle_count']
    print '    * **Cycles (block)**: %d' % (block_test['cycle_count'] - sched_test['cycle_count'])
    print '    * **Stack**: %dB' % block_test['stack_usage']
    print '    * **Code size**: %dB' % block_test['code_size']
    print

def tabulate_aes(arch, block_result, sched_result, table = None):
    if table is None:
        table = []
        table.append((
            'Core',
            'Cycles (key schedule + block)',
            'Cycles (key schedule)',
            'Cycles (block)',
            'Stack',
            'Code size'
            ))

    table.append(
            (
                arch_names[arch],
                '%d' % block_result['cycle_count'],
                '%d' % sched_result['cycle_count'],
                '%d' % (block_result['cycle_count'] - sched_result['cycle_count']),
                '%dB' % block_result['stack_usage'],
                '%dB' % block_result['code_size']
            ))

    return table

def print_std(result):
    print """* **Cycles**: %(cycle_count)d
* **Stack**: %(stack_usage)dB
* **Code size**: %(code_size)dB
""" % result

def tabulate_std(arch, result, table = None):
    if table is None:
        table = []
        table.append(('Core', 'Cycles', 'Stack', 'Code size'))

    table.append(
            (
                arch_names[arch],
                '%d' % result['cycle_count'],
                '%dB' % result['stack_usage'],
                '%dB' % result['code_size']
            ))

    return table

def tabulate(mktab):
    table = None
    for arch in archs:
        if arch not in results:
            continue
        table = mktab(arch, table)
    print_table(table)

print '##', 'AES (128-bit key)'
tabulate(lambda arch, table: tabulate_aes(arch, results[arch]['aes128block_test'], results[arch]['aes128sched_test'], table))
print

print '##', 'AES (256-bit key)'
tabulate(lambda arch, table: tabulate_aes(arch, results[arch]['aes256block_test'], results[arch]['aes256sched_test'], table))
print

def do_table(title, test):
    print '##', title
    tabulate(lambda arch, table: tabulate_std(arch, results[arch][test], table))
    print

do_table('AES128-GCM', 'aes128gcm_test')
do_table('AES128-EAX', 'aes128eax_test')
do_table('ChaCha20', 'chacha20_test')
do_table('Salsa20', 'salsa20_test')
do_table('SHA256', 'hashtest_sha256')
do_table('SHA512', 'hashtest_sha512')

