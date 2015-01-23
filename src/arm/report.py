archs = 'stm32f0 stm32f3'.split()
tests = """
aes128block_test
aes256block_test
aes128sched_test
aes256sched_test
hashtest_sha256
hashtest_sha512
aes128gcm_test
aes128eax_test
do_nothing
""".split()

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
    print '    * **Cycles (key schedule)**: %d' % sched_test['cycle_count']
    print '    * **Cycles (block)**: %d' % (block_test['cycle_count'] - sched_test['cycle_count'])
    print '    * **Stack**: %dB' % block_test['stack_usage']
    print '    * **Code size**: %dB' % block_test['code_size']
    print

def print_std(result):
    print """* **Cycles**: %(cycle_count)d
* **Stack**: %(stack_usage)dB
* **Code size**: %(code_size)dB
""" % result

for arch in results.keys():
    print '##', 'AES (%s)' % arch
    print_aes('128 bit key', results[arch]['aes128block_test'], results[arch]['aes128sched_test'])
    print_aes('256 bit key', results[arch]['aes256block_test'], results[arch]['aes256sched_test'])
    
    print '## AES128-GCM (%s)' % arch
    print_std(results[arch]['aes128gcm_test'])
    
    print '## AES128-EAX (%s)' % arch
    print_std(results[arch]['aes128eax_test'])

    print '## SHA256 (%s)' % arch
    print_std(results[arch]['hashtest_sha256'])
    
    print '## SHA512 (%s)' % arch
    print_std(results[arch]['hashtest_sha512'])
