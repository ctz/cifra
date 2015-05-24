FUNCS = do_nothing stack_8w stack_64w \
	hashtest_sha256 hashtest_sha512 \
	hashtest_sha3_256 hashtest_sha3_512 \
	aes128block_test aes128sched_test \
	aes256block_test aes256sched_test \
	aes128gcm_test aes128eax_test \
	aes128ccm_test \
	salsa20_test chacha20_test \
	poly1305_test hmacsha256_test \
	curve25519_test \
	norx_test
TESTS = testcurve25519 testaes testmodes testsalsa20 testsha1 testsha2 \
	testsha3 testpoly1305 testnorx
ARCHS = stm32f0 stm32f1 stm32f3 qemucm0

all: $(patsubst %,%.stm32f0.bin,$(FUNCS) $(TESTS)) \
	$(patsubst %,%.stm32f1.bin,$(FUNCS) $(TESTS)) \
	$(patsubst %,%.stm32f3.bin,$(FUNCS) $(TESTS)) \
	$(patsubst %,%.qemucm0.bin,$(FUNCS) $(TESTS))

%.stm32f0.elf:
	arm-none-eabi-gcc $(CFLAGS) $(CFLAGS_$*) $(LDFLAGS) -T linkscript.stm32f0.ld -mcpu=cortex-m0 -DCORTEX_M0 -o $@ $^ -DTEST=$* -lgcc

%.stm32f1.elf:
	arm-none-eabi-gcc $(CFLAGS) $(CFLAGS_$*) $(LDFLAGS) -T linkscript.stm32f1.ld -mcpu=cortex-m3 -DCORTEX_M3 -o $@ $^ -DTEST=$* -lgcc

%.stm32f3.elf:
	arm-none-eabi-gcc $(CFLAGS) $(CFLAGS_$*) $(LDFLAGS) -T linkscript.stm32f3.ld -mcpu=cortex-m4 -DCORTEX_M4 -o $@ $^ -DTEST=$* -lgcc

%.qemucm0.elf:
	arm-none-eabi-gcc $(CFLAGS) $(CFLAGS_$*) $(LDFLAGS) -T linkscript.qemucm0.ld -mcpu=cortex-m0 -DCORTEX_M0 -o $@ $^ -DTEST=$* -lgcc

%.bin: %.elf
	arm-none-eabi-objcopy -O binary $< $@
.PRECIOUS: %.bin

AES_OPTIONS = -DCF_AES_ENCRYPT_ONLY=1 -DCF_SIDE_CHANNEL_PROTECTION=0
AES128_OPTIONS = -DCF_AES_MAXROUNDS=AES128_ROUNDS
AES256_OPTIONS = -DCF_AES_MAXROUNDS=AES256_ROUNDS

CFLAGS_aes128block_test = $(AES_OPTIONS) $(AES128_OPTIONS)
CFLAGS_aes128sched_test = $(AES_OPTIONS) $(AES128_OPTIONS)
CFLAGS_aes128gcm_test = $(AES_OPTIONS) $(AES128_OPTIONS)
CFLAGS_aes128eax_test = $(AES_OPTIONS) $(AES128_OPTIONS)
CFLAGS_aes128ccm_test = $(AES_OPTIONS) $(AES128_OPTIONS)
CFLAGS_poly1305_test = $(AES_OPTIONS) $(AES128_OPTIONS)

CFLAGS_aes256block_test = $(AES_OPTIONS) $(AES256_OPTIONS)
CFLAGS_aes256sched_test = $(AES_OPTIONS) $(AES256_OPTIONS)

CFLAGS_testaes = -DCF_SIDE_CHANNEL_PROTECTION=0

CFLAGS = -I./ext -I../ext -I.. -Os -ffunction-sections -g \
	 -Wall -Werror -std=gnu99 -mthumb
LDFLAGS = -nostartfiles -nostdlib -Wl,-gc-sections
CURVESRCS = unacl/cortex_m0_mpy121666.s unacl/cortex_m0_reduce25519.s unacl/mul.s unacl/sqr.s
SRCS = boot.c memcpy.s memset.s semihost.c semihost.s \
       ../sha1.c ../sha256.c ../sha512.c ../sha3.c ../blockwise.c ../chash.c \
       ../curve25519.c ../poly1305.c \
       ../aes.c ../eax.c ../gcm.c ../cbcmac.c ../ccm.c \
       ../modes.c ../cmac.c ../gf128.c \
       ../hmac.c ../pbkdf2.c ../salsa20.c ../chacha20.c \
       ../norx.c

$(patsubst %,%.stm32f0.elf, $(FUNCS)): $(SRCS) main.c $(CURVESRCS)
$(patsubst %,%.stm32f1.elf, $(FUNCS)): $(SRCS) main.c $(CURVESRCS)
$(patsubst %,%.stm32f3.elf, $(FUNCS)): $(SRCS) main.c $(CURVESRCS)
$(patsubst %,%.qemucm0.elf, $(FUNCS)): $(SRCS) main.c

$(patsubst %,testcurve25519.%.elf, $(ARCHS)): $(SRCS) $(CURVESRCS) ../testcurve25519.c
$(patsubst %,testaes.%.elf, $(ARCHS)): $(SRCS) ../testaes.c
$(patsubst %,testmodes.%.elf, $(ARCHS)): $(SRCS) ../testmodes.c
$(patsubst %,testsalsa20.%.elf, $(ARCHS)): $(SRCS) ../testsalsa20.c
$(patsubst %,testsha1.%.elf, $(ARCHS)): $(SRCS) ../testsha1.c
$(patsubst %,testsha2.%.elf, $(ARCHS)): $(SRCS) ../testsha2.c
$(patsubst %,testsha3.%.elf, $(ARCHS)): $(SRCS) ../testsha3.c
$(patsubst %,testpoly1305.%.elf, $(ARCHS)): $(SRCS) ../testpoly1305.c
$(patsubst %,testnorx.%.elf, $(ARCHS)): $(SRCS) ../testnorx.c

run.%.qemucm0: %.qemucm0.bin
	arm-none-eabi-readelf -l $(patsubst %.bin,%.elf,$^) > $@.log
	qemu-system-gnuarmeclipse -verbose -verbose -M STM32F0-Discovery -kernel $^ -semihosting -nographic -monitor null -serial null 2>> $@.log
	cat $@.log

run.%.stm32f0: %.stm32f0.elf
	arm-none-eabi-readelf -l $^ > $@.log
	echo '-----' >> $@.log
	openocd -f openocd.stm32f0.cfg >> $@.log &
	arm-none-eabi-gdb --quiet --batch-silent \
		$^ \
		-ex 'target remote :3333' \
		-ex 'monitor reset halt' \
		-ex 'load' \
		-ex 'monitor arm semihosting enable' \
		-ex 'monitor reset run' \
		-ex 'monitor wait_halt 240000' \
		-ex 'monitor shutdown'

run.%.stm32f1: %.stm32f1.elf
	arm-none-eabi-readelf -l $^ > $@.log
	echo '-----' >> $@.log
	openocd -f openocd.stm32f1.cfg >> $@.log &
	arm-none-eabi-gdb --quiet --batch-silent \
		$^ \
		-ex 'target remote :3333' \
		-ex 'monitor reset halt' \
		-ex 'load' \
		-ex 'monitor arm semihosting enable' \
		-ex 'monitor reset run' \
		-ex 'monitor wait_halt 240000' \
		-ex 'monitor shutdown'

run.%.stm32f3: %.stm32f3.elf
	arm-none-eabi-readelf -l $^ > $@.log
	echo '-----' >> $@.log
	openocd -f openocd.stm32f3.cfg >> $@.log &
	arm-none-eabi-gdb --quiet --batch-silent \
		$^ \
		-ex 'target remote :3333' \
		-ex 'monitor reset halt' \
		-ex 'load' \
		-ex 'monitor arm semihosting enable' \
		-ex 'monitor reset run' \
		-ex 'monitor wait_halt 240000' \
		-ex 'monitor shutdown'

test: $(patsubst %,run.%.qemucm0,$(FUNCS) $(TESTS))
.PHONY: test

test.stm32f0: $(patsubst %,run.%.stm32f0,$(FUNCS) $(TESTS))
.PHONY: test.stm32f0

test.stm32f1: $(patsubst %,run.%.stm32f1,$(FUNCS) $(TESTS))
.PHONY: test.stm32f1

test.stm32f3: $(patsubst %,run.%.stm32f3,$(FUNCS) $(TESTS))
.PHONY: test.stm32f3

clean:
	rm -rf *.log *.elf *.bin
