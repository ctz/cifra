FUNCS = do_nothing stack_8w stack_64w hashtest_sha256 hashtest_sha512 \
	aes128block_test aes256block_test \
	curve25519_test
TESTS = testcurve25519 testaes testsalsa20 testsha2
ARCHS = stm32f0 stm32f3 qemucm0

all: $(patsubst %,%.stm32f0.bin,$(FUNCS) $(TESTS)) \
	$(patsubst %,%.stm32f3.bin,$(FUNCS) $(TESTS)) \
	$(patsubst %,%.qemucm0.bin,$(FUNCS) $(TESTS))

%.stm32f0.elf:
	arm-none-eabi-gcc $(CFLAGS) $(LDFLAGS) -T linkscript.stm32f0.ld -mcpu=cortex-m0 -DCORTEX_M0 -o $@ $^ -DTEST=$* $(EABI_M0)

%.stm32f3.elf:
	arm-none-eabi-gcc $(CFLAGS) $(LDFLAGS) -T linkscript.stm32f3.ld -mcpu=cortex-m3 -DCORTEX_M3 -o $@ $^ -DTEST=$*

%.qemucm0.elf:
	arm-none-eabi-gcc $(CFLAGS) $(LDFLAGS) -T linkscript.qemucm0.ld -mcpu=cortex-m0 -DCORTEX_M0 -o $@ $^ -DTEST=$* $(EABI_M0)

%.bin: %.elf
	arm-none-eabi-objcopy -O binary $< $@
.PRECIOUS: %.bin

CFLAGS = -I./ext -I../../bignum -I.. -Os -ffunction-sections -g -Wall -Werror -std=gnu99 -mthumb
LDFLAGS = -nostartfiles -nostdlib -Wl,-gc-sections
EABI_M0 = libeabi-cortex-m0-lmul.s
SRCS = boot.c semihost.c semihost.s \
       ../sha256.c ../sha512.c ../blockwise.c ../chash.c \
       ../curve25519.c \
       ../aes.c ../eax.c ../modes.c ../cmac.c \
       ../hmac.c ../pbkdf2.c ../salsa20.c ../chacha20.c

$(patsubst %,%.stm32f0.elf, $(FUNCS)): $(SRCS) main.c
$(patsubst %,%.stm32f3.elf, $(FUNCS)): $(SRCS) main.c
$(patsubst %,%.qemucm0.elf, $(FUNCS)): $(SRCS) main.c

$(patsubst %,testcurve25519.%.elf, $(ARCHS)): $(SRCS) ../testcurve25519.c
$(patsubst %,testaes.%.elf, $(ARCHS)): $(SRCS) ../testaes.c
$(patsubst %,testsalsa20.%.elf, $(ARCHS)): $(SRCS) ../testsalsa20.c
$(patsubst %,testsha2.%.elf, $(ARCHS)): $(SRCS) ../testsha2.c

run.%.qemucm0: %.qemucm0.bin
	qemu-system-gnuarmeclipse -verbose -verbose -M STM32F0-Discovery -kernel $^ -semihosting -nographic -monitor null -serial null 2> $@.log
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

test.stm32f3: $(patsubst %,run.%.stm32f3,$(FUNCS) $(TESTS))
.PHONY: test.stm32f3

clean:
	rm -rf *.log *.elf *.bin
