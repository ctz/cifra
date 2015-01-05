FUNCS = do_nothing stack_8w stack_64w hashtest_sha256 hashtest_sha512 curve25519_test

all: $(patsubst %,%.stm32f0.bin,$(FUNCS)) \
	$(patsubst %,%.stm32f3.bin,$(FUNCS)) \
	$(patsubst %,%.qemucm0.bin,$(FUNCS))

%.stm32f0.elf:
	arm-none-eabi-gcc $(CFLAGS) $(LDFLAGS) -T linkscript.stm32f0.ld -mcpu=cortex-m0 -o $@ $^ -DTEST=$*

%.stm32f3.elf:
	arm-none-eabi-gcc $(CFLAGS) $(LDFLAGS) -T linkscript.stm32f3.ld -mcpu=cortex-m3 -o $@ $^ -DTEST=$*

%.qemucm0.elf:
	arm-none-eabi-gcc $(CFLAGS) $(LDFLAGS) -T linkscript.qemucm0.ld -mcpu=cortex-m0 -o $@ $^ -DTEST=$*

%.bin: %.elf
	arm-none-eabi-objcopy -O binary $< $@
.PRECIOUS: %.bin

CFLAGS = -I../../bignum -I.. -O3 -ffunction-sections -g -Wall -Werror -std=gnu99 -mthumb
LDFLAGS = -nostartfiles -nostdlib -Wl,-gc-sections
EABI_M0 = libeabi-cortex-m0-lmul.s
SRCS = boot.c main.c semihost.c semihost.s ../sha256.c ../sha512.c ../blockwise.c ../curve25519.c

$(patsubst %,%.stm32f0.elf, $(FUNCS)): $(SRCS) $(EABI_M0)
$(patsubst %,%.stm32f3.elf, $(FUNCS)): $(SRCS)
$(patsubst %,%.qemucm0.elf, $(FUNCS)): $(SRCS) $(EABI_M0)

run.%.qemucm0: %.qemucm0.bin
	qemu-system-gnuarmeclipse -verbose -verbose -M STM32F0-Discovery -kernel $^ -semihosting -nographic -monitor null -serial null 2> $@.log
	cat $@.log

runtests: $(patsubst %,run.%.qemucm0,$(FUNCS))
.PHONY: runtests

clean:
	rm -rf *.log *.elf *.bin
