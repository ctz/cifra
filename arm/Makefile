%.stm32f0.elf:
	arm-none-eabi-gcc $(CFLAGS) -g -T linkscript.stm32f0.ld -nostartfiles -nostdlib -Wall -Werror -std=gnu99 -mthumb -mcpu=cortex-m0 -o $@ $^

%.bin: %.elf
	arm-none-eabi-objcopy -O binary $< $@
.PRECIOUS: %.bin

CFLAGS = -I../../bignum -I..
EABI = libeabi-cortex-lmul.s
test.stm32f0.elf: boot.c main.c semihost.c $(EABI) ../sha256.c ../sha512.c ../blockwise.c ../curve25519.c

run.%.stm32f0: %.stm32f0.bin
	qemu-system-gnuarmeclipse -M STM32F0-Discovery -kernel $^ -semihosting -nographic -monitor null -serial null 2> $@.log
	cat $@.log

runtests: run.test.stm32f0
.PHONY: runtests

clean:
	rm -rf *.log *.elf *.bin
