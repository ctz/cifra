#include <stdint.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

#include "semihost.h"

#define OP_WRITE0 0x04
#define OP_EXIT 0x18
#define OP_EXIT_ARG_FAILURE 0x0
#define OP_EXIT_ARG_SUCCESS 0x20026

static uint32_t semihost(uint32_t op, void *ptr)
{
  uint32_t r = 0;
  asm volatile ("mov r0, %[op]\n"
                "mov r1, %[arg]\n"
                "bkpt 0xab\n"
                "mov %[ret], r0"
                : [ret] "=r" (r)
                : [op] "r" (op),
                  [arg] "r" (ptr)
                : "r0", "r1");

  return r;
}

__attribute__((noreturn))
void quit_success(void)
{
  semihost(OP_EXIT, (void *) OP_EXIT_ARG_SUCCESS);
  while (1)
    ;
}

__attribute__((noreturn))
void quit_failure(void)
{
  semihost(OP_EXIT, (void *) OP_EXIT_ARG_FAILURE);
  while (1)
    ;
}

void emit(const char *buf)
{
  semihost(OP_WRITE0, (void *) buf);
}

static void emit_extent(const char *start, const char *end)
{
  char buf[32+1];
  size_t bufmax = sizeof(buf) - 1;
  buf[32] = 0;

  size_t bytes = end - start + 1;

  while (bytes >= bufmax)
  {
    memcpy(buf, start, bufmax);
    emit(buf);
    bytes -= bufmax;
    start += bufmax;
  }
  
  if (bytes == 0)
    return;
  
  memcpy(buf, start, bytes);
  buf[bytes] = 0;
  emit(buf);
}

void emitf(const char *fmt, ...)
{
  const char *start = fmt, *end = fmt;

  va_list args;
  va_start(args, fmt);

  while (*fmt)
  {
    switch (*fmt)
    {
      case '%':
        emit_extent(start, end);

        switch (fmt[1])
        {
          case '%':
            emit("%");
            break;

          case 'u':
            emit_uint32(va_arg(args, uint32_t));
            break;

          case 's':
            emit(va_arg(args, const char *));
            break;
        }
        start = end = fmt + 2;
        break;

      default:
        end = fmt;
        break;
    }

    fmt++;
  }

  va_end(args);
  emit_extent(start, end);
}
  
void emit_hex(const void *ptr, size_t len)
{
  const char *hex_char = "0123456789abcdef";
  const uint8_t *bb = ptr;
  char byte[3];

  byte[2] = 0;

  for (size_t i = 0; i < len; i++)
  {
    byte[0] = hex_char[(bb[i] >> 4) & 0xf];
    byte[1] = hex_char[bb[i] & 0xf];
    emit(byte);
  }
}

void emit_uint32(uint32_t x)
{
  const char *hex_char = "0123456789abcdef";
  char buf[sizeof "0x11223344"];
  buf[0] = '0';
  buf[1] = 'x';
  buf[2] = hex_char[(x >> 28) & 0xf];
  buf[3] = hex_char[(x >> 24) & 0xf];
  buf[4] = hex_char[(x >> 20) & 0xf];
  buf[5] = hex_char[(x >> 16) & 0xf];
  buf[6] = hex_char[(x >> 12) & 0xf];
  buf[7] = hex_char[(x >> 8) & 0xf];
  buf[8] = hex_char[(x >> 4) & 0xf];
  buf[9] = hex_char[x & 0xf];
  buf[10] = 0;

  emit(buf);
}

typedef struct
{
  volatile uint32_t ctrl;
  volatile uint32_t reload;
  volatile uint32_t current;
} systick;

#define SysTick ((systick *)0xe000e010)

#define STCTRL_SYSCLOCK 0x04
#define STCTRL_ENABLE   0x01

#define STCTRL_MAX 0xffffff

uint32_t reset_cycles(void)
{
  SysTick->reload = STCTRL_MAX;
  SysTick->ctrl = STCTRL_SYSCLOCK | STCTRL_ENABLE;
  SysTick->current = 0;
  return get_cycles();
}

uint32_t get_cycles(void)
{
  return STCTRL_MAX - SysTick->current;
}

