OUTPUT_FORMAT(elf64-x86-64)

PHDRS
{
	tcs PT_LOAD;
	unmeasured PT_LOAD;
	text PT_LOAD;
	data PT_LOAD;
}

SECTIONS
{
	. = 0;
        __enclave_start = .;
	.tcs : {
		*(.tcs*)
	} : tcs

	. = ALIGN(4096);
	.text : {
		*(.text*)
		*(.rodata*)
		FILL(0xDEADBEEF);
		. = ALIGN(4096);
	} : text

	.data : {
		*(.data*)
		*(.bss*)
	    . = ALIGN(4096);
	} : data

	. = ALIGN(4096);
	.unmeasured : {
		*(.unmeasured*)
		. = ALIGN(4096);
	} : unmeasured

	/DISCARD/ : {
		*(.comment*)
		*(.note*)
		*(.debug*)
		*(.eh_frame*)
	}
        __enclave_end = .;
}

ASSERT(!DEFINED(.altinstructions), "ALTERNATIVES are not supported in enclaves")
ASSERT(!DEFINED(.altinstr_replacement), "ALTERNATIVES are not supported in enclaves")
ASSERT(!DEFINED(.discard.retpoline_safe), "RETPOLINE ALTERNATIVES are not supported in enclaves")
ASSERT(!DEFINED(.discard.nospec), "RETPOLINE ALTERNATIVES are not supported in enclaves")
ASSERT(!DEFINED(.got.plt), "Libcalls are not supported in enclaves")
