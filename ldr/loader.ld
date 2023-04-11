ENTRY(_start)

SECTIONS {
    . = 0x0;
    .text :{
        *(.boot.text) *(.text*) *(.data*) *(.rodata*)
	. = ALIGN(8);
        payload = .;
    }
}
