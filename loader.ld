ENTRY(_start)

SECTIONS {
    . = 0x0;
    .text :{
        *(.boot.text) *(.text)
        payload_size = .;
        QUAD(0)
        key_seed = .;
        QUAD(0)
        iv_seed = .;
        QUAD(0)
        loader_end = .;
    }

    .data :{
        *(.data) *(.rodata)
    }
}
