    .text
    .global test_dummy
    .align 0x1000   /* Align to 4KiB */
test_dummy:
    mov $0, %eax    /* Return 0 */
    retq
    .space 0x1000   /* Fill remaining page with NOPs */

