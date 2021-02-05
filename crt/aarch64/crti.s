.section .init
.global _init
.align 2
.type _init,%function
_init:
	stp x29,x30,[sp,-16]!
	mov x29,sp

.section .fini
.global _fini
.align 2
.type _fini,%function
_fini:
	stp x29,x30,[sp,-16]!
	mov x29,sp
