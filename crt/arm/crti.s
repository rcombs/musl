.syntax unified

.section .init
.align 2
.global _init
.type _init,%function
_init:
	push {r0,lr}

.section .fini
.align 2
.global _fini
.type _fini,%function
_fini:
	push {r0,lr}
