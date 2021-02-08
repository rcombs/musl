#include "syscall.h"

#ifdef SYSCALL_MAX_DYN
syscall_arg_t __syscall_max = LONG_MAX;
#endif
#ifdef SYSCALL_MAX_SEMIDYN
int __syscall_check_enabled = 0;
#endif
