#define SYSCALL_NO_TLS 1

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <features.h>
#include <libgen.h>
#include <sys/mman.h>
#include <string.h>
#include <unistd.h>
#include "atomic.h"
#include "dynlink.h"
#include "syscall.h"

extern weak hidden const size_t _DYNAMIC[];

int main();
weak void _init();
weak void _fini();
weak _Noreturn int __libc_start_main(int (*)(), int, char **,
	void (*)(), void(*)(), void(*)());

#define START "_start"
#define _dlstart_c _start_c
#define DL_DNI
#include "../ldso/dlstart.c"

#ifndef PAGESIZE
#ifdef PAGE_SIZE
#undef PAGE_SIZE // We don't want to use libc.page_size here
#endif
static size_t page_size;
#define PAGE_SIZE page_size
#endif

#ifdef SYS_mmap2
#define crt_mmap(start, len, prot, flags, fd, off) (void*)__syscall(SYS_mmap2, start, len, prot, flags, fd, off/SYSCALL_MMAP2_UNIT)
#else
#define crt_mmap(start, len, prot, flags, fd, off) (void*)__syscall(SYS_mmap, start, len, prot, flags, fd, off)
#endif

#define crt_munmap(ptr, len) __syscall(SYS_munmap, ptr, len)

static inline int crt_mprotect(void *addr, size_t len, int prot)
{
	size_t start, end;
	start = (size_t)addr & -PAGE_SIZE;
	end = (size_t)((char *)addr + len + PAGE_SIZE-1) & -PAGE_SIZE;
	return __syscall(SYS_mprotect, start, end-start, prot);
}

#define crt_read(fd, buf, size) __syscall(SYS_read, fd, buf, size)
#define crt_pread(fd, buf, size, ofs) __syscall(SYS_pread, fd, buf, size, __SYSCALL_LL_PRW(ofs))
#define crt_write(fd, buf, size) __syscall(SYS_write, fd, buf, size)

#define map_failed(val) ((unsigned long)val > -4096UL)

#ifdef SYS_readlink
#define crt_readlink(path, buf, bufsize) __syscall(SYS_readlink, path, buf, bufsize)
#else
#define crt_readlink(path, buf, bufsize) __syscall(SYS_readlinkat, AT_FDCWD, path, buf, bufsize)
#endif

#ifdef SYS_access
#define crt_access(filename, amode) __syscall(SYS_access, filename, amode)
#else
#define crt_access(filename, amode) __syscall(SYS_faccessat, AT_FDCWD, filename, amode, 0)
#endif

__attribute__((__visibility__("default")))
void _dl_debug_state(void) {}

static void *crt_memcpy(void *restrict dest, const void *restrict src, size_t n)
{
	unsigned char *d = dest;
	const unsigned char *s = src;
	for (; n; n--) *d++ = *s++;
	return dest;
}

static void *crt_memset(void *dest, int c, size_t n)
{
	unsigned char *s = dest;
	for (; n; n--, s++) *s = c;
	return dest;
}

static size_t crt_strlen(const char *s)
{
	const char *a = s;
	for (; *s; s++);
	return s-a;
}

static char *crt_strchrnul(const char *s, int c)
{
	c = (unsigned char)c;
	if (!c) return (char *)s + crt_strlen(s);
	for (; *s && *(unsigned char *)s != c; s++);
	return (char *)s;
}

static int crt_strncmp(const char *_l, const char *_r, size_t n)
{
	const unsigned char *l=(void *)_l, *r=(void *)_r;
	if (!n--) return 0;
	for (; *l && *r && n && *l == *r ; l++, r++, n--);
	return *l - *r;
}

static char *crt_getenv(const char *name, char **environ)
{
	size_t l = crt_strchrnul(name, '=') - name;
	if (l && !name[l] && environ)
		for (char **e = environ; *e; e++)
			if (!crt_strncmp(name, *e, l) && l[*e] == '=')
				return *e + l+1;
	return 0;
}

static inline void *map_library(int fd)
{
	size_t addr_min=SIZE_MAX, addr_max=0;
	size_t this_min, this_max;
	off_t off_start = 0;
	Ehdr eh;
	Phdr *ph, *ph0;
	unsigned prot = 0;
	unsigned char *map=MAP_FAILED;
	size_t i;

	ssize_t l = crt_read(fd, &eh, sizeof eh);
	if (l<0) goto error;
	if (l<sizeof eh || (eh.e_type != ET_DYN && eh.e_type != ET_EXEC))
		goto error;
	for (i = 0; i < eh.e_phnum; i++, ph=(void *)((char *)ph+eh.e_phentsize)) {
		Phdr phbuf;
		ph = &phbuf;
		l = crt_pread(fd, ph, sizeof *ph, eh.e_phoff + eh.e_phentsize * i);
		if (l < sizeof *ph) goto error;
		if (ph->p_type != PT_LOAD) continue;
		if (ph->p_vaddr < addr_min) {
			addr_min = ph->p_vaddr;
			off_start = ph->p_offset;
			prot = (((ph->p_flags&PF_R) ? PROT_READ : 0) |
				((ph->p_flags&PF_W) ? PROT_WRITE: 0) |
				((ph->p_flags&PF_X) ? PROT_EXEC : 0));
		}
		if (ph->p_vaddr + ph->p_memsz > addr_max) {
			addr_max = ph->p_vaddr + ph->p_memsz;
		}
	}

	/* We rely on the header being mapped as readable later */
	if (addr_min != 0 || off_start != 0 || addr_max == 0 || !(prot & PROT_READ))
		goto error;

	addr_max += PAGE_SIZE-1;
	addr_max &= -PAGE_SIZE;

	/* The first time, we map too much, possibly even more than
	 * the length of the file. This is okay because we will not
	 * use the invalid part; we just need to reserve the right
	 * amount of virtual address space to map over later. */
	map = crt_mmap(0, addr_max, prot, MAP_PRIVATE, fd, off_start);
	if (map_failed(map)) goto error;

	ph0 = (void*)(map + eh.e_phoff);

	for (ph=ph0, i=eh.e_phnum; i; i--, ph=(void *)((char *)ph+eh.e_phentsize)) {
		if (ph->p_type != PT_LOAD) continue;
		this_min = ph->p_vaddr & -PAGE_SIZE;
		this_max = ph->p_vaddr+ph->p_memsz+PAGE_SIZE-1 & -PAGE_SIZE;
		off_start = ph->p_offset & -PAGE_SIZE;
		prot = (((ph->p_flags&PF_R) ? PROT_READ : 0) |
			((ph->p_flags&PF_W) ? PROT_WRITE: 0) |
			((ph->p_flags&PF_X) ? PROT_EXEC : 0));
		/* Reuse the existing mapping for the lowest-address LOAD */
		if ((ph->p_vaddr & -PAGE_SIZE) != addr_min)
			if (map_failed(crt_mmap(map+this_min, this_max-this_min, prot, MAP_PRIVATE|MAP_FIXED, fd, off_start)))
				goto error;
		if (ph->p_memsz > ph->p_filesz && (ph->p_flags&PF_W)) {
			size_t brk = (size_t)map+ph->p_vaddr+ph->p_filesz;
			size_t pgbrk = brk+PAGE_SIZE-1 & -PAGE_SIZE;
			crt_memset((void *)brk, 0, pgbrk-brk & PAGE_SIZE-1);
			if (pgbrk-(size_t)map < this_max && map_failed(crt_mmap((void *)pgbrk, (size_t)map+this_max-pgbrk, prot, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0)))
				goto error;
		}
	}
	return map;
error:
	return 0;
}

static void decode_vec(const size_t *v, size_t *a, size_t cnt)
{
	size_t i;
	for (i=0; i<cnt; i++) a[i] = 0;
	for (; v[0]; v+=2) if (v[0]-1<cnt-1) {
		a[0] |= 1UL<<v[0];
		a[v[0]] = v[1];
	}
}

static void get_rpath(const char **runpath, const size_t *dyn, unsigned char *base)
{
	/* DT_STRTAB is pre-relocated for us by dlstart */
	const char *strings = (char*)base + dyn[DT_STRTAB];

	*runpath = NULL;

	if (dyn[0] & (1 << DT_RPATH))
		*runpath = strings + dyn[DT_RPATH];
	if (dyn[0] & (1 << DT_RUNPATH))
		*runpath = strings + dyn[DT_RUNPATH];
}

static size_t find_linker(char *outbuf, size_t bufsize, const char *this_path, size_t thisl, const size_t *dyn, unsigned char *base, char **environ, int secure)
{
	const char *paths[2]; // envpath, rpath/runpath
	size_t i;

	// In the suid/secure case, skip everything and use the fixed path
	if (secure)
		goto default_path;

	// Strip filename
	if (thisl)
		thisl--;
	while (thisl > 1 && this_path[thisl] == '/')
		thisl--;
	while (thisl > 0 && this_path[thisl] != '/')
		thisl--;

	const char *envpath = crt_getenv("LD_LOADER_PATH", environ);
	if (envpath) {
		size_t envlen = crt_strlen(envpath);
		if (envlen < bufsize) {
			crt_memcpy(outbuf, envpath, envlen + 1);
			return envlen + 1;
		}
	}

	get_rpath(&paths[1], dyn, base);

	paths[0] = crt_getenv("LD_LIBRARY_PATH", environ);

	for (i = 0; i < 2; i++) {
		const char *p = paths[i];
		char *o = outbuf;
		if (!p)
			continue;
		for (;;) {
			if (!crt_strncmp(p, "$ORIGIN", 7) ||
					!crt_strncmp(p, "${ORIGIN}", 9)) {
				if (o + thisl + 1 < outbuf + bufsize) {
					crt_memcpy(o, this_path, thisl);
					o += thisl;
				} else {
					o = outbuf + bufsize - 1;
				}
				p += (p[1] == '{' ? 9 : 7);
			} else if (*p == ':' || !*p) {
#define LDSO_FILENAME "ld-musl-" LDSO_ARCH ".so.1"
				if (o + sizeof(LDSO_FILENAME) + 1 < outbuf + bufsize) {
					*o++ = '/';
					crt_memcpy(o, LDSO_FILENAME, sizeof(LDSO_FILENAME));
					if (!crt_access(outbuf, R_OK | X_OK))
						return (o + sizeof(LDSO_FILENAME)) - outbuf;
				}
				if (!*p)
					break;
				o = outbuf;
				p++;
			} else {
				if (o < outbuf + bufsize)
					*o++ = *p;
				p++;
			}
		}
	}

	default_path:
	// Didn't find a usable loader anywhere (or in secure mode), so try the default
	crt_memcpy(outbuf, LDSO_PATHNAME, sizeof(LDSO_PATHNAME));
	return sizeof(LDSO_PATHNAME);
}

#define _ERROR(str) { if (!secure) crt_write(2, str, sizeof(str) - 1); goto error; }
#define ERROR(str) _ERROR("DCRT: " str "\n")

hidden _Noreturn void __dls2(unsigned char *base, size_t *p)
{
	int argc = p[0];
	char **argv = (void *)(p+1);
	int fd;
	int secure;
	Ehdr *loader_hdr;
	Phdr *new_hdr;
	void *entry;
	char this_path[PATH_MAX];
	size_t thisl;
	char linker_path[PATH_MAX];
	size_t linker_len;
	size_t i;
	size_t aux[AUX_CNT];
	size_t *auxv;
	size_t dyn[DYN_CNT];
	char **environ = argv + argc + 1;

	// We're already finished here; just run main.
	if (__libc_start_main)
		__libc_start_main(main, argc, argv, _init, _fini, 0);

	/* Find aux vector just past environ[] and use it to initialize
	* global data that may be needed before we can make syscalls. */
	for (i = argc + 1; argv[i]; i++);
	auxv = (void *)(argv + i + 1);
	decode_vec(auxv, aux, AUX_CNT);
	secure = ((aux[0] & 0x7800) != 0x7800 || aux[AT_UID] != aux[AT_EUID]
		|| aux[AT_GID] != aux[AT_EGID] || aux[AT_SECURE]);

#ifndef PAGESIZE
	page_size = aux[AT_PAGESZ];
#endif

	decode_vec(_DYNAMIC, dyn, DYN_CNT);

	thisl = crt_readlink("/proc/self/exe", this_path, sizeof this_path);
	linker_len = find_linker(linker_path, sizeof linker_path, this_path, thisl, dyn, base, environ, secure);

	fd = __sys_open2(, linker_path, O_RDONLY);
	if (fd < 0)
		ERROR("Failed to open ldso")

	loader_hdr = map_library(fd);
	if (!loader_hdr)
		ERROR("Failed to map ldso")

	__syscall(SYS_close, fd);

	// Copy the program headers into an anonymous mapping
	new_hdr = crt_mmap(0, (aux[AT_PHENT] * (aux[AT_PHNUM] + 2) + linker_len + PAGE_SIZE - 1) & -PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (map_failed(new_hdr))
		ERROR("Failed to map new phdrs")

	// Point it back at the original kernel-provided base
	new_hdr->p_type = PT_PHDR;
	new_hdr->p_vaddr = (size_t)new_hdr - (size_t)base;

	((Phdr*)((char*)new_hdr + aux[AT_PHENT]))->p_type = PT_INTERP;
	((Phdr*)((char*)new_hdr + aux[AT_PHENT]))->p_vaddr = new_hdr->p_vaddr + aux[AT_PHENT] * (aux[AT_PHNUM] + 2);

	crt_memcpy((char*)new_hdr + aux[AT_PHENT] * (aux[AT_PHNUM] + 2), linker_path, linker_len);

	for (i = 0; i < aux[AT_PHNUM]; i++) {
		Phdr *hdr = (void*)((char*)aux[AT_PHDR] + aux[AT_PHENT] * i);
		Phdr *dst = (void*)((char*)new_hdr + aux[AT_PHENT] * (i + 2));
		if (hdr->p_type == PT_PHDR || hdr->p_type == PT_INTERP) {
			// Can't have a duplicate
			dst->p_type = PT_NULL;
		} else {
			crt_memcpy(dst, hdr, aux[AT_PHENT]);
		}
	}

	if (crt_mprotect(new_hdr, aux[AT_PHENT] * (aux[AT_PHNUM] + 2) + linker_len, PROT_READ))
		ERROR("Failed to mprotect new phdrs")

	for (i=0; auxv[i]; i+=2) {
		if (auxv[i] == AT_BASE)
			auxv[i + 1] = (size_t)loader_hdr;
		if (auxv[i] == AT_PHDR)
			auxv[i + 1] = (size_t)new_hdr;
		if (auxv[i] == AT_PHNUM)
			auxv[i + 1] += 2;
	}

	entry = (char*)loader_hdr + loader_hdr->e_entry;

	/* Undo the relocations performed by dlstart */

	if (NEED_MIPS_GOT_RELOCS) {
		const size_t *dynv = _DYNAMIC;
		size_t local_cnt = 0;
		size_t *got = (void *)(base + dyn[DT_PLTGOT]);
		for (i=0; dynv[i]; i+=2) if (dynv[i]==DT_MIPS_LOCAL_GOTNO)
			local_cnt = dynv[i+1];
		for (i=0; i<local_cnt; i++) got[i] -= (size_t)base;
	}

	size_t *rel = (void *)((size_t)base+dyn[DT_REL]);
	size_t rel_size = dyn[DT_RELSZ];
	for (; rel_size; rel+=2, rel_size-=2*sizeof(size_t)) {
		if (!IS_RELATIVE(rel[1], 0)) continue;
		size_t *rel_addr = (void *)((size_t)base + rel[0]);
		*rel_addr -= (size_t)base;
	}

	CRTJMP(entry, argv - 1);

error:
	for(;;) a_crash();
}
