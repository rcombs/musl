#include "pthread_impl.h"

int pthread_mutex_destroy(pthread_mutex_t *mutex)
{
	/* If the mutex being destroyed is process-shared and has nontrivial
	 * type (tracking ownership), it might be in the pending slot of a
	 * robust_list; wait for quiescence. */
	if (mutex->_m_type > 128) __vm_wait();

	/* Some software seems to call destroy on locked mutexes.
	 * This is undefined behavior, but it's harmless in glibc.
	 * In our implementation, there's a risk that a destroyed mutex
	 * could result in invalid internal state in the holding thread.
	 * This is easy enough to handle, at least for the case where
	 * the same thread owns the mutex.
	 * We'll just attempt to unlock it, since this is harmless
	 * in our implementation even if it's already unlocked,
	 * or locked by another thread. */
	__pthread_mutex_unlock(mutex);
	return 0;
}
