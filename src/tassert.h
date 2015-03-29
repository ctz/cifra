#ifndef TASSERT_H
#define TASSERT_H

/* Tiny assert
 * -----------
 *
 * This is an assert(3) definition which doesn't include any
 * strings, but just branches to abort(3) on failure.
 */

#ifndef FULL_FAT_ASSERT
# include <stdlib.h>
# define assert(expr) do { if (!(expr)) abort(); } while (0)
#else
# include <assert.h>
#endif

#endif
