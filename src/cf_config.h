/* --- Library configuration --- */

#ifndef CF_CONFIG_H
#define CF_CONFIG_H

/* Define this as 1 if you need side channel protection.
 * This option MAY alter the ABI.
 * 
 * This should protect against:
 * - the cache side channel
 * - the timing side channel
 * - the branch prediction side channel
 * - simple power analysis
 * 
 * This has a non-trivial performance penalty.  Where a
 * side-channel free option is cheap or free (like checking
 * a MAC) this is always done in a side-channel free way.
 * 
 * Operations this alters include:
 * 
 * - AES s-box lookups.
 * - Multiplications in GF(2^128).
 * 
 * The default is ON.
 */
#ifndef CF_SIDE_CHANNEL_PROTECTION
# define CF_SIDE_CHANNEL_PROTECTION 1
#endif

#endif
