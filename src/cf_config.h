/* --- Library configuration --- */

#ifndef CF_CONFIG_H
#define CF_CONFIG_H

/* Define this as 1 if you need all available side channel protections.
 * This option MAY alter the ABI.
 *
 * This has a non-trivial performance penalty.  Where a
 * side-channel free option is cheap or free (like checking
 * a MAC) this is always done in a side-channel free way.
 *
 * The default is ON for all available protections.
 */
#ifndef CF_SIDE_CHANNEL_PROTECTION
# define CF_SIDE_CHANNEL_PROTECTION 1
#endif

/* Define this as 1 if you need timing/branch prediction side channel
 * protection.
 *
 * You probably want this.  The default is on. */
#ifndef CF_TIME_SIDE_CHANNEL_PROTECTION
# define CF_TIME_SIDE_CHANNEL_PROTECTION CF_SIDE_CHANNEL_PROTECTION
#endif

/* Define this as 1 if you need cache side channel protection.
 *
 * If you have a microcontroller with no cache, you can turn this off
 * without negative effects.
 *
 * The default is on.  This will have some performance impact,
 * especially on AES.
 */
#ifndef CF_CACHE_SIDE_CHANNEL_PROTECTION
# define CF_CACHE_SIDE_CHANNEL_PROTECTION CF_SIDE_CHANNEL_PROTECTION
#endif

#endif
