/*
 * Compile-time configuration for the NTRUGEN code. This ensures that
 * the keygen code (imported from NTRUGEN) uses the same options as
 * the rest of the Hawk code.
 */

#ifndef NG_CONFIG_H__
#define NG_CONFIG_H__

#include "hawk_config.h"

/*
 * If the prefix for Hawk code is 'xxx', then all NTRUGEN functions will
 * use the 'xxx_ntrugen' prefix. Default prefix for Hawk is 'hawk'.
 */
#ifdef HAWK_PREFIX
#define NTRUGEN_PREFIX           NTRUGEN_PREFIX_(HAWK_PREFIX, _ntrugen)
#define NTRUGEN_PREFIX_(x, y)    NTRUGEN_PREFIX__(x, y)
#define NTRUGEN_PREFIX__(x, y)   x ## y
#else
#define NTRUGEN_PREFIX   hawk_ntrugen
#endif

#ifndef NTRUGEN_AVX2
#if defined HAWK_AVX2
#define NTRUGEN_AVX2   HAWK_AVX2
#endif
#endif // NTRUGEN_AVX2

#endif
