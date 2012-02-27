/**
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * http://www.owasp.org/index.php/ESAPI.
 *
 * Copyright (c) 2011 - The OWASP Foundation
 *
 * @author Kevin Wall, kevin.w.wall@gmail.com
 * @author Jeffrey Walton, noloader@gmail.com
 *
 */

#pragma once

#if defined(_MSC_VER)
# pragma warning( push, 2 )
# pragma warning( disable: 4505 )
# pragma warning( disable: 6326 )
#endif

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

#include <cryptopp/config.h>
#include <cryptopp/misc.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/aes.h>
#include <cryptopp/des.h>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/md5.h>
//////////////////////////////////////////
//  These include files are not included in 5.3.0
//    #include <cryptopp/eax.h>
//    #include <cryptopp/ccm.h>
//    #include <cryptopp/gcm.h>
#include <cryptopp/hmac.h>
#include <cryptopp/osrng.h>
#include <cryptopp/modes.h>
#include <cryptopp/base64.h>
#include <cryptopp/hrtimer.h>
#include <cryptopp/integer.h>
#include <cryptopp/filters.h>
#include <cryptopp/blowfish.h>
#include <cryptopp/camellia.h>
#include <cryptopp/whrlpool.h>
#include <cryptopp/rijndael.h>
#include <cryptopp/secblock.h>

#if defined(_MSC_VER)
# pragma warning( pop )
#endif
