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

#include "EsapiCommon.h"

ESAPI_MS_WARNING_PUSH(3)

#include <cryptopp/aes.h>
#include <cryptopp/des.h>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/hmac.h>
#include <cryptopp/osrng.h>
#include <cryptopp/modes.h>
#include <cryptopp/base64.h>
#include <cryptopp/hrtimer.h>
#include <cryptopp/integer.h>
#include <cryptopp/blowfish.h>
#include <cryptopp/camellia.h>
#include <cryptopp/whrlpool.h>
#include <cryptopp/filters.h>
#include <cryptopp/secblock.h>

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <cryptopp/arc4.h>

ESAPI_MS_WARNING_POP()