/*
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * http://www.owasp.org/index.php/ESAPI.
 *
 * Copyright (c) 2011 - The OWASP Foundation
 */

#pragma once

#include "EsapiCommon.h"

#include <stdexcept>
#include <string>

// TODO: Finish Porting from Java

class ESAPI_EXPORT EncryptionException : public std::runtime_error
{
public:
	EncryptionException(): std::runtime_error( "EncryptionException" ) {}
};

#endif /* _EncryptionException_H_ */
