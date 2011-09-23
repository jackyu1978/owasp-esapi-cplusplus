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
 * @author Andrew Durkin, atdurkin@gmail.com
 *
 */

#pragma once

#include "EsapiCommon.h"
#include "util/SecureString.h"
#include "util/SecureArray.h"
//#include "Logger.h"
#include <string>

namespace esapi
{

class ESAPI_EXPORT PlainText
{
private:
//     const Logger logger = esapi.getLogger("PlainText");
     esapi::SecureByteArray rawBytes;
public:
     PlainText();
     explicit PlainText(std::string str);
     explicit PlainText(const esapi::SecureByteArray &b);
     std::string toString();
     esapi::SecureByteArray asBytes();
     bool equals(PlainText obj);
     int length();
     void overwrite();
};

} // NAMESPACE esapi
