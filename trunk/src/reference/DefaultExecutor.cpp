/**
* OWASP Enterprise Security API (ESAPI)
*
* This file is part of the Open Web Application Security Project (OWASP)
* Enterprise Security API (ESAPI) project. For details, please see
* <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
*
* Copyright (c) 2007 - The OWASP Foundation
*
* The ESAPI is published by OWASP under the BSD license. You should read and accept the
* LICENSE before you use, modify, and/or redistribute this software.
*
* @author Jeff Williams <a href="http://www.aspectsecurity.com">Aspect Security</a>
* @author Jim Manico (jim@manico.net) <a href="http://www.manico.net">Manico.net</a>
* @author David Anderson (david.anderson@aspectsecurity.com)
*
* @created 2007
*/

#include <fstream>
#include <vector>
#include <string>

#include "Executor.h"
#include "errors/ExecutionException.h"

namespace esapi
{
  class ESAPI_EXPORT DefaultExecutor
  {
    virtual ExecuteResult executeSystemCommand(const std::fstream& executable, const std::vector<std::string>& params)
    {
      return 1;
    }

    virtual ExecuteResult executeSystemCommand(const std::fstream& executable, const std::vector<std::string>& params, std::fstream workingDir, Codec codec, bool logParams, bool redirectErrorStream)
    {
      return 1;
    }
  };
} // NAMESPACE