/**
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
#include "codecs/Codec.h"
#include "errors/ExecutionException.h"

#include <fstream>
#include <vector>
#include <string>

namespace esapi
{
/**
 * The Executor interface is used to run an OS command with reduced security risk.
 *
 * <p>Implementations should do as much as possible to minimize the risk of
 * injection into either the command or parameters. In addition, implementations
 * should timeout after a specified time period in order to help prevent denial
 * of service attacks.</p>
 *
 * <p>The class should perform logging and error handling as
 * well. Finally, implementation should handle errors and generate an
 * ExecutorException with all the necessary information.</p>
 *
 * <p>The reference implementation does all of the above.</p>
 *
 * @since June 11, 2011
 */

  // Hack!!!
  typedef unsigned int ExecuteResult;

	class Executor
	{
	public:
		virtual ExecuteResult executeSystemCommand(const std::fstream& executable, const std::vector<String>& params) = 0;
		virtual ExecuteResult executeSystemCommand(const std::fstream& executable, const std::vector<String>& params, std::fstream&, Codec&, bool, bool) = 0;

		virtual ~Executor() {};
	};
};


