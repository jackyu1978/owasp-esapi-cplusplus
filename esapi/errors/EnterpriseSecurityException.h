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
 * @created 2007
 */

#pragma once

#include "EsapiCommon.h"
#include <exception>

  /**
   * EnterpriseSecurityException is the base class for all security related exceptions. You should pass in the root cause
   * exception where possible. Constructors for classes extending EnterpriseSecurityException should be sure to call the
   * appropriate super() method in order to ensure that logging and intrusion detection occur properly.
   * <P>
   * All EnterpriseSecurityExceptions have two messages, one for the user and one for the log file. This way, a message
   * can be shown to the user that doesn't contain sensitive information or unnecessary implementation details. Meanwhile,
   * all the critical information can be included in the exception so that it gets logged.
   * <P>
   * Note that the "logMessage" for ALL EnterpriseSecurityExceptions is logged in the log file. This feature should be
   * used extensively throughout ESAPI implementations and the result is a fairly complete set of security log records.
   * ALL EnterpriseSecurityExceptions are also sent to the IntrusionDetector for use in detecting anomalous patterns of
   * application usage.
   * <P>
   * @author Jeff Williams (jeff.williams@aspectsecurity.com)
   */
namespace esapi
{
  class ESAPI_EXPORT EnterpriseSecurityException : public std::exception
    {
    protected:

      /** The logger. */
      //const Logger logger = ESAPI.getLogger(L"EnterpriseSecurityException");
      NarrowString userMessage;
      NarrowString logMessage;

    public:

      /**
       * Creates a new instance of EnterpriseSecurityException. This exception is automatically logged, so that simply by
       * using this API, applications will generate an extensive security log. In addition, this exception is
       * automatically registered with the IntrusionDetector, so that quotas can be checked.
       *
       * It should be noted that messages that are intended to be displayed to the user should be safe for display. In
       * other words, don't pass in unsanitized data here. Also could hold true for the logging message depending on the
       * context of the exception.
       *
       * @param userMessage
       *                        the message displayed to the user
       * @param logMessage
       *                        the message logged
       */
      explicit EnterpriseSecurityException(const NarrowString& userMessage, const NarrowString& logMessage);

      /**
       * Creates a new instance of EnterpriseSecurityException. This exception is automatically logged, so that simply by
       * using this API, applications will generate an extensive security log. In addition, this exception is
       * automatically registered with the IntrusionDetector, so that quotas can be checked.
       *
       * It should be noted that messages that are intended to be displayed to the user should be safe for display. In
       * other words, don't pass in unsanitized data here. Also could hold true for the logging message depending on the
       * context of the exception.
       *
       * @param userMessage
       *                        the message displayed to the user
       * @param logMessage
       *                        the message logged
       */
      EnterpriseSecurityException(const WideString& userMessage, const WideString& logMessage);

      /**
       * Returns message meant for display to users
       *
       * Note that if you are unsure of what set this message, it would probably
       * be a good idea to encode this message before displaying it to the end user.
       *
       * @return a NarrowString containing a message that is safe to display to users
       */
      virtual NarrowString getUserMessage() const;      

      /**
       * Returns a message that is safe to display in logs, but may contain
       * sensitive information and therefore probably should not be displayed to
       * users.
       *
       * @return a NarrowString containing a message that is safe to display in logs,
       * but probably not to users as it may contain sensitive information.
       */
      virtual NarrowString getLogMessage() const;

      virtual ~EnterpriseSecurityException() throw() { };

      virtual const char* what() const throw();
    };
};
