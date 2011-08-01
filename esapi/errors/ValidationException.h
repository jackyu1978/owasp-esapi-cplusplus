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

#ifndef _ValidationException_H_
#define _ValidationException_H_

#include <stdexcept>
#include <string>
#include "EnterpriseSecurityException.h"

namespace esapi {

/**
 * A ValidationException should be thrown to indicate that the data provided by
 * the user or from some other external source does not match the validation
 * rules that have been specified for that data.
 *
 * @author Jeff Williams (jeff.williams@aspectsecurity.com)
 * @author Dan Amodio (dan.amodio@aspectsecurity.com)
 */
class ValidationException : public esapi::EnterpriseSecurityException
{
protected:
	static const long serialVersionUID = 1;

private:
	/** The UI reference that caused this ValidationException */
	std::string context;

public:
    /**
     * Creates a new instance of ValidationException.
     *
     * @param userMessage
     *            the message to display to users
     * @param logMessage
	 * 			  the message logged
     */
	ValidationException::ValidationException(std::string userMessage, std::string logMessage): esapi::EnterpriseSecurityException(userMessage, logMessage) {}

    /**
     * Creates a new instance of ValidationException.
     *
     * @param userMessage
     *            the message to display to users
     * @param logMessage
	 * 			  the message logged
     * @param context
     *            the source that caused this exception
     */
	ValidationException::ValidationException(std::string, std::string, std::string);

	/**
	 * Returns the UI reference that caused this ValidationException
	 *
	 * @return context, the source that caused the exception, stored as a string
	 */
	std::string getContext();

	/**
	 * Set's the UI reference that caused this ValidationException
	 *
	 * @param context
	 * 			the context to set, passed as a String
	 */
	void setContext(std::string);

	ValidationException::~ValidationException() throw() {};
};

};
#endif /* _ValidationException_H_ */
