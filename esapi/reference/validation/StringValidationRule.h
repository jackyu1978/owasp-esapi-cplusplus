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
 */

#pragma once

#include <string>
#include <list>

#include "BaseValidationRule.h"
#include "errors/ValidationException.h"
#include "errors/InvalidArgumentException.h"
#include "errors/IllegalArgumentException.h"

namespace esapi
{
/**
 * A validator performs syntax and possibly semantic validation of a single
 * piece of data from an untrusted source.
 *
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 *         href="http://www.aspectsecurity.com">Aspect Security</a>
 * @author Dan Amodio (dan.amodio@aspectsecurity.com)
 * @since June 1, 2007
 * @see org.owasp.esapi.Validator
 *
 * http://en.wikipedia.org/wiki/Whitelist
 */
class ESAPI_EXPORT StringValidationRule : public BaseValidationRule<String>
{
protected:
	std::set<String> whitelistPatterns;
	std::set<String> blacklistPatterns;
	size_t minLength /*= 0*/;
	size_t maxLength /*= INT_MAX*/;
	bool validateInputAndCanonical /*= true*/;

public:

	StringValidationRule(const String &);

	StringValidationRule(const String &, Encoder*);

	StringValidationRule(const String &, Encoder*, const String &);

	/**
	 * {@inheritDoc}
	 */
	virtual String getValid(const String &, const String &);

	/**
	 * {@inheritDoc}
	 */
	String getValid( const String &context, const String &input, ValidationErrorList &errorList );

	/**
	 * {@inheritDoc}
	 */
	virtual String sanitize(const String &, const String &);

	virtual void addWhitelistPattern(const String &);
	//virtual void addWhitelistPattern(Pattern);

	virtual void addBlacklistPattern(const String &);
	//virtual void addBlacklistPattern(Pattern);

	virtual void setMinimumLength(int);
	virtual void setMaximumLength(int);

	/**
	 * Set the flag which determines whether the in input itself is
	 * checked as well as the canonical form of the input.
	 * @param flag The value to set
	 */
	virtual void setValidateInputAndCanonical(bool);

private:
	StringValidationRule(){};

	/**
	 * checks input against whitelists.
	 * @param context The context to include in exception messages
	 * @param input the input to check
	 * @param orig A origional input to include in exception
	 *	messages. This is not included if it is the same as
	 *	input.
	 * @return input upon a successful check
	 * @throws ValidationException if the check fails.
	 */
	virtual String checkWhitelist(const String &, const String &, const String &);

	/**
	 * checks input against whitelists.
	 * @param context The context to include in exception messages
	 * @param input the input to check
	 * @return input upon a successful check
	 * @throws ValidationException if the check fails.
	 */
	virtual String checkWhitelist(const String &, const String &);

	/**
	 * checks input against blacklists.
	 * @param context The context to include in exception messages
	 * @param input the input to check
	 * @param orig A origional input to include in exception
	 *	messages. This is not included if it is the same as
	 *	input.
	 * @return input upon a successful check
	 * @throws ValidationException if the check fails.
	 */
	virtual String checkBlacklist(const String &, const String &, const String &);

	/**
	 * checks input against blacklists.
	 * @param context The context to include in exception messages
	 * @param input the input to check
	 * @return input upon a successful check
	 * @throws ValidationException if the check fails.
	 */
	virtual String checkBlacklist(const String &, const String &);

	/**
	 * checks input lengths
	 * @param context The context to include in exception messages
	 * @param input the input to check
	 * @param orig A origional input to include in exception
	 *	messages. This is not included if it is the same as
	 *	input.
	 * @return input upon a successful check
	 * @throws ValidationException if the check fails.
	 */
	virtual String checkLength(const String &, const String &, const String &);

	/**
	 * checks input lengths
	 * @param context The context to include in exception messages
	 * @param input the input to check
	 * @return input upon a successful check
	 * @throws ValidationException if the check fails.
	 */
	virtual String checkLength(const String &, const String &);

	/**
	 * checks input emptiness
	 * @param context The context to include in exception messages
	 * @param input the input to check
	 * @param orig A origional input to include in exception
	 *	messages. This is not included if it is the same as
	 *	input.
	 * @return input upon a successful check
	 * @throws ValidationException if the check fails.
	 */
	virtual String checkEmpty(const String &, const String &, const String &);

	/**
	 * checks input emptiness
	 * @param context The context to include in exception messages
	 * @param input the input to check
	 * @return input upon a successful check
	 * @throws ValidationException if the check fails.
	 */
	virtual String checkEmpty(const String &, const String &);

public:
	virtual ~StringValidationRule() {};
};
}; // esapi namespace

