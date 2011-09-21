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

#include <string>
#include <set>
#include "errors/ValidationException.h"
#include "ValidationErrorList.h"
#include "Encoder.h"

namespace esapi
{
	template <typename T>
	class ValidationRule
	{
	public:


		/**
		 * Parse the input, throw exceptions if validation fails
		 *
		 * @param context
		 *            for logging
		 * @param input
		 *            the value to be parsed
		 * @return a validated value
		 * @throws ValidationException
		 *             if any validation rules fail
		 */
		//template <typename T>
		virtual T getValid(const String &, const String &) =0;

		/**
		 * Whether or not a valid valid can be null. getValid will throw an
		 * Exception and getSafe will return the default value if flag is set to
		 * true
		 *
		 * @param flag
		 *            whether or not null values are valid/safe
		 */
		virtual void setAllowNull(bool) =0;

		/**
		 * Programmatically supplied name for the validator
		 * @return a name, describing the validator
		 */
		virtual String getTypeName() =0;

		/**
		 * @param typeName a name, describing the validator
		 */
		virtual void setTypeName(const String &) =0;

		/**
		 * @param encoder the encoder to use
		 */
		virtual void setEncoder(Encoder *) =0;

		/**
		 * Check if the input is valid, throw an Exception otherwise
		 */
		virtual void assertValid(const String &, const String &) =0;

		/**
		 * Get a validated value, add the errors to an existing error list
		 */
		//template <typename T>
		virtual T getValid(const String &, const String &, ValidationErrorList &) =0;

		/**
		 * Try to call get valid, then call sanitize, finally return a default value
		 */
		//template <typename T>
		virtual T getSafe(const String &, const String &) =0;

		/**
		 * @return true if the input passes validation
		 */
		virtual bool isValid(const String &, const String &) =0;

		/**
		 * String the input of all chars contained in the list
		 */
		virtual String whitelist(const String &, const std::set<Char> &) =0;

		virtual ~ValidationRule() {};
	};
};


