#ifndef _validation_rule_h_
#define _validation_rule_h_

#include <string>
#include <set>
#include "errors/ValidationException.h"
#include "ValidationErrorList.h"
#include "encoder.h"

namespace esapi
{
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
		virtual void* getValid(std::string, std::string) throw (ValidationException) =0;

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
		virtual std::string getTypeName() =0;

		/**
		 * @param typeName a name, describing the validator
		 */
		virtual void setTypeName(std::string) =0;

		/**
		 * @param encoder the encoder to use
		 */
		virtual void setEncoder(Encoder*) =0;

		/**
		 * Check if the input is valid, throw an Exception otherwise
		 */
		virtual void assertValid(std::string, std::string) throw (ValidationException) =0;

		/**
		 * Get a validated value, add the errors to an existing error list
		 */
		virtual void* getValid(std::string, std::string,class ValidationErrorList*) throw (ValidationException) =0;

		/**
		 * Try to call get valid, then call sanitize, finally return a default value
		 */
		virtual void* getSafe(std::string, std::string) =0;

		/**
		 * @return true if the input passes validation
		 */
		virtual bool isValid(std::string, std::string) =0;

		/**
		 * String the input of all chars contained in the list
		 */
		virtual std::string whitelist(std::string, char[]) =0;

		/**
		 * String the input of all chars contained in the list
		 */
		virtual std::string whitelist(std::string, std::set<char>) =0;

		virtual ~ValidationRule() {};
	};
};

#endif /* _validation_rule_h_ */
