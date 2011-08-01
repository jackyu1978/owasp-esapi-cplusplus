#ifndef _string_validation_rule_h_
#define _string_validation_rule_h_

#include "BaseValidationRule.h"

namespace esapi
{
	class String_Validation_Rule : Base_Validation_Rule
	{
	public:

		virtual void addWhitelistPattern(String) throw (IllegalArgumentException) =0;
		virtual void addWhitelistPattern(Pattern) throw (IllegalArgumentException) =0;
		virtual void addBlacklistPattern(String) throw (IllegalArgumentException)=0;
		virtual void addBlacklistPattern(Pattern) throw (IllegalArgumentException) =0;
		virtual void setMinimumLength(int) =0;
		virtual void setMaximumLength(int) =0;
		virtual void setValidateInputAndCanonical(bool) =0;

	private:
		virtual String checkWhitelist(String, String, String) throw (ValidationException) =0;
		virtual String checkWhitelist(String, String) throw (ValidationException) =0;
		virtual String checkBlacklist(String, String, String) throw (ValidationException) =0;
		virtual String checkBlacklist(String, String) throw (ValidationException) =0;
		virtual String checkLength(String, String, String) throw (ValidationException) =0;
		virtual String checkLength(String, String) throw (ValidationException) =0;
		virtual String checkEmpty(String, String, String) throw (ValidationException) =0;
		virtual String checkEmpty(String, String) throw (ValidationException) =0;

		virtual ~String_Validation_Rule() {};
	};
};

#endif /* _string_validation_rule_h_ */
