#ifndef _StringValidationRule_h_
#define _StringValidationRule_h_

#include <string>

#include "BaseValidationRule.h"

namespace esapi
{
	class StringValidationRule : BaseValidationRule
	{
	public:

		virtual void addWhitelistPattern(const std::string &) throw (IllegalArgumentException) =0;
		virtual void addWhitelistPattern(Pattern) throw (IllegalArgumentException) =0;
		virtual void addBlacklistPattern(const std::string &) throw (IllegalArgumentException)=0;
		virtual void addBlacklistPattern(Pattern) throw (IllegalArgumentException) =0;
		virtual void setMinimumLength(int) =0;
		virtual void setMaximumLength(int) =0;
		virtual void setValidateInputAndCanonical(bool) =0;

	private:
		virtual std::string checkWhitelist(const std::string &, const std::string &, const std::string &) throw (ValidationException) =0;
		virtual std::string checkWhitelist(const std::string &, const std::string &) throw (ValidationException) =0;
		virtual std::string checkBlacklist(const std::string &, const std::string &, const std::string &) throw (ValidationException) =0;
		virtual std::string checkBlacklist(const std::string &, const std::string &) throw (ValidationException) =0;
		virtual std::string checkLength(const std::string &, const std::string &, const std::string &) throw (ValidationException) =0;
		virtual std::string checkLength(const std::string &, const std::string &) throw (ValidationException) =0;
		virtual std::string checkEmpty(const std::string &, const std::string &, const std::string &) throw (ValidationException) =0;
		virtual std::string checkEmpty(const std::string &, const std::string &) throw (ValidationException) =0;

		virtual ~StringValidationRule() {};
	};
};

#endif /* _StringValidationRule_h_ */
