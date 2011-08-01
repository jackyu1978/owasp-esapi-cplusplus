#ifndef _base_validation_rule_h_
#define _base_validation_rule_h_

#include "ValidationRule.h"
#include <string>
#include <set>
#include "encoder.h"

/**
 * A ValidationRule performs syntax and possibly semantic validation of a single
 * piece of data from an untrusted source.
 *
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 *         href="http://www.aspectsecurity.com">Aspect Security</a>
 * @author Dan Amodio (dan.amodio@aspectsecurity.com)
 * @since June 1, 2007
 * @see org.owasp.esapi.Validator
 */

namespace esapi
{
	class Base_Validation_Rule : ValidationRule {
	protected:
		bool allowNull;
		Encoder * encoder;

		/**
		 * The method is similar to ValidationRuile.getSafe except that it returns a
		 * harmless object that <b>may or may not have any similarity to the original
		 * input (in some cases you may not care)</b>. In most cases this should be the
		 * same as the getSafe method only instead of throwing an exception, return
		 * some default value.
		 *
		 * @param context
		 * @param input
		 * @return a parsed version of the input or a default value.
		 */
		virtual void* sanitize(std::string, std::string) =0;

	private:
		std::string typeName;

		Base_Validation_Rule () {};

	public:
		Base_Validation_Rule (std::string);
		Base_Validation_Rule (std::string, Encoder*);

		virtual void* getValid(std::string, std::string) throw (ValidationException) =0;

	    /**
	     * {@inheritDoc}
		 */
		virtual void setAllowNull(bool);

	    /**
	     * {@inheritDoc}
		 */
		virtual std::string getTypeName();

	    /**
	     * {@inheritDoc}
		 */
		virtual void setTypeName(std::string);

	    /**
	     * {@inheritDoc}
		 */
		virtual void setEncoder(Encoder*) =0;

	    /**
	     * {@inheritDoc}
		 */
		virtual void assertValid(std::string, std::string) throw (ValidationException);

	    /**
	     * {@inheritDoc}
		 */
		virtual void* getValid(std::string, std::string,class ValidationErrorList*) throw (ValidationException);

	    /**
	     * {@inheritDoc}
		 */
		virtual void* getSafe(std::string, std::string);

	    /**
	     * {@inheritDoc}
		 */
		virtual bool isValid(std::string, std::string);

	    /**
	     * {@inheritDoc}
		 */
		virtual std::string whitelist(std::string, char[]);

	    /**
	     * {@inheritDoc}
		 */
		virtual std::string whitelist(std::string, std::set<char>);

		virtual bool isAllowNull();

		//virtual void setAllowNull( bool );

		virtual Encoder* getEncoder();

		virtual ~Base_Validation_Rule() {};
	};
};

#endif /* _base_validation_rule_h_ */
