#ifndef _BaseValidationRule_h_
#define _BaseValidationRule_h_

#include "ValidationRule.h"
#include <string>
#include <set>
#include "Encoder.h"

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
	class BaseValidationRule : ValidationRule {
	protected:
		bool allowNull;
		const Encoder *encoder;

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
		virtual void* sanitize(const std::string &, const std::string &) =0;

	private:
		std::string typeName;

		BaseValidationRule () {};

	public:
		BaseValidationRule (const std::string &);
		BaseValidationRule (const std::string &, Encoder&);

		virtual void* getValid(const std::string &, const std::string &) throw (ValidationException) =0;

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
		virtual void setTypeName(const std::string &);

	    /**
	     * {@inheritDoc}
		 */
		virtual void setEncoder(const Encoder &) =0;

	    /**
	     * {@inheritDoc}
		 */
		virtual void assertValid(const std::string &, const std::string &) throw (ValidationException);

	    /**
	     * {@inheritDoc}
		 */
		virtual void* getValid(const std::string &, const std::string &, ValidationErrorList&) throw (ValidationException);

	    /**
	     * {@inheritDoc}
		 */
		virtual void* getSafe(const std::string &, const std::string &);

	    /**
	     * {@inheritDoc}
		 */
		virtual bool isValid(const std::string &, const std::string &);

	    /**
	     * {@inheritDoc}
		 */
		virtual std::string whitelist(const std::string &, const std::set<char> &);

		virtual bool isAllowNull();

		//virtual void setAllowNull( bool );

		virtual const Encoder* getEncoder();

		virtual ~BaseValidationRule() {};
	};
};

#endif /* _BaseValidationRule_h_ */
