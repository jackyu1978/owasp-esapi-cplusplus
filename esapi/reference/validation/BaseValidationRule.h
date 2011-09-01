#ifndef _BaseValidationRule_h_
#define _BaseValidationRule_h_

#include "Encoder.h"
#include "ValidationRule.h"
#include "errors/UnsupportedOperationException.h"

#include <string>
#include <set>
#include <boost/shared_ptr.hpp>

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
	template <typename T>
	class BaseValidationRule : ValidationRule<T> {
	protected:
		bool allowNull;
        // TODO: Bring back constness as required
		boost::shared_ptr<Encoder> encoder;

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
		//template <typename T>
		virtual T sanitize(const std::string &, const std::string &) = 0;

	private:
		std::string typeName;


	public:
		/*
		 * @throws UnsupportedOperationException - Should not be instanciated like this.
		 */
		BaseValidationRule ();
		BaseValidationRule (const std::string &);
		BaseValidationRule (const std::string &, Encoder*);

		//template <typename T>
		virtual T getValid(const std::string &, const std::string &) throw (ValidationException) =0;

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
		virtual void setEncoder(Encoder*) = 0;

	    /**
	     * {@inheritDoc}
		 */
		virtual void assertValid(const std::string &, const std::string &) throw (ValidationException);

	    /**
	     * {@inheritDoc}
		 */
		//template <typename T>
		virtual T getValid(const std::string &, const std::string &, ValidationErrorList&) throw (ValidationException);

	    /**
	     * {@inheritDoc}
		 */
		virtual T getSafe(const std::string &, const std::string &);

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

// Template functions have to be declared in the same file

template <typename T>
esapi::BaseValidationRule<T>::BaseValidationRule() {
	throw new esapi::UnsupportedOperationException("BaseValidationRule<T> Should not be instantiated by default constructor.");
}

template <typename T>
esapi::BaseValidationRule<T>::BaseValidationRule (const std::string &newTypeName)
  : allowNull(false), encoder(), typeName(newTypeName)
{
	// get encoder singleton
	//TODO setEncoder( ESAPI.encoder() );
}

template <typename T>
esapi::BaseValidationRule<T>::BaseValidationRule (const std::string &newTypeName, Encoder* newEncoder)
  : allowNull(false), encoder(newEncoder), typeName(newTypeName)
{
}

template <typename T>
void esapi::BaseValidationRule<T>::setAllowNull( bool flag ) {
	allowNull = flag;
}

template <typename T>
std::string esapi::BaseValidationRule<T>::getTypeName() {
	return this->typeName;
}

template <typename T>
void esapi::BaseValidationRule<T>::setTypeName( const std::string &newTypeName ) {
	this->typeName = newTypeName;
}

template <typename T>
void esapi::BaseValidationRule<T>::setEncoder( Encoder* newEncoder ) {
		this->encoder = boost::shared_ptr<Encoder>(newEncoder);
}

template <typename T>
void esapi::BaseValidationRule<T>::assertValid( const std::string &context, const std::string &input ) throw (ValidationException) {
		getValid( context, input, *(new ValidationErrorList));
}

template <typename T>
T esapi::BaseValidationRule<T>::getValid( const std::string &context, const std::string &input, ValidationErrorList &errorList ) throw (ValidationException) {
		T valid = 0;
		try {
			valid = this->getValid( context, input );
		} catch (ValidationException &e) {
			errorList.addError(context, &e);
		}
		return valid;
}

template <typename T>
T esapi::BaseValidationRule<T>::getSafe( const std::string &context, const std::string &input ) {
		T valid = 0;
		try {
			valid = this->getValid( context, input );
		} catch ( ValidationException& /*e*/ ) {
			return sanitize( context, input );
		}
		return valid;
}

template <typename T>
bool esapi::BaseValidationRule<T>::isValid( const std::string &context, const std::string &input ) {
		bool valid = false;
		try {
			this->getValid( context, input );
			valid = true;
		} catch( std::exception& /*e*/ ) {
			valid = false;
		}

		return valid;
}

//std::string esapi::BaseValidationRule::whitelist( const std::string &input, char whitelist[]) {
//	std::string stripped = "";
//	int whitelistSize = sizeof(whitelist) / sizeof(char);
//
//	for (unsigned int i = 0; i < input.length(); i++) {
//		char c = input[i];
//
//		for (int n = 0; n < whitelistSize; n++) {
//			if (whitelist[n] == c){
//				stripped += c;
//			}
//		}
//	}
//	return stripped;
//}

/**
 * Removes characters that aren't in the whitelist from the input String.
 * O(input.length) whitelist performance
 * @param input String to be sanitized
 * @param whitelist allowed characters
 * @return input stripped of all chars that aren't in the whitelist
 */
template <typename T>
std::string esapi::BaseValidationRule<T>::whitelist( const std::string &input, const std::set<char> &whitelist) {
	std::string stripped = "";

	for (unsigned int i = 0; i < input.length(); i++) {
		char c = input[i];
		if (whitelist.find(c) != whitelist.end()) {
			stripped += c;
		}
	}

	return stripped;
}

template <typename T>
bool esapi::BaseValidationRule<T>::isAllowNull() {
	return allowNull;
}

template <typename T>
const esapi::Encoder* esapi::BaseValidationRule<T>::getEncoder() {
	return this->encoder.get();
}


#endif /** _BaseValidationRule_h_ */
