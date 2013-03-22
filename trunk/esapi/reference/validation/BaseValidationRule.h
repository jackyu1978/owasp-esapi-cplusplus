/**
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2011 - The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 *
 * @author Jeff Williams <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @created 2011
 */

#pragma once

#include "EsapiCommon.h"
#include "Encoder.h"
#include "ValidationRule.h"
#include "errors/UnsupportedOperationException.h"

#include <set>


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
		shared_ptr<Encoder> encoder;

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
		virtual T sanitize(const NarrowString &, const NarrowString &) = 0;

	private:
		String typeName;


	public:
		/*
		 * @throws UnsupportedOperationException - Should not be instanciated like this.
		 */
		BaseValidationRule ();
		BaseValidationRule (const NarrowString &);
		BaseValidationRule (const NarrowString &, Encoder*);

		//template <typename T>
		virtual T getValid(const NarrowString &, const NarrowString &) =0;

	    /**
	     * {@inheritDoc}
		 */
		virtual void setAllowNull(bool);

	    /**
	     * {@inheritDoc}
		 */
		virtual String getTypeName();

	    /**
	     * {@inheritDoc}
		 */
		virtual void setTypeName(const NarrowString &);

	    /**
	     * {@inheritDoc}
		 */
		virtual void setEncoder(Encoder*);

	    /**
	     * {@inheritDoc}
		 */
		virtual void assertValid(const NarrowString &, const NarrowString &);

	    /**
	     * {@inheritDoc}
		 */
		//template <typename T>
		virtual T getValid(const NarrowString &, const NarrowString &, ValidationErrorList&);

	    /**
	     * {@inheritDoc}
		 */
		virtual T getSafe(const NarrowString &, const NarrowString &);

	    /**
	     * {@inheritDoc}
		 */
		virtual bool isValid(const NarrowString &, const NarrowString &);

	    /**
	     * {@inheritDoc}
		 */
		virtual String whitelist(const NarrowString &, const std::set<Char> &);

		virtual bool isAllowNull();

		//virtual void setAllowNull( bool );

		virtual const Encoder* getEncoder();

		virtual ~BaseValidationRule() {};
	};

// Template functions have to be declared in the same file

template <typename T>
BaseValidationRule<T>::BaseValidationRule() {
	throw UnsupportedOperationException("BaseValidationRule<T> Should not be instantiated by default constructor");
}

template <typename T>
BaseValidationRule<T>::BaseValidationRule (const NarrowString &newTypeName)
  : allowNull(false), encoder(), typeName(newTypeName)
{
	// get encoder singleton
	//TODO setEncoder( ESAPI.encoder() );
}

template <typename T>
BaseValidationRule<T>::BaseValidationRule (const NarrowString &newTypeName, Encoder* newEncoder)
  : allowNull(false), encoder(newEncoder), typeName(newTypeName)
{
}

template <typename T>
void BaseValidationRule<T>::setAllowNull( bool flag ) {
	allowNull = flag;
}

template <typename T>
String BaseValidationRule<T>::getTypeName() {
	return this->typeName;
}

template <typename T>
void BaseValidationRule<T>::setTypeName( const NarrowString &newTypeName ) {
	this->typeName = newTypeName;
}

template <typename T>
void BaseValidationRule<T>::setEncoder( Encoder* newEncoder ) {
		this->encoder = shared_ptr<Encoder>(newEncoder);
}

template <typename T>
void BaseValidationRule<T>::assertValid( const NarrowString &context, const NarrowString &input ) {
		getValid( context, input, *(new ValidationErrorList));
}

template <typename T>
T BaseValidationRule<T>::getValid( const NarrowString &context, const NarrowString &input, ValidationErrorList &errorList ) {
		T valid = 0;
		try {
			valid = this->getValid( context, input );
		} catch (ValidationException &e) {
			errorList.addError(context, &e);
		}
		return valid;
}

template <typename T>
T BaseValidationRule<T>::getSafe( const NarrowString &context, const NarrowString &input ) {
		T valid = 0;
		try {
			valid = this->getValid( context, input );
		} catch ( ValidationException& /*e*/ ) {
			return sanitize( context, input );
		}
		return valid;
}

template <typename T>
bool BaseValidationRule<T>::isValid( const NarrowString &context, const NarrowString &input ) {
		bool valid = false;
		try {
			this->getValid( context, input );
			valid = true;
		} catch( std::exception& /*e*/ ) {
			valid = false;
		}

		return valid;
}

//String BaseValidationRule::whitelist( const NarrowString &input, Char whitelist[]) {
//	String stripped = "";
//	int whitelistSize = sizeof(whitelist) / sizeof(Char);
//
//	for (unsigned int i = 0; i < input.length(); i++) {
//		Char c = input[i];
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
String BaseValidationRule<T>::whitelist( const NarrowString &input, const std::set<Char> &whitelist) {
	String stripped = "";

	for (unsigned int i = 0; i < input.length(); i++) {
		Char c = input[i];
		if (whitelist.find(c) != whitelist.end()) {
			stripped += c;
		}
	}

	return stripped;
}

template <typename T>
bool BaseValidationRule<T>::isAllowNull() {
	return allowNull;
}

template <typename T>
const Encoder* BaseValidationRule<T>::getEncoder() {
	return this->encoder.get();
}

} // esapi
