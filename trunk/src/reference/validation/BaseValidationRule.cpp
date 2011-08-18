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

#include "reference/validation/BaseValidationRule.h"
#include <exception>
#include "Encoder.h"


esapi::BaseValidationRule::BaseValidationRule (const std::string &newTypeName) {
	//this();
	this->allowNull = false;
	//typeName = "";

	// get encoder singleton
	//TODO setEncoder( ESAPI.encoder() );

	this->typeName = newTypeName;
}


esapi::BaseValidationRule::BaseValidationRule (const std::string &newTypeName, Encoder &newEncoder)
{
	//this();
	allowNull = false;
	typeName = "";

	//setEncoder( encoder );
	this->encoder = &newEncoder;

	typeName = newTypeName;
}


void esapi::BaseValidationRule::setAllowNull( bool flag ) {
	allowNull = flag;
}

std::string esapi::BaseValidationRule::getTypeName() {
	return this->typeName;
}

void esapi::BaseValidationRule::setTypeName( const std::string &newTypeName ) {
	this->typeName = newTypeName;
}


void esapi::BaseValidationRule::setEncoder( const Encoder &newEncoder ) {
		this->encoder = &newEncoder;
}

void esapi::BaseValidationRule::assertValid( const std::string &context, const std::string &input ) throw (ValidationException) {
		getValid( context, input, *(new ValidationErrorList));
}

void* esapi::BaseValidationRule::getValid( const std::string &context, const std::string &input, ValidationErrorList &errorList ) throw (ValidationException) {
		void* valid = 0;
		try {
			valid = this->getValid( context, input );
		} catch (ValidationException &e) {
			errorList.addError(context, &e);
		}
		return valid;
}

void* esapi::BaseValidationRule::getSafe( const std::string &context, const std::string &input ) {
		void* valid = 0;
		try {
			valid = this->getValid( context, input );
		} catch ( ValidationException& /*e*/ ) {
			return sanitize( context, input );
		}
		return valid;
}

bool esapi::BaseValidationRule::isValid( const std::string &context, const std::string &input ) {
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
std::string esapi::BaseValidationRule::whitelist( const std::string &input, const std::set<char> &whitelist) {
	std::string stripped = "";

	for (unsigned int i = 0; i < input.length(); i++) {
		char c = input[i];
		if (whitelist.find(c) != whitelist.end()) {
			stripped += c;
		}
	}

	return stripped;
}

bool esapi::BaseValidationRule::isAllowNull() {
	return allowNull;
}



const esapi::Encoder* esapi::BaseValidationRule::getEncoder() {
	return this->encoder;
}


