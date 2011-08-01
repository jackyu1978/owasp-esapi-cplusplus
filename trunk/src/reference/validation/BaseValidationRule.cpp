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

#include "esapi/reference/validation/BaseValidationRule.h"
#include <exception>


esapi::Base_Validation_Rule::Base_Validation_Rule (std::string newTypeName) {
	//this();
	this->allowNull = false;
	//typeName = "";

	// get encoder singleton
	//TODO setEncoder( ESAPI.encoder() );

	this->typeName = newTypeName;
}


esapi::Base_Validation_Rule::Base_Validation_Rule (std::string newTypeName, Encoder* encoder)
{
	//this();
	allowNull = false;
	typeName = "";

	// TODO //setEncoder( encoder );

	typeName = newTypeName;
}


void esapi::Base_Validation_Rule::setAllowNull( bool flag ) {
	allowNull = flag;
}

std::string esapi::Base_Validation_Rule::getTypeName() {
	return this->typeName;
}

void esapi::Base_Validation_Rule::setTypeName( std::string newTypeName ) {
	this->typeName = newTypeName;
}


void esapi::Base_Validation_Rule::setEncoder( Encoder *newEncoder ) {
		this->encoder = newEncoder;
}

void esapi::Base_Validation_Rule::assertValid( std::string context, std::string input ) throw (ValidationException) {
		getValid( context, input, 0 );
}

void* esapi::Base_Validation_Rule::getValid( std::string context, std::string input,ValidationErrorList* errorList ) throw (ValidationException) {
		void* valid = 0;
		try {
			valid = this->getValid( context, input );
		} catch (ValidationException& e) {
			errorList->addError(context, &e);
		}
		return valid;
}

void* esapi::Base_Validation_Rule::getSafe( std::string context, std::string input ) {
		void* valid = 0;
		try {
			valid = this->getValid( context, input );
		} catch ( ValidationException& e ) {
			return sanitize( context, input );
		}
		return valid;
}

bool esapi::Base_Validation_Rule::isValid( std::string context, std::string input ) {
		bool valid = false;
		try {
			this->getValid( context, input );
			valid = true;
		} catch( std::exception& e ) {
			valid = false;
		}

		return valid;
}

std::string esapi::Base_Validation_Rule::whitelist( std::string input, char whitelist[]) {
	std::string stripped = "";
	int whitelistSize = sizeof(whitelist) / sizeof(char);

	for (unsigned int i = 0; i < input.length(); i++) {
		char c = input[i];

		for (int n = 0; n < whitelistSize; n++) {
			if (whitelist[n] == c){
				stripped += c;
			}
		}
	}
	return stripped;
}

/**
 * Removes characters that aren't in the whitelist from the input String.
 * O(input.length) whitelist performance
 * @param input String to be sanitized
 * @param whitelist allowed characters
 * @return input stripped of all chars that aren't in the whitelist
 */
std::string esapi::Base_Validation_Rule::whitelist( std::string input, std::set<char> whitelist) {
	std::string stripped = "";

	for (unsigned int i = 0; i < input.length(); i++) {
		char c = input[i];
		if (whitelist.find(c) != whitelist.end()) {
			stripped += c;
		}
	}

	return stripped;
}

bool esapi::Base_Validation_Rule::isAllowNull() {
	return allowNull;
}



esapi::Encoder* esapi::Base_Validation_Rule::getEncoder() {
	return this->encoder;
}


