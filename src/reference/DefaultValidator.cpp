/**
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2007 - The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 *
 * @author Jeff Williams <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @author Jim Manico (jim@manico.net) <a href="http://www.manico.net">Manico.net</a>
 * @author Dan Amodio (dan.amodio@aspectsecurity.com)
 *
 * @created 2007
 */

#include "EsapiCommon.h"
#include "Validator.h"
#include "Encoder.h"
#include "ValidationRule.h"
#include "reference/DefaultValidator.h"
#include "reference/validation/BaseValidationRule.h"

#include "errors/UnsupportedOperationException.h"

namespace esapi
{
Validator* DefaultValidator::instance = nullptr;

//std::map<String, ValidationRule> DefaultValidator::rules;

//Encoder* DefaultValidator::encoder = nullptr;

Validator* DefaultValidator::fileValidator = nullptr;


bool DefaultValidator::isEmpty(const String &) const {
	throw UnsupportedOperationException("Not yet implemented"); //TODO Implement
}


bool DefaultValidator::isEmpty(Char[]) const {
	throw UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

Validator* DefaultValidator::getInstance() {
	/*
         if ( instance == null ) {
            synchronized ( Validator.class ) {
                if ( instance == null ) {
                    instance = new DefaultValidator();
                }
            }
        }
        return instance;
	 */
	throw UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

void DefaultValidator::initFileValidator() {
	/*std::list<String> list = new ArrayList<String>();
	list.add( "HTMLEntityCodec" );
	list.add( "PercentCodec" );
	Encoder fileEncoder = new DefaultEncoder( list );
	fileValidator = new DefaultValidator( fileEncoder );	*/
}


DefaultValidator::DefaultValidator()
	: rules(), encoder()
{
	//this.encoder = ESAPI.encoder();
	initFileValidator();
	throw UnsupportedOperationException("Not yet implemented"); //TODO Implement
}


DefaultValidator::DefaultValidator(Encoder* encoder)
	: rules(), encoder(encoder)
{
	initFileValidator();
}

// must override to get rid of pointer member warning
DefaultValidator::DefaultValidator(const DefaultValidator& other)
	: rules(other.rules), encoder(other.encoder)
{
	initFileValidator();
}


void DefaultValidator::addRule( const ValidationRule<void*> & ) {
	//rules.put( rule.getTypeName(), rule );
	throw UnsupportedOperationException("Not yet implemented"); //TODO Implement
}


ValidationRule<void*>& DefaultValidator::getRule( const String & ) {
	//return rules.get( name );
	throw UnsupportedOperationException("Not yet implemented"); //TODO Implement
}


bool DefaultValidator::isValidInput(const String & context, const String &input, const String &type, int maxLength, bool allowNull) {
	return isValidInput(context, input, type, maxLength, allowNull, true);
}

bool DefaultValidator::isValidInput(const String & context, const String &input, const String &type, int maxLength, bool allowNull, ValidationErrorList &errors) {
	return isValidInput(context, input, type, maxLength, allowNull, true, errors);
}

bool DefaultValidator::isValidInput(const String &context, const String &input, const String &type, int maxLength, bool allowNull, bool canonicalize) {
	try {
		getValidInput( context, input, type, maxLength, allowNull, canonicalize);
		return true;
	} catch( std::exception& /*e*/ ) {
		return false;
	}
}

bool DefaultValidator::isValidInput(const String & context, const String & input, const String &type, int maxLength, bool allowNull, bool canonicalize, ValidationErrorList &errors) {
	try {
		getValidInput( context, input, type, maxLength, allowNull, canonicalize);
		return true;
	} catch( ValidationException& e ) {
		errors.addError( context, &e );
		return false;
	}
}

String DefaultValidator::getValidInput(const String &, const String &, const String &, int, bool) {
	throw UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

String DefaultValidator::getValidInput(const String &, const String &, const String &, int, bool, bool) {
	throw UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

String DefaultValidator::getValidInput(const String &, const String &, const String &, int, bool, ValidationErrorList&) {
	throw UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

String DefaultValidator::getValidInput(const String &, const String &, const String &, int, bool, bool, ValidationErrorList &) {
	throw UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

bool DefaultValidator::isValidDate(const String &, const String &, const DateFormat &, bool) {
	throw UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

bool DefaultValidator::isValidDate(const String &, const String &, const DateFormat &, bool, ValidationErrorList &) {
	throw UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

Char* DefaultValidator::getValidDate(const String &, const String &, const DateFormat &, bool) throw (ValidationException, IntrusionException) {
	throw UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

Char* DefaultValidator::getValidDate(const String &, const String &, const DateFormat &, bool, ValidationErrorList &) {
	throw UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

bool DefaultValidator::isValidSafeHTML(const String &, const String &, int, bool) {
	throw UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

bool DefaultValidator::isValidSafeHTML(const String &, const String &, int, bool, ValidationErrorList &) {
	throw UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

String DefaultValidator::getValidSafeHTML( const String &, const String &, int, bool) throw (ValidationException, IntrusionException) {
	throw UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

String DefaultValidator::getValidSafeHTML(const String &, const String &, int, bool, ValidationErrorList &) {
	throw UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

bool DefaultValidator::isValidCreditCard(const String &, const String &, bool) {
	throw UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

bool DefaultValidator::isValidCreditCard(const String &, const String &, bool, ValidationErrorList &) {
	throw UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

String DefaultValidator::getValidCreditCard(const String &, const String &, bool) throw (ValidationException, IntrusionException) {
	throw UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

String DefaultValidator::getValidCreditCard(const String &, const String &, bool, ValidationErrorList &) {
	throw UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

bool DefaultValidator::isValidDirectoryPath(const String &, const String &, std::fstream &, bool) {
	throw UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

bool DefaultValidator::isValidDirectoryPath(const String &, const String &, std::fstream &, bool, ValidationErrorList &) {
	throw UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

String DefaultValidator::getValidDirectoryPath(const String &, const String &, std::fstream &, bool) throw (ValidationException, IntrusionException) {
	throw UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

String DefaultValidator::getValidDirectoryPath(const String &, const String &, std::fstream &, bool, ValidationErrorList &)  {
	throw UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

bool DefaultValidator::isValidFileName(const String &, const String &, bool) {
	throw UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

bool DefaultValidator::isValidFileName(const String &, const String &, bool, ValidationErrorList &) {
	throw UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

bool DefaultValidator::isValidFileName(const String &, const String &, const std::list<String> &, bool) {
	throw UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

bool DefaultValidator::isValidFileName(const String &, const String &, const std::list<String> &, bool, ValidationErrorList &) {
	throw UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

String DefaultValidator::getValidFileName(const String &, const String &, const std::list<String> &, bool) throw (ValidationException, IntrusionException) {
	throw UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

String DefaultValidator::getValidFileName(const String &, const String &, const std::list<String> &, bool, ValidationErrorList &) {
	throw UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

bool DefaultValidator::isValidNumber(const String &, const String &, long, long, bool) {
	throw UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

bool DefaultValidator::isValidNumber(const String &, const String &, long, long, bool, ValidationErrorList &) {
	throw UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

double DefaultValidator::getValidNumber(const String &, const String &, long, long, bool) throw (ValidationException, IntrusionException) {
	throw UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

double DefaultValidator::getValidNumber(const String &, const String &, long, long, bool, ValidationErrorList &) {
	throw UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

bool DefaultValidator::isValidDouble(const String &, const String &, double, double, bool) {
	throw UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

bool DefaultValidator::isValidDouble(const String &, const String &, double, double, bool, ValidationErrorList &) {
	throw UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

double DefaultValidator::getValidDouble(const String &, const String &, double, double, bool) throw (ValidationException, IntrusionException) {
	throw UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

double DefaultValidator::getValidDouble(const String &, const String &, double, double, bool, ValidationErrorList &) {
	throw UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

bool DefaultValidator::isValidInteger(const String &, const String &, int, int, bool) {
	throw UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

bool DefaultValidator::isValidInteger(const String &, const String &, int, int, bool, ValidationErrorList &) {
	throw UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

int DefaultValidator::getValidInteger(const String &, const String &, int, int, bool) throw (ValidationException, IntrusionException) {
	throw UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

int DefaultValidator::getValidInteger(const String &, const String &, int, int, bool, ValidationErrorList &) {
	throw UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

bool DefaultValidator::isValidFileContent(const String &, Char[], int, bool) {
	throw UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

bool DefaultValidator::isValidFileContent(const String &, Char[], int, bool, ValidationErrorList &) {
	throw UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

Char* DefaultValidator::getValidFileContent(const String &, Char[], int, bool) throw (ValidationException, IntrusionException) {
	throw UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

Char* DefaultValidator::getValidFileContent(const String &, Char[], int, bool, ValidationErrorList &) {
	throw UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

bool DefaultValidator::isValidFileUpload(const String &, const String &, const String &, std::fstream &, Char[], int, bool) {
	throw UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

bool DefaultValidator::isValidFileUpload(const String &, const String &, const String &, std::fstream &, Char[], int, bool, ValidationErrorList &) {
	throw UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

void DefaultValidator::assertValidFileUpload(const String &, const String &, const String &, std::fstream &, Char[], int, const std::list<String> &, bool) {
	throw UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

void DefaultValidator::assertValidFileUpload(const String &, const String &, const String &, std::fstream &, Char[], int, const std::list<String> &, bool, ValidationErrorList &) {
	throw UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

bool DefaultValidator::isValidListItem(const String &, const String &, const std::list<String> &) {
	throw UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

bool DefaultValidator::isValidListItem(const String &, const String &, const std::list<String> &, ValidationErrorList &) {
	throw UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

String DefaultValidator::getValidListItem(const String &, const String &, const std::list<String> &) throw (ValidationException, IntrusionException) {
	throw UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

String DefaultValidator::getValidListItem(const String &, const String &, const std::list<String> &, ValidationErrorList &) {
	throw UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

bool DefaultValidator::isValidPrintable(const String &, Char[], int, bool) {
	throw UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

bool DefaultValidator::isValidPrintable(const String &, Char[], int, bool, ValidationErrorList &) {
	throw UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

Char* DefaultValidator::getValidPrintable(const String &, Char[], int, bool) throw (ValidationException, IntrusionException) {
	throw UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

Char* DefaultValidator::getValidPrintable(const String &, Char[], int, bool, ValidationErrorList &) {
	throw UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

bool DefaultValidator::isValidPrintable(const String &, const String &, int, bool) {
	throw UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

bool DefaultValidator::isValidPrintable(const String &, const String &, int, bool, ValidationErrorList &) {
	throw UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

String DefaultValidator::getValidPrintable(const String &, const String &, int, bool) throw (ValidationException, IntrusionException) {
	throw UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

String DefaultValidator::getValidPrintable(const String &, const String &, int, bool, ValidationErrorList &) {
	throw UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

String DefaultValidator::safeReadLine(std::fstream &, int) {
	throw UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

} // espai