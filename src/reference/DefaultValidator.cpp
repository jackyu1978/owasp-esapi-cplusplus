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

#include "Validator.h"
#include "Encoder.h"
#include "ValidationRule.h"
#include "reference/DefaultValidator.h"
#include "reference/validation/BaseValidationRule.h"

#include "errors/UnsupportedOperationException.h"


esapi::Validator* esapi::DefaultValidator::instance = nullptr;

//std::map<std::string, esapi::ValidationRule> esapi::DefaultValidator::rules;

//esapi::Encoder* esapi::DefaultValidator::encoder = nullptr;

esapi::Validator* esapi::DefaultValidator::fileValidator = nullptr;


bool esapi::DefaultValidator::isEmpty(const std::string &) const {
	throw new UnsupportedOperationException("Not yet implemented"); //TODO Implement
}


bool esapi::DefaultValidator::isEmpty(char[]) const {
	throw new UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

esapi::Validator* esapi::DefaultValidator::getInstance() {
	throw new UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

/** Initialize file validator with an appropriate set of codecs */
/*static {
	List<String> list = new ArrayList<String>();
	list.add( "HTMLEntityCodec" );
	list.add( "PercentCodec" );
	Encoder fileEncoder = new DefaultEncoder( list );
	fileValidator = new DefaultValidator( fileEncoder );
}*/


esapi::DefaultValidator::DefaultValidator()
	: rules(), encoder(nullptr)
{
	throw new UnsupportedOperationException("Not yet implemented"); //TODO Implement
}


esapi::DefaultValidator::DefaultValidator( const esapi::Encoder &)
	//: //rules(new std::map<std::string, esapi::ValidationRule*>),
	//  encoder(new esapi::Encoder)
{
	esapi::DefaultValidator::encoder = nullptr;
	throw new UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

//TODO must override to get rid of pointer member warning
esapi::DefaultValidator::DefaultValidator(const esapi::DefaultValidator&)
	//: //rules(new std::map<std::string, esapi::ValidationRule*>),
	//  encoder(new esapi::Encoder)
{
	esapi::DefaultValidator::encoder = nullptr;
	throw new UnsupportedOperationException("Not yet implemented"); //TODO Implement
}



void esapi::DefaultValidator::addRule( const esapi::ValidationRule & ) {
	throw new UnsupportedOperationException("Not yet implemented"); //TODO Implement
}


esapi::ValidationRule& esapi::DefaultValidator::getRule( const std::string & ) {
	throw new UnsupportedOperationException("Not yet implemented"); //TODO Implement
}


bool esapi::DefaultValidator::isValidInput(const std::string &, const std::string &, const std::string &, int, bool) throw (esapi::IntrusionException) {
	throw new UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

bool esapi::DefaultValidator::isValidInput(const std::string &, const std::string &, const std::string &, int, bool, esapi::ValidationErrorList &) throw (esapi::IntrusionException) {
	throw new UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

bool esapi::DefaultValidator::isValidInput(const std::string &, const std::string &, const std::string &, int, bool, bool) throw (esapi::IntrusionException) {
	throw new UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

bool esapi::DefaultValidator::isValidInput(const std::string &, const std::string &, const std::string &, int, bool, bool, esapi::ValidationErrorList &) throw (esapi::IntrusionException) {
	throw new UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

std::string esapi::DefaultValidator::getValidInput(const std::string &, const std::string &, const std::string &, int, bool) throw (esapi::ValidationException) {
	throw new UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

std::string esapi::DefaultValidator::getValidInput(const std::string &, const std::string &, const std::string &, int, bool, bool) throw (esapi::ValidationException) {
	throw new UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

std::string esapi::DefaultValidator::getValidInput(const std::string &, const std::string &, const std::string &, int, bool, esapi::ValidationErrorList&) throw (esapi::IntrusionException) {
	throw new UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

std::string esapi::DefaultValidator::getValidInput(const std::string &, const std::string &, const std::string &, int, bool, bool, esapi::ValidationErrorList &) throw (esapi::IntrusionException) {
	throw new UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

bool esapi::DefaultValidator::isValidDate(const std::string &, const std::string &, const DateFormat &, bool) throw (esapi::IntrusionException) {
	throw new UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

bool esapi::DefaultValidator::isValidDate(const std::string &, const std::string &, const DateFormat &, bool, esapi::ValidationErrorList &) throw (esapi::IntrusionException) {
	throw new UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

char* esapi::DefaultValidator::getValidDate(const std::string &, const std::string &, const DateFormat &, bool) throw (esapi::ValidationException, esapi::IntrusionException) {
	throw new UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

char* esapi::DefaultValidator::getValidDate(const std::string &, const std::string &, const DateFormat &, bool, esapi::ValidationErrorList &) throw (esapi::IntrusionException) {
	throw new UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

bool esapi::DefaultValidator::isValidSafeHTML(const std::string &, const std::string &, int, bool) throw (esapi::IntrusionException) {
	throw new UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

bool esapi::DefaultValidator::isValidSafeHTML(const std::string &, const std::string &, int, bool, esapi::ValidationErrorList &) throw (esapi::IntrusionException) {
	throw new UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

std::string esapi::DefaultValidator::getValidSafeHTML( const std::string &, const std::string &, int, bool) throw (esapi::ValidationException, esapi::IntrusionException) {
	throw new UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

std::string esapi::DefaultValidator::getValidSafeHTML(const std::string &, const std::string &, int, bool, esapi::ValidationErrorList &) throw (esapi::IntrusionException) {
	throw new UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

bool esapi::DefaultValidator::isValidCreditCard(const std::string &, const std::string &, bool) throw (esapi::IntrusionException) {
	throw new UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

bool esapi::DefaultValidator::isValidCreditCard(const std::string &, const std::string &, bool, esapi::ValidationErrorList &) throw (esapi::IntrusionException) {
	throw new UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

std::string esapi::DefaultValidator::getValidCreditCard(const std::string &, const std::string &, bool) throw (esapi::ValidationException, esapi::IntrusionException) {
	throw new UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

std::string esapi::DefaultValidator::getValidCreditCard(const std::string &, const std::string &, bool, esapi::ValidationErrorList &) throw (esapi::IntrusionException) {
	throw new UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

bool esapi::DefaultValidator::isValidDirectoryPath(const std::string &, const std::string &, std::fstream &, bool) throw (esapi::IntrusionException) {
	throw new UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

bool esapi::DefaultValidator::isValidDirectoryPath(const std::string &, const std::string &, std::fstream &, bool, esapi::ValidationErrorList &) throw (esapi::IntrusionException) {
	throw new UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

std::string esapi::DefaultValidator::getValidDirectoryPath(const std::string &, const std::string &, std::fstream &, bool) throw (esapi::ValidationException, esapi::IntrusionException) {
	throw new UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

std::string esapi::DefaultValidator::getValidDirectoryPath(const std::string &, const std::string &, std::fstream &, bool, esapi::ValidationErrorList &) throw (esapi::IntrusionException)  {
	throw new UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

bool esapi::DefaultValidator::isValidFileName(const std::string &, const std::string &, bool) throw (esapi::IntrusionException) {
	throw new UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

bool esapi::DefaultValidator::isValidFileName(const std::string &, const std::string &, bool, esapi::ValidationErrorList &) throw (esapi::IntrusionException) {
	throw new UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

bool esapi::DefaultValidator::isValidFileName(const std::string &, const std::string &, const std::list<std::string> &, bool) throw (esapi::IntrusionException) {
	throw new UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

bool esapi::DefaultValidator::isValidFileName(const std::string &, const std::string &, const std::list<std::string> &, bool, esapi::ValidationErrorList &) throw (esapi::IntrusionException) {
	throw new UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

std::string esapi::DefaultValidator::getValidFileName(const std::string &, const std::string &, const std::list<std::string> &, bool) throw (esapi::ValidationException, esapi::IntrusionException) {
	throw new UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

std::string esapi::DefaultValidator::getValidFileName(const std::string &, const std::string &, const std::list<std::string> &, bool, esapi::ValidationErrorList &) throw (esapi::IntrusionException) {
	throw new UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

bool esapi::DefaultValidator::isValidNumber(const std::string &, const std::string &, long, long, bool) throw (esapi::IntrusionException) {
	throw new UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

bool esapi::DefaultValidator::isValidNumber(const std::string &, const std::string &, long, long, bool, esapi::ValidationErrorList &) throw (esapi::IntrusionException) {
	throw new UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

double esapi::DefaultValidator::getValidNumber(const std::string &, const std::string &, long, long, bool) throw (esapi::ValidationException, esapi::IntrusionException) {
	throw new UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

double esapi::DefaultValidator::getValidNumber(const std::string &, const std::string &, long, long, bool, esapi::ValidationErrorList &) throw (esapi::IntrusionException) {
	throw new UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

bool esapi::DefaultValidator::isValidDouble(const std::string &, const std::string &, double, double, bool) throw (esapi::IntrusionException) {
	throw new UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

bool esapi::DefaultValidator::isValidDouble(const std::string &, const std::string &, double, double, bool, esapi::ValidationErrorList &) throw (esapi::IntrusionException) {
	throw new UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

double esapi::DefaultValidator::getValidDouble(const std::string &, const std::string &, double, double, bool) throw (esapi::ValidationException, esapi::IntrusionException) {
	throw new UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

double esapi::DefaultValidator::getValidDouble(const std::string &, const std::string &, double, double, bool, esapi::ValidationErrorList &) throw (esapi::IntrusionException) {
	throw new UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

bool esapi::DefaultValidator::isValidInteger(const std::string &, const std::string &, int, int, bool) throw (esapi::IntrusionException) {
	throw new UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

bool esapi::DefaultValidator::isValidInteger(const std::string &, const std::string &, int, int, bool, esapi::ValidationErrorList &) throw (esapi::IntrusionException) {
	throw new UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

int esapi::DefaultValidator::getValidInteger(const std::string &, const std::string &, int, int, bool) throw (esapi::ValidationException, esapi::IntrusionException) {
	throw new UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

int esapi::DefaultValidator::getValidInteger(const std::string &, const std::string &, int, int, bool, esapi::ValidationErrorList &) throw (esapi::IntrusionException) {
	throw new UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

bool esapi::DefaultValidator::isValidFileContent(const std::string &, char[], int, bool) throw (esapi::IntrusionException) {
	throw new UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

bool esapi::DefaultValidator::isValidFileContent(const std::string &, char[], int, bool, esapi::ValidationErrorList &) throw (esapi::IntrusionException) {
	throw new UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

char* esapi::DefaultValidator::getValidFileContent(const std::string &, char[], int, bool) throw (esapi::ValidationException, esapi::IntrusionException) {
	throw new UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

char* esapi::DefaultValidator::getValidFileContent(const std::string &, char[], int, bool, esapi::ValidationErrorList &) throw (esapi::IntrusionException) {
	throw new UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

bool esapi::DefaultValidator::isValidFileUpload(const std::string &, const std::string &, const std::string &, std::fstream &, char[], int, bool) throw (esapi::IntrusionException) {
	throw new UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

bool esapi::DefaultValidator::isValidFileUpload(const std::string &, const std::string &, const std::string &, std::fstream &, char[], int, bool, esapi::ValidationErrorList &) throw (esapi::IntrusionException) {
	throw new UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

void esapi::DefaultValidator::assertValidFileUpload(const std::string &, const std::string &, const std::string &, std::fstream &, char[], int, const std::list<std::string> &, bool) throw(esapi::ValidationException, esapi::IntrusionException) {
	throw new UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

void esapi::DefaultValidator::assertValidFileUpload(const std::string &, const std::string &, const std::string &, std::fstream &, char[], int, const std::list<std::string> &, bool, esapi::ValidationErrorList &) throw (esapi::IntrusionException) {
	throw new UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

bool esapi::DefaultValidator::isValidListItem(const std::string &, const std::string &, const std::list<std::string> &) throw (esapi::IntrusionException) {
	throw new UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

bool esapi::DefaultValidator::isValidListItem(const std::string &, const std::string &, const std::list<std::string> &, esapi::ValidationErrorList &) throw (esapi::IntrusionException) {
	throw new UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

std::string esapi::DefaultValidator::getValidListItem(const std::string &, const std::string &, const std::list<std::string> &) throw (esapi::ValidationException, esapi::IntrusionException) {
	throw new UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

std::string esapi::DefaultValidator::getValidListItem(const std::string &, const std::string &, const std::list<std::string> &, esapi::ValidationErrorList &) throw (esapi::IntrusionException) {
	throw new UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

bool esapi::DefaultValidator::isValidPrintable(const std::string &, char[], int, bool) throw (esapi::IntrusionException) {
	throw new UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

bool esapi::DefaultValidator::isValidPrintable(const std::string &, char[], int, bool, esapi::ValidationErrorList &) throw (esapi::IntrusionException) {
	throw new UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

char* esapi::DefaultValidator::getValidPrintable(const std::string &, char[], int, bool) throw (esapi::ValidationException, esapi::IntrusionException) {
	throw new UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

char* esapi::DefaultValidator::getValidPrintable(const std::string &, char[], int, bool, esapi::ValidationErrorList &) throw (esapi::IntrusionException) {
	throw new UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

bool esapi::DefaultValidator::isValidPrintable(const std::string &, const std::string &, int, bool) throw (esapi::IntrusionException) {
	throw new UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

bool esapi::DefaultValidator::isValidPrintable(const std::string &, const std::string &, int, bool, esapi::ValidationErrorList &) throw (esapi::IntrusionException) {
	throw new UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

std::string esapi::DefaultValidator::getValidPrintable(const std::string &, const std::string &, int, bool) throw (esapi::ValidationException, esapi::IntrusionException) {
	throw new UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

std::string esapi::DefaultValidator::getValidPrintable(const std::string &, const std::string &, int, bool, esapi::ValidationErrorList &) throw (esapi::IntrusionException) {
	throw new UnsupportedOperationException("Not yet implemented"); //TODO Implement
}

std::string esapi::DefaultValidator::safeReadLine(std::fstream &, int) throw (esapi::ValidationException) {
	throw new UnsupportedOperationException("Not yet implemented"); //TODO Implement
}
