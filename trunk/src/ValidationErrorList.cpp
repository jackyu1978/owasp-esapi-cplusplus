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
 * @author Dan Amodio (dan.amodio@aspectsecurity.com)
 *
 * @created 2007
 */

#include "ValidationErrorList.h"

void esapi::ValidationErrorList::addError(const std::string &context, esapi::ValidationException *vex) {
	if ( context.compare("") ) throw( "Context for cannot be null: " + vex->getLogMessage() );
	//if ( vex == NULL ) throw( "Context (" + context + ") cannot be null" );
	if (getError(context) != NULL) throw ("Context (" + context + ") already exists, must be unique");
	this->errorList.insert( std::pair<std::string, ValidationException *>(context, vex) );
}

std::list<esapi::ValidationException *> esapi::ValidationErrorList::errors(){
	std::list<esapi::ValidationException *> errors;
	std::map<std::string, esapi::ValidationException *>::iterator it;

	for ( it = errorList.begin(); it != errorList.end(); it++ )
		errors.push_back( (*it).second );

	return errors;
}

esapi::ValidationException *esapi::ValidationErrorList::getError(const std::string &context){
	if (context.compare("")) return NULL;
	//esapi::ValidationException *foo = new esapi::ValidationException("foo","bar");
	return errorList.find(context)->second;
}

bool esapi::ValidationErrorList::isEmpty() const{
	return errorList.empty();
}

size_t esapi::ValidationErrorList::size() const{
	return errorList.size();
}

