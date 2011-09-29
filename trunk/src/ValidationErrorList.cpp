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
#include "errors/InvalidArgumentException.h"

namespace esapi
{
  void ValidationErrorList::addError(const String &context, ValidationException *vex) {
    if ( context.empty() ) {
      // throw( "Context for cannot be null: " + vex->getLogMessage() );
      throw InvalidArgumentException("Context for cannot be null");
    }

	  //if ( vex == NULL ) throw( "Context (L" + context + ") cannot be null" );
    if (getError(context) != NULL) {
      // throw (L"Context (L" + context + ") already exists, must be unique");
      throw InvalidArgumentException("Context must be unique");
    }

	  this->errorList.insert( std::pair<String, ValidationException *>(context, vex) );
  }

  std::list<ValidationException *> ValidationErrorList::errors(){
	  std::list<ValidationException *> errors;
	  std::map<String, ValidationException *>::iterator it;

	  for ( it = errorList.begin(); it != errorList.end(); it++ )
		  errors.push_back( (*it).second );

	  return errors;
  }

  ValidationException *ValidationErrorList::getError(const String &context){
	  if (context.compare(L"")) return NULL;
	  //ValidationException *foo = new ValidationException("foo",L"bar");
	  return errorList.find(context)->second;
  }

  bool ValidationErrorList::isEmpty() const{
	  return errorList.empty();
  }

  size_t ValidationErrorList::size() const{
	  return errorList.size();
  }
} // esapi
