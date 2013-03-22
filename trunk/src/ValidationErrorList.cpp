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
#include "errors/IllegalArgumentException.h"

namespace esapi
{
  void ValidationErrorList::addError(const NarrowString &context, ValidationException *vex) {
    if ( context.empty() ) {
      // throw( "Context for cannot be null: " + vex->getLogMessage() );
      throw IllegalArgumentException("Context for cannot be nul");
    }

	  //if ( vex == NULL ) throw( "Context (" + context + ") cannot be nul" );
    if (getError(context) != NULL) {
      // throw ("Context (" + context + ") already exists, must be unique");
      throw IllegalArgumentException("Context must be unique");
    }

	  m_errorList.insert( std::pair<String, ValidationException *>(context, vex) );
  }

  std::list<ValidationException *> ValidationErrorList::errors(){
	  std::list<ValidationException *> errs;
	  std::map<String, ValidationException *>::iterator it;

	  for ( it = m_errorList.begin(); it != m_errorList.end(); it++ )
		  errs.push_back( (*it).second );

	  return errs;
  }

  ValidationException *ValidationErrorList::getError(const NarrowString &context){
	  if (context.compare("")) return NULL;
	  //ValidationException *foo = new ValidationException("foo","bar");
	  return m_errorList.find(context)->second;
  }

  bool ValidationErrorList::isEmpty() const{
	  return m_errorList.empty();
  }

  size_t ValidationErrorList::size() const{
	  return m_errorList.size();
  }
} // esapi
