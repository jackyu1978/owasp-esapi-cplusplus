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

#pragma once

#include "EsapiCommon.h"
#include "errors/ValidationException.h"

#include <string>
#include <map>
#include <list>

/**
 * The ValidationErrorList class defines a well-formed collection of
 * ValidationExceptions so that groups of validation functions can be
 * called in a non-blocking fashion.
 * <P>
 * To use the ValidationErrorList to execute groups of validation
 * attempts, your controller code would look something like:
 *
 * <PRE>
 * ValidationErrorList() errorList = new ValidationErrorList();.
 * String name  = getValidInput("Name", form.getName(), "SomeESAPIRegExName1", 255, false, errorList);
 * String address = getValidInput("Address", form.getAddress(), "SomeESAPIRegExName2", 255, false, errorList);
 * Integer weight = getValidInteger("Weight", form.getWeight(), 1, 1000000000, false, errorList);
 * Integer sortOrder = getValidInteger("Sort Order", form.getSortOrder(), -100000, +100000, false, errorList);
 * request.setAttribute( "ERROR_LIST", errorList );
 * </PRE>
 *
 * The at your view layer you would be able to retrieve all
 * of your error messages via a helper function like:
 *
 * <PRE>
 * public static ValidationErrorList getErrors() {
 *     HttpServletRequest request = ESAPI.httpUtilities().getCurrentRequest();
 *     ValidationErrorList errors = new ValidationErrorList();
 *     if (request.getAttribute(Constants.ERROR_LIST) != null) {
 *        errors = (ValidationErrorList)request.getAttribute("ERROR_LIST");
 *     }
 * 	   return errors;
 * }
 * </PRE>
 *
 * You can list all errors like:
 *
 * <PRE>
 * <%
 *      for (Object vo : errorList.errors()) {
 *         ValidationException ve = (ValidationException)vo;
 * %>
 * <%= ESAPI.encoder().encodeForHTML(ve.getMessage()) %><br/>
 * <%
 *     }
 * %>
 * </PRE>
 *
 * And even check if a specific UI component is in error via calls like:
 *
 * <PRE>
 * ValidationException e = errorList.getError("Name");
 * </PRE>
 *
 * @author Jim Manico (jim@manico.net) <a href="http://www.manico.net">Manico.net</a>
 * @since August 15, 2008
 */
namespace esapi {
	class ESAPI_EXPORT ValidationErrorList {

	private:
		/**
		 * Error list of ValidationException's
		 */
		//private HashMap<String, ValidationException> errorList = new HashMap<String, ValidationException>();
		//std::hash_map<const NarrowString, ValidationException*, hash<const NarrowString>, eqstr> errorList;
		std::map<String, ValidationException *> m_errorList;

	public:
		ValidationErrorList() : m_errorList() {};


		/**
		 * Adds a new error to list with a unique named context.
		 * No action taken if either element is null.
		 * Existing contexts will be overwritten.
		 *
		 * @param context Unique named context for this {@code ValidationErrorList}.
		 * @param vex	A {@code ValidationException}.
		 */
		virtual void addError(const NarrowString &, ValidationException *);


		/**
		 * Returns list of ValidationException, or empty list if no errors exist.
		 *
		 * @return List
		 */
		virtual std::list<ValidationException *> errors();

		/**
		 * Retrieves ValidationException for given context if one exists.
		 *
		 * @param context unique name for each error
		 * @return ValidationException or null for given context
		 */
		virtual ValidationException *getError(const NarrowString &);

		/**
		 * Returns true if no error are present.
		 *
		 * @return bool
		 */
		virtual bool isEmpty( ) const;

		/**
		 * Returns the numbers of errors present.
		 *
		 * @return int
		 */
		virtual size_t size() const;

		virtual ~ValidationErrorList() {};
	};
} // NAMESPACE

