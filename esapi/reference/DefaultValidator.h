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

#pragma once

#include "Validator.h"

#include <exception>
#include "errors/ValidationException.h"
#include "errors/IntrusionException.h"

#include <map>
#include <string>

#include <boost/shared_ptr.hpp>

namespace esapi {
/**
 * Reference implementation of the Validator interface. This implementation
 * relies on the ESAPI Encoder, Java Pattern (regex), Date,
 * and several other classes to provide basic validation functions. This library
 * has a heavy emphasis on whitelist validation and canonicalization.
 *
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @author Jim Manico (jim@manico.net) <a href="http://www.manico.net">Manico.net</a>
 *
 * @since June 1, 2007
 * @see org.owasp.esapi.Validator
 */
class ESAPI_EXPORT DefaultValidator : public Validator {
private:

	static Validator* instance;

	/** A map of validation rules */
	std::map<std::string, const ValidationRule<void*>* > rules;

	/** The encoder to use for canonicalization */
	boost::shared_ptr<Encoder> encoder;

	/** Initialize file validator with an appropriate set of codecs */
	void initFileValidator();

	/** The encoder to use for file system */
	static Validator* fileValidator;


	/**
	 * Helper function to check if a String is empty
	 *
	 * @param input string input value
	 * @return boolean response if input is empty or not
	 */
	bool isEmpty(const std::string &) const ;

	/**
	 * Helper function to check if a byte array is empty
	 *
	 * @param input string input value
	 * @return boolean response if input is empty or not
	 */
	//bool isEmpty(byte[]) const;


	/**
	 * Helper function to check if a char array is empty
	 *
	 * @param input string input value
	 * @return boolean response if input is empty or not
	 */
	bool isEmpty(char[]) const;

public:
	static Validator* getInstance();

	/** Initialize file validator with an appropriate set of codecs */
	/*static {
		List<String> list = new ArrayList<String>();
		list.add( "HTMLEntityCodec" );
		list.add( "PercentCodec" );
		Encoder fileEncoder = new DefaultEncoder( list );
		fileValidator = new DefaultValidator( fileEncoder );
	}*/


	/**
	 * Default constructor uses the ESAPI standard encoder for canonicalization.
	 */
	DefaultValidator();

	/**
	 * Construct a new DefaultValidator that will use the specified
	 * Encoder for canonicalization.
     *
     * @param encoder
     */
	DefaultValidator(Encoder *);

	// must override to get rid of pointer member warning
	DefaultValidator(const esapi::DefaultValidator&);
	DefaultValidator& operator=(const esapi::DefaultValidator&);

	/**
	 * Add a validation rule to the registry using the "type name" of the rule as the key.
	 */
	void addRule( const ValidationRule<void*> & );

	/**
	 * Get a validation rule from the registry with the "type name" of the rule as the key.
	 */
	ValidationRule<void*>& getRule( const std::string & );

	/**
	 * Returns true if data received from browser is valid. Double encoding is treated as an attack. The
	 * default encoder supports html encoding, URL encoding, and javascript escaping. Input is canonicalized
	 * by default before validation.
	 *
	 * @param context A descriptive name for the field to validate. This is used for error facing validation messages and element identification.
	 * @param input The actual user input data to validate.
	 * @param type The regular expression name while maps to the actual regular expression from "ESAPI.properties".
	 * @param maxLength The maximum post-canonicalized String length allowed.
	 * @param allowNull If allowNull is true then a input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
	 * @return The canonicalized user input.
	 * @throws IntrusionException
	 */
	bool isValidInput(const std::string &, const std::string &, const std::string &, int, bool);

	bool isValidInput(const std::string &, const std::string &, const std::string &, int, bool, ValidationErrorList &);

	bool isValidInput(const std::string &, const std::string &, const std::string &, int, bool, bool);

	bool isValidInput(const std::string &, const std::string &, const std::string &, int, bool, bool, ValidationErrorList &);

	/**
	 * Validates data received from the browser and returns a safe version.
	 * Double encoding is treated as an attack. The default encoder supports
	 * html encoding, URL encoding, and javascript escaping. Input is
	 * canonicalized by default before validation.
	 *
	 * @param context A descriptive name for the field to validate. This is used for error facing validation messages and element identification.
	 * @param input The actual user input data to validate.
	 * @param type The regular expression name which maps to the actual regular expression from "ESAPI.properties".
	 * @param maxLength The maximum post-canonicalized String length allowed.
	 * @param allowNull If allowNull is true then a input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
	 * @return The canonicalized user input.
	 * @throws ValidationException
	 * @throws IntrusionException
	 */
	std::string getValidInput(const std::string &, const std::string &, const std::string &, int, bool);

	/**
	 * Validates data received from the browser and returns a safe version. Only
	 * URL encoding is supported. Double encoding is treated as an attack.
	 *
	 * @param context A descriptive name for the field to validate. This is used for error facing validation messages and element identification.
	 * @param input The actual user input data to validate.
	 * @param type The regular expression name which maps to the actual regular expression in the ESAPI validation configuration file
	 * @param maxLength The maximum String length allowed. If input is canonicalized per the canonicalize argument, then maxLength must be verified after canonicalization
     * @param allowNull If allowNull is true then a input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
	 * @param canonicalize If canonicalize is true then input will be canonicalized before validation
	 * @return The user input, may be canonicalized if canonicalize argument is true
	 * @throws ValidationException
	 * @throws IntrusionException
	 */
	std::string getValidInput(const std::string &, const std::string &, const std::string &, int, bool, bool);

	/**
	 * Validates data received from the browser and returns a safe version. Only
	 * URL encoding is supported. Double encoding is treated as an attack. Input
	 * is canonicalized by default before validation.
	 *
	 * @param context A descriptive name for the field to validate. This is used for error facing validation messages and element identification.
	 * @param input The actual user input data to validate.
	 * @param type The regular expression name while maps to the actual regular expression from "ESAPI.properties".
	 * @param maxLength The maximum String length allowed. If input is canonicalized per the canonicalize argument, then maxLength must be verified after canonicalization
	 * @param allowNull If allowNull is true then a input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
	 * @param errors If ValidationException is thrown, then add to error list instead of throwing out to caller
	 * @return The canonicalized user input.
	 * @throws IntrusionException
	 */
	std::string getValidInput(const std::string &, const std::string &, const std::string &, int, bool, ValidationErrorList&);

	/**
	 * Validates data received from the browser and returns a safe version. Only
	 * URL encoding is supported. Double encoding is treated as an attack.
	 *
	 * @param context A descriptive name for the field to validate. This is used for error facing validation messages and element identification.
	 * @param input The actual user input data to validate.
	 * @param type The regular expression name while maps to the actual regular expression from "ESAPI.properties".
	 * @param maxLength The maximum post-canonicalized String length allowed
	 * @param allowNull If allowNull is true then a input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
	 * @param canonicalize If canonicalize is true then input will be canonicalized before validation
	 * @param errors If ValidationException is thrown, then add to error list instead of throwing out to caller
	 * @return The user input, may be canonicalized if canonicalize argument is true
	 * @throws IntrusionException
	 */
	std::string getValidInput(const std::string &, const std::string &, const std::string &, int, bool, bool, ValidationErrorList &);

	/**
	 * {@inheritDoc}
	 */
	bool isValidDate(const std::string &, const std::string &, const DateFormat &, bool);

        /**
	 * {@inheritDoc}
	 */
	bool isValidDate(const std::string &, const std::string &, const DateFormat &, bool, ValidationErrorList &);

	/**
	 * {@inheritDoc}
	 * TODO this should end up returning boost::gregorian::date
	 */
	char* getValidDate(const std::string &, const std::string &, const DateFormat &, bool) throw (ValidationException, IntrusionException);

	/**
	 * {@inheritDoc}
	 */
	char* getValidDate(const std::string &, const std::string &, const DateFormat &, bool, ValidationErrorList &);

	/**
	 * {@inheritDoc}
	 */
	bool isValidSafeHTML(const std::string &, const std::string &, int, bool);

   /**
	 * {@inheritDoc}
	 */
	bool isValidSafeHTML(const std::string &, const std::string &, int, bool, ValidationErrorList &);

	/**
	 * {@inheritDoc}
	 *
	 * This implementation relies on the OWASP AntiSamy project.
	 */
	std::string getValidSafeHTML( const std::string &, const std::string &, int, bool) throw (ValidationException, IntrusionException);

	/**
	 * {@inheritDoc}
	 */
	std::string getValidSafeHTML(const std::string &, const std::string &, int, bool, ValidationErrorList &);

	/**
	 * {@inheritDoc}
	 */
	bool isValidCreditCard(const std::string &, const std::string &, bool);

   /**
	 * {@inheritDoc}
	 */
	bool isValidCreditCard(const std::string &, const std::string &, bool, ValidationErrorList &);

	/**
	 * {@inheritDoc}
	 */
	std::string getValidCreditCard(const std::string &, const std::string &, bool) throw (ValidationException, IntrusionException);

	/**
	 * {@inheritDoc}
	 */
	std::string getValidCreditCard(const std::string &, const std::string &, bool, ValidationErrorList &);

	/**
	 * {@inheritDoc}
	 *
	 * <p><b>Note:</b> On platforms that support symlinks, this function will fail canonicalization if directorypath
	 * is a symlink. For example, on MacOS X, /etc is actually /private/etc. If you mean to use /etc, use its real
	 * path (/private/etc), not the symlink (/etc).</p>
	 */
	bool isValidDirectoryPath(const std::string &, const std::string &, std::fstream &, bool);

        /**
	 * {@inheritDoc}
	 *
	 * <p><b>Note:</b> On platforms that support symlinks, this function will fail canonicalization if directorypath
	 * is a symlink. For example, on MacOS X, /etc is actually /private/etc. If you mean to use /etc, use its real
	 * path (/private/etc), not the symlink (/etc).</p>
	 */
	bool isValidDirectoryPath(const std::string &, const std::string &, std::fstream &, bool, ValidationErrorList &);

	/**
	 * {@inheritDoc}
	 */
	std::string getValidDirectoryPath(const std::string &, const std::string &, std::fstream &, bool) throw (ValidationException, IntrusionException);

	/**
	 * {@inheritDoc}
	 */
	std::string getValidDirectoryPath(const std::string &, const std::string &, std::fstream &, bool, ValidationErrorList &);


	/**
	 * {@inheritDoc}
	 */
	bool isValidFileName(const std::string &, const std::string &, bool);

    /**
	 * {@inheritDoc}
	 */
	bool isValidFileName(const std::string &, const std::string &, bool, ValidationErrorList &);

	/**
	 * {@inheritDoc}
	 */
	bool isValidFileName(const std::string &, const std::string &, const std::list<std::string> &, bool);

    /**
	 * {@inheritDoc}
	 */
	bool isValidFileName(const std::string &, const std::string &, const std::list<std::string> &, bool, ValidationErrorList &);

	/**
	 * {@inheritDoc}
	 */
	std::string getValidFileName(const std::string &, const std::string &, const std::list<std::string> &, bool) throw (ValidationException, IntrusionException);

	/**
	 * {@inheritDoc}
	 */
	std::string getValidFileName(const std::string &, const std::string &, const std::list<std::string> &, bool, ValidationErrorList &);

	/**
	 * {@inheritDoc}
	 */
	bool isValidNumber(const std::string &, const std::string &, long, long, bool);

    /**
	 * {@inheritDoc}
	 */
	bool isValidNumber(const std::string &, const std::string &, long, long, bool, ValidationErrorList &);

	/**
	 * {@inheritDoc}
	 */
	double getValidNumber(const std::string &, const std::string &, long, long, bool) throw (ValidationException, IntrusionException);

	/**
	 * {@inheritDoc}
	 */
	double getValidNumber(const std::string &, const std::string &, long, long, bool, ValidationErrorList &);

	/**
	 * {@inheritDoc}
	 */
	bool isValidDouble(const std::string &, const std::string &, double, double, bool);

    /**
	 * {@inheritDoc}
	 */
	bool isValidDouble(const std::string &, const std::string &, double, double, bool, ValidationErrorList &);

	/**
	 * {@inheritDoc}
	 */
	double getValidDouble(const std::string &, const std::string &, double, double, bool) throw (ValidationException, IntrusionException);

	/**
	 * {@inheritDoc}
	 */
	double getValidDouble(const std::string &, const std::string &, double, double, bool, ValidationErrorList &);

	/**
	 * {@inheritDoc}
	 */
	bool isValidInteger(const std::string &, const std::string &, int, int, bool);

    /**
	 * {@inheritDoc}
	 */
	bool isValidInteger(const std::string &, const std::string &, int, int, bool, ValidationErrorList &);

	/**
	 * {@inheritDoc}
	 */
	int getValidInteger(const std::string &, const std::string &, int, int, bool) throw (ValidationException, IntrusionException);

	/**
	 * {@inheritDoc}
	 */
	int getValidInteger(const std::string &, const std::string &, int, int, bool, ValidationErrorList &);

	/**
	 * {@inheritDoc}
	 */
	bool isValidFileContent(const std::string &, char[], int, bool);

        /**
	 * {@inheritDoc}
	 */
	bool isValidFileContent(const std::string &, char[], int, bool, ValidationErrorList &);

	/**
	 * {@inheritDoc}
	 */
	char* getValidFileContent(const std::string &, char[], int, bool) throw (ValidationException, IntrusionException);

	/**
	 * {@inheritDoc}
	 */
	char* getValidFileContent(const std::string &, char[], int, bool, ValidationErrorList &);

	/**
	 * {@inheritDoc}
	 *
	 * <p><b>Note:</b> On platforms that support symlinks, this function will fail canonicalization if directorypath
	 * is a symlink. For example, on MacOS X, /etc is actually /private/etc. If you mean to use /etc, use its real
	 * path (/private/etc), not the symlink (/etc).</p>
     */
	bool isValidFileUpload(const std::string &, const std::string &, const std::string &, std::fstream &, char[], int, bool);

    /**
	 * {@inheritDoc}
	 *
	 * <p><b>Note:</b> On platforms that support symlinks, this function will fail canonicalization if directorypath
	 * is a symlink. For example, on MacOS X, /etc is actually /private/etc. If you mean to use /etc, use its real
	 * path (/private/etc), not the symlink (/etc).</p>
     */
	bool isValidFileUpload(const std::string &, const std::string &, const std::string &, std::fstream &, char[], int, bool, ValidationErrorList &);

	/**
	 * {@inheritDoc}
	 */
	void assertValidFileUpload(const std::string &, const std::string &, const std::string &, std::fstream &, char[], int, const std::list<std::string> &, bool);

	/**
	 * {@inheritDoc}
	 */
	void assertValidFileUpload(const std::string &, const std::string &, const std::string &, std::fstream &, char[], int, const std::list<std::string> &, bool, ValidationErrorList &);

	 /**
	 * {@inheritDoc}
	 *
	 * Returns true if input is a valid list item.
	 */
	bool isValidListItem(const std::string &, const std::string &, const std::list<std::string> &);

    /**
	 * {@inheritDoc}
	 *
	 * Returns true if input is a valid list item.
	 */
	bool isValidListItem(const std::string &, const std::string &, const std::list<std::string> &, ValidationErrorList &);

	/**
	 * Returns the list item that exactly matches the canonicalized input. Invalid or non-matching input
	 * will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException.
	 */
	std::string getValidListItem(const std::string &, const std::string &, const std::list<std::string> &) throw (ValidationException, IntrusionException);

	/**
	 * ValidationErrorList variant of getValidListItem
     *
     * @param errors
     */
	std::string getValidListItem(const std::string &, const std::string &, const std::list<std::string> &, ValidationErrorList &);

	 /**
	 * {@inheritDoc}
     */
	//bool isValidHTTPRequestParameterSet(const std::string &, HttpServletRequest request, Set<String> requiredNames, Set<String> optionalNames);

         /**
	 * {@inheritDoc}
     */
	//public boolean isValidHTTPRequestParameterSet(String context, HttpServletRequest request, Set<String> requiredNames, Set<String> optionalNames, ValidationErrorList errors);

	/**
	 * Validates that the parameters in the current request contain all required parameters and only optional ones in
	 * addition. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException.
	 *
	 * Uses current HTTPRequest
	 */
	//public void assertValidHTTPRequestParameterSet(String context, HttpServletRequest request, Set<String> required, Set<String> optional) throws ValidationException, IntrusionException ;

	/**
	 * ValidationErrorList variant of assertIsValidHTTPRequestParameterSet
     *
	 * Uses current HTTPRequest saved in ESAPI Authenticator
     * @param errors
     */
	//public void assertValidHTTPRequestParameterSet(String context, HttpServletRequest request, Set<String> required, Set<String> optional, ValidationErrorList errors) throws IntrusionException ;

	/**
     * {@inheritDoc}
     *
	 * Checks that all bytes are valid ASCII characters (between 33 and 126
	 * inclusive). This implementation does no decoding. http://en.wikipedia.org/wiki/ASCII.
	 */
	bool isValidPrintable(const std::string &, char[], int, bool);

    /**
     * {@inheritDoc}
     *
	 * Checks that all bytes are valid ASCII characters (between 33 and 126
	 * inclusive). This implementation does no decoding. http://en.wikipedia.org/wiki/ASCII.
	 */
	bool isValidPrintable(const std::string &, char[], int, bool, ValidationErrorList &);

	/**
	 * Returns canonicalized and validated printable characters as a byte array. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException.
     *
     * @throws IntrusionException
     */
	char* getValidPrintable(const std::string &, char[], int, bool) throw (ValidationException, IntrusionException);

	/**
	 * ValidationErrorList variant of getValidPrintable
     *
     * @param errors
     */
	char* getValidPrintable(const std::string &, char[], int, bool, ValidationErrorList &);


	 /**
	 * {@inheritDoc}
	 *
	 * Returns true if input is valid printable ASCII characters (32-126).
	 */
	bool isValidPrintable(const std::string &, const std::string &, int, bool);

    /**
	 * {@inheritDoc}
	 *
	 * Returns true if input is valid printable ASCII characters (32-126).
	 */
	bool isValidPrintable(const std::string &, const std::string &, int, bool, ValidationErrorList &);

	/**
	 * Returns canonicalized and validated printable characters as a String. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException.
     *
     * @throws IntrusionException
     */
	std::string getValidPrintable(const std::string &, const std::string &, int, bool) throw (ValidationException, IntrusionException);

	/**
	 * ValidationErrorList variant of getValidPrintable
     *
     * @param errors
     */
	std::string getValidPrintable(const std::string &, const std::string &, int, bool, ValidationErrorList &);


	/**
	 * Returns true if input is a valid redirect location.
	 */
	//bool isValidRedirectLocation(const std::string &, const std::string &, bool);

        /**
	 * Returns true if input is a valid redirect location.
	 */
	//public boolean isValidRedirectLocation(String context, String input, boolean allowNull, ValidationErrorList errors) throws IntrusionException;


	/**
	 * Returns a canonicalized and validated redirect location as a String. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException.
	 */
	//public String getValidRedirectLocation(String context, String input, boolean allowNull) throws ValidationException, IntrusionException ;

	/**
	 * ValidationErrorList variant of getValidRedirectLocation
     *
     * @param errors
     */
	//public String getValidRedirectLocation(String context, String input, boolean allowNull, ValidationErrorList errors) throws IntrusionException ;

	/**
     * {@inheritDoc}
     *
	 * This implementation reads until a newline or the specified number of
	 * characters.
     *
     * @param in
     * @param max
     */
	std::string safeReadLine(std::fstream &, int);


};
}; //esapi namespace

