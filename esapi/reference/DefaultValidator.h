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
namespace esapi
{
  class ESAPI_EXPORT DefaultValidator : public Validator {
  private:

	  static Validator* instance;

	  /** A map of validation rules */
	  std::map<String, const ValidationRule<void*>* > rules;

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
	  bool isEmpty(const String &) const ;

	  /**
	   * Helper function to check if a byte array is empty
	   *
	   * @param input string input value
	   * @return boolean response if input is empty or not
	   */
	  //bool isEmpty(byte[]) const;


	  /**
	   * Helper function to check if a Char array is empty
	   *
	   * @param input string input value
	   * @return boolean response if input is empty or not
	   */
	  bool isEmpty(Char[]) const;

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
	  DefaultValidator(const DefaultValidator&);
	  DefaultValidator& operator=(const DefaultValidator&);

	  /**
	   * Add a validation rule to the registry using the "type name" of the rule as the key.
	   */
	  void addRule( const ValidationRule<void*> & );

	  /**
	   * Get a validation rule from the registry with the "type name" of the rule as the key.
	   */
	  ValidationRule<void*>& getRule( const String & );

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
	  bool isValidInput(const String &, const String &, const String &, int, bool);

	  bool isValidInput(const String &, const String &, const String &, int, bool, ValidationErrorList &);

	  bool isValidInput(const String &, const String &, const String &, int, bool, bool);

	  bool isValidInput(const String &, const String &, const String &, int, bool, bool, ValidationErrorList &);

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
	  String getValidInput(const String &, const String &, const String &, int, bool);

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
	  String getValidInput(const String &, const String &, const String &, int, bool, bool);

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
	  String getValidInput(const String &, const String &, const String &, int, bool, ValidationErrorList&);

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
	  String getValidInput(const String &, const String &, const String &, int, bool, bool, ValidationErrorList &);

	  /**
	   * {@inheritDoc}
	   */
	  bool isValidDate(const String &, const String &, const DateFormat &, bool);

          /**
	   * {@inheritDoc}
	   */
	  bool isValidDate(const String &, const String &, const DateFormat &, bool, ValidationErrorList &);

	  /**
	   * {@inheritDoc}
	   * TODO this should end up returning boost::gregorian::date
	   */
	  Char* getValidDate(const String &, const String &, const DateFormat &, bool) throw (ValidationException, IntrusionException);

	  /**
	   * {@inheritDoc}
	   */
	  Char* getValidDate(const String &, const String &, const DateFormat &, bool, ValidationErrorList &);

	  /**
	   * {@inheritDoc}
	   */
	  bool isValidSafeHTML(const String &, const String &, int, bool);

     /**
	   * {@inheritDoc}
	   */
	  bool isValidSafeHTML(const String &, const String &, int, bool, ValidationErrorList &);

	  /**
	   * {@inheritDoc}
	   *
	   * This implementation relies on the OWASP AntiSamy project.
	   */
	  String getValidSafeHTML( const String &, const String &, int, bool) throw (ValidationException, IntrusionException);

	  /**
	   * {@inheritDoc}
	   */
	  String getValidSafeHTML(const String &, const String &, int, bool, ValidationErrorList &);

	  /**
	   * {@inheritDoc}
	   */
	  bool isValidCreditCard(const String &, const String &, bool);

     /**
	   * {@inheritDoc}
	   */
	  bool isValidCreditCard(const String &, const String &, bool, ValidationErrorList &);

	  /**
	   * {@inheritDoc}
	   */
	  String getValidCreditCard(const String &, const String &, bool) throw (ValidationException, IntrusionException);

	  /**
	   * {@inheritDoc}
	   */
	  String getValidCreditCard(const String &, const String &, bool, ValidationErrorList &);

	  /**
	   * {@inheritDoc}
	   *
	   * <p><b>Note:</b> On platforms that support symlinks, this function will fail canonicalization if directorypath
	   * is a symlink. For example, on MacOS X, /etc is actually /private/etc. If you mean to use /etc, use its real
	   * path (/private/etc), not the symlink (/etc).</p>
	   */
	  bool isValidDirectoryPath(const String &, const String &, std::fstream &, bool);

          /**
	   * {@inheritDoc}
	   *
	   * <p><b>Note:</b> On platforms that support symlinks, this function will fail canonicalization if directorypath
	   * is a symlink. For example, on MacOS X, /etc is actually /private/etc. If you mean to use /etc, use its real
	   * path (/private/etc), not the symlink (/etc).</p>
	   */
	  bool isValidDirectoryPath(const String &, const String &, std::fstream &, bool, ValidationErrorList &);

	  /**
	   * {@inheritDoc}
	   */
	  String getValidDirectoryPath(const String &, const String &, std::fstream &, bool) throw (ValidationException, IntrusionException);

	  /**
	   * {@inheritDoc}
	   */
	  String getValidDirectoryPath(const String &, const String &, std::fstream &, bool, ValidationErrorList &);


	  /**
	   * {@inheritDoc}
	   */
	  bool isValidFileName(const String &, const String &, bool);

      /**
	   * {@inheritDoc}
	   */
	  bool isValidFileName(const String &, const String &, bool, ValidationErrorList &);

	  /**
	   * {@inheritDoc}
	   */
	  bool isValidFileName(const String &, const String &, const std::list<String> &, bool);

      /**
	   * {@inheritDoc}
	   */
	  bool isValidFileName(const String &, const String &, const std::list<String> &, bool, ValidationErrorList &);

	  /**
	   * {@inheritDoc}
	   */
	  String getValidFileName(const String &, const String &, const std::list<String> &, bool) throw (ValidationException, IntrusionException);

	  /**
	   * {@inheritDoc}
	   */
	  String getValidFileName(const String &, const String &, const std::list<String> &, bool, ValidationErrorList &);

	  /**
	   * {@inheritDoc}
	   */
	  bool isValidNumber(const String &, const String &, long, long, bool);

      /**
	   * {@inheritDoc}
	   */
	  bool isValidNumber(const String &, const String &, long, long, bool, ValidationErrorList &);

	  /**
	   * {@inheritDoc}
	   */
	  double getValidNumber(const String &, const String &, long, long, bool) throw (ValidationException, IntrusionException);

	  /**
	   * {@inheritDoc}
	   */
	  double getValidNumber(const String &, const String &, long, long, bool, ValidationErrorList &);

	  /**
	   * {@inheritDoc}
	   */
	  bool isValidDouble(const String &, const String &, double, double, bool);

      /**
	   * {@inheritDoc}
	   */
	  bool isValidDouble(const String &, const String &, double, double, bool, ValidationErrorList &);

	  /**
	   * {@inheritDoc}
	   */
	  double getValidDouble(const String &, const String &, double, double, bool) throw (ValidationException, IntrusionException);

	  /**
	   * {@inheritDoc}
	   */
	  double getValidDouble(const String &, const String &, double, double, bool, ValidationErrorList &);

	  /**
	   * {@inheritDoc}
	   */
	  bool isValidInteger(const String &, const String &, int, int, bool);

      /**
	   * {@inheritDoc}
	   */
	  bool isValidInteger(const String &, const String &, int, int, bool, ValidationErrorList &);

	  /**
	   * {@inheritDoc}
	   */
	  int getValidInteger(const String &, const String &, int, int, bool) throw (ValidationException, IntrusionException);

	  /**
	   * {@inheritDoc}
	   */
	  int getValidInteger(const String &, const String &, int, int, bool, ValidationErrorList &);

	  /**
	   * {@inheritDoc}
	   */
	  bool isValidFileContent(const String &, Char[], int, bool);

          /**
	   * {@inheritDoc}
	   */
	  bool isValidFileContent(const String &, Char[], int, bool, ValidationErrorList &);

	  /**
	   * {@inheritDoc}
	   */
	  Char* getValidFileContent(const String &, Char[], int, bool) throw (ValidationException, IntrusionException);

	  /**
	   * {@inheritDoc}
	   */
	  Char* getValidFileContent(const String &, Char[], int, bool, ValidationErrorList &);

	  /**
	   * {@inheritDoc}
	   *
	   * <p><b>Note:</b> On platforms that support symlinks, this function will fail canonicalization if directorypath
	   * is a symlink. For example, on MacOS X, /etc is actually /private/etc. If you mean to use /etc, use its real
	   * path (/private/etc), not the symlink (/etc).</p>
       */
	  bool isValidFileUpload(const String &, const String &, const String &, std::fstream &, Char[], int, bool);

      /**
	   * {@inheritDoc}
	   *
	   * <p><b>Note:</b> On platforms that support symlinks, this function will fail canonicalization if directorypath
	   * is a symlink. For example, on MacOS X, /etc is actually /private/etc. If you mean to use /etc, use its real
	   * path (/private/etc), not the symlink (/etc).</p>
       */
	  bool isValidFileUpload(const String &, const String &, const String &, std::fstream &, Char[], int, bool, ValidationErrorList &);

	  /**
	   * {@inheritDoc}
	   */
	  void assertValidFileUpload(const String &, const String &, const String &, std::fstream &, Char[], int, const std::list<String> &, bool);

	  /**
	   * {@inheritDoc}
	   */
	  void assertValidFileUpload(const String &, const String &, const String &, std::fstream &, Char[], int, const std::list<String> &, bool, ValidationErrorList &);

	   /**
	   * {@inheritDoc}
	   *
	   * Returns true if input is a valid list item.
	   */
	  bool isValidListItem(const String &, const String &, const std::list<String> &);

      /**
	   * {@inheritDoc}
	   *
	   * Returns true if input is a valid list item.
	   */
	  bool isValidListItem(const String &, const String &, const std::list<String> &, ValidationErrorList &);

	  /**
	   * Returns the list item that exactly matches the canonicalized input. Invalid or non-matching input
	   * will generate a descriptive ValidationException, and input that is clearly an attack
	   * will generate a descriptive IntrusionException.
	   */
	  String getValidListItem(const String &, const String &, const std::list<String> &) throw (ValidationException, IntrusionException);

	  /**
	   * ValidationErrorList variant of getValidListItem
       *
       * @param errors
       */
	  String getValidListItem(const String &, const String &, const std::list<String> &, ValidationErrorList &);

	   /**
	   * {@inheritDoc}
       */
	  //bool isValidHTTPRequestParameterSet(const String &, HttpServletRequest request, Set<String> requiredNames, Set<String> optionalNames);

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
	  bool isValidPrintable(const String &, Char[], int, bool);

      /**
       * {@inheritDoc}
       *
	   * Checks that all bytes are valid ASCII characters (between 33 and 126
	   * inclusive). This implementation does no decoding. http://en.wikipedia.org/wiki/ASCII.
	   */
	  bool isValidPrintable(const String &, Char[], int, bool, ValidationErrorList &);

	  /**
	   * Returns canonicalized and validated printable characters as a byte array. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack
	   * will generate a descriptive IntrusionException.
       *
       * @throws IntrusionException
       */
	  Char* getValidPrintable(const String &, Char[], int, bool) throw (ValidationException, IntrusionException);

	  /**
	   * ValidationErrorList variant of getValidPrintable
       *
       * @param errors
       */
	  Char* getValidPrintable(const String &, Char[], int, bool, ValidationErrorList &);


	   /**
	   * {@inheritDoc}
	   *
	   * Returns true if input is valid printable ASCII characters (32-126).
	   */
	  bool isValidPrintable(const String &, const String &, int, bool);

      /**
	   * {@inheritDoc}
	   *
	   * Returns true if input is valid printable ASCII characters (32-126).
	   */
	  bool isValidPrintable(const String &, const String &, int, bool, ValidationErrorList &);

	  /**
	   * Returns canonicalized and validated printable characters as a String. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack
	   * will generate a descriptive IntrusionException.
       *
       * @throws IntrusionException
       */
	  String getValidPrintable(const String &, const String &, int, bool) throw (ValidationException, IntrusionException);

	  /**
	   * ValidationErrorList variant of getValidPrintable
       *
       * @param errors
       */
	  String getValidPrintable(const String &, const String &, int, bool, ValidationErrorList &);


	  /**
	   * Returns true if input is a valid redirect location.
	   */
	  //bool isValidRedirectLocation(const String &, const String &, bool);

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
	  String safeReadLine(std::fstream &, int);
  };
}; //esapi namespace
