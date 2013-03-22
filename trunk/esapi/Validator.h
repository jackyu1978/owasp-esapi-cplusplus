/**
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * http://www.owasp.org/index.php/ESAPI.
 *
 * Copyright (c) 2011 - The OWASP Foundation
 */

#pragma once

#include "EsapiCommon.h"
#include "ValidationRule.h"
#include "errors/IntrusionException.h"

#include <fstream>
#include <string>
#include <cstdio>

typedef esapi::String DateFormat;

namespace esapi
{
	/**
	 * The Validator interface defines a set of methods for canonicalizing and
	 * validating untrusted input. Implementors should feel free to extend this
	 * interface to accommodate their own data formats. Rather than throw exceptions,
	 * this interface returns bool results because not all validation problems
	 * are security issues. bool returns allow developers to handle both valid
	 * and invalid results more cleanly than exceptions.
	 * <P>
	 * Implementations must adopt a "whitelist" approach to validation where a
	 * specific pattern or character set is matched. "Blacklist" approaches that
	 * attempt to identify the invalid or disallowed characters are much more likely
	 * to allow a bypass with encoding or other tricks.
	 *
	 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
	 *         href="http://www.aspectsecurity.com">Aspect Security</a>
	 * @author David Anderson (david.anderson@aspectsecurity.com)
	 * @author Dan Amodio (dan.amodio@aspectsecurity.com)
	 * @since June 1, 2007
	 */
	class Validator
	{
	public:

		virtual void addRule( const ValidationRule<void*> &) =0;

		virtual ValidationRule<void*>& getRule(const NarrowString &) =0;

		/**
		 * Calls isValidInput and returns true if no exceptions are thrown.
		 */
		virtual bool isValidInput(const NarrowString &, const NarrowString &, const NarrowString &, int, bool) =0;

		/**
		 * Calls isValidInput and returns true if no exceptions are thrown.
		 */
		virtual bool isValidInput(const NarrowString &, const NarrowString &, const NarrowString &, int, bool, ValidationErrorList &) =0;

		/**
		 * Calls isValidInput and returns true if no exceptions are thrown.
		 */
		virtual bool isValidInput(const NarrowString &, const NarrowString &, const NarrowString &, int, bool, bool) =0;

		/**
		 * Calls isValidInput and returns true if no exceptions are thrown.
		 */
		virtual bool isValidInput(const NarrowString &, const NarrowString &, const NarrowString &, int, bool, bool, ValidationErrorList &) =0;

		/**
		 * Returns canonicalized and validated input as a String. Invalid input will generate a descriptive ValidationException,
		 * and input that is clearly an attack will generate a descriptive IntrusionException.
		 *
		 * @param context
		 * 		A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
		 * @param input
		 * 		The actual user input data to validate.
		 * @param type
		 * 		The regular expression name that maps to the actual regular expression from "ESAPI.properties".
		 * @param maxLength
		 * 		The maximum post-canonicalized String length allowed.
		 * @param allowNull
		 * 		If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
		 *
		 * @return The canonicalized user input.
		 *
		 * @throws ValidationException
		 * @throws IntrusionException
		 */
		virtual String getValidInput(const NarrowString &, const NarrowString &, const NarrowString &, int, bool) =0;

		/**
		 * Returns validated input as a String with optional canonicalization. Invalid input will generate a descriptive ValidationException,
		 * and input that is clearly an attack will generate a descriptive IntrusionException.
		 *
		 * @param context
		 * 		A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
		 * @param input
		 * 		The actual user input data to validate.
		 * @param type
		 * 		The regular expression name that maps to the actual regular expression from "ESAPI.properties".
		 * @param maxLength
		 * 		The maximum post-canonicalized String length allowed.
		 * @param allowNull
		 * 		If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
		 * @param canonicalize
		 *      If canonicalize is true then input will be canonicalized before validation
		 *
		 * @return The canonicalized user input.
		 *
		 * @throws ValidationException
		 * @throws IntrusionException
		 */
		virtual String getValidInput(const NarrowString &, const NarrowString &, const NarrowString &, int, bool, bool) =0;

		/**
		 * Calls getValidInput with the supplied errorList to capture ValidationExceptions
		 */
		virtual String getValidInput(const NarrowString &, const NarrowString &, const NarrowString &, int, bool, ValidationErrorList &) =0;

		/**
		 * Calls getValidInput with the supplied errorList to capture ValidationExceptions
		 */
		virtual String getValidInput(const NarrowString &, const NarrowString &, const NarrowString &, int, bool, bool, ValidationErrorList &) =0;

		/**
		 * Calls isValidDate and returns true if no exceptions are thrown.
		 */
		virtual bool isValidDate(const NarrowString &, const NarrowString &, const DateFormat &, bool) =0;

		/**
		 * Calls isValidDate and returns true if no exceptions are thrown.
		 */
		virtual bool isValidDate(const NarrowString &, const NarrowString &, const DateFormat &, bool, ValidationErrorList &) =0;

		/**
		 * Returns a valid date as a Date. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack
		 * will generate a descriptive IntrusionException.
		 *
		 * @param context
		 * 		A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
		 * @param input
		 * 		The actual user input data to validate.
		 * @param format
		 * 		Required formatting of date inputted.
		 * @param allowNull
		 * 		If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
		 *
		 * @return A valid date as a Date
		 *
		 * @throws ValidationException
		 * @throws IntrusionException
		 */
		virtual Char* getValidDate(const NarrowString &, const NarrowString &, const DateFormat &, bool) =0;

		/**
		 * Calls getValidDate with the supplied errorList to capture ValidationExceptions
		 */
		virtual Char* getValidDate(const NarrowString &, const NarrowString &, const DateFormat &, bool, ValidationErrorList &) =0;


		//virtual bool isValidSafeHTML(String, String, int, bool) =0;


		//virtual bool isValidSafeHTML(String, String, int, bool, ValidationErrorList) =0;


		//virtual String getValidSafeHTML(String, String, int, bool) =0;


		//virtual String getValidSafeHTML(String, String, int, bool, ValidationErrorList) =0;

		/**
		 * Calls getValidCreditCard and returns true if no exceptions are thrown.
		 */
		virtual bool isValidCreditCard(const NarrowString &, const NarrowString &, bool) =0;

		/**
		 * Calls getValidCreditCard and returns true if no exceptions are thrown.
		 */
		virtual bool isValidCreditCard(const NarrowString &, const NarrowString &, bool, ValidationErrorList &) =0;

		/**
		 * Returns a canonicalized and validated credit card number as a String. Invalid input
		 * will generate a descriptive ValidationException, and input that is clearly an attack
		 * will generate a descriptive IntrusionException.
		 *
		 * @param context
		 * 		A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
		 * @param input
		 * 		The actual user input data to validate.
		 * @param allowNull
		 * 		If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
		 *
		 * @return A valid credit card number
		 *
		 * @throws ValidationException
		 * @throws IntrusionException
		 */
		virtual String getValidCreditCard(const NarrowString &, const NarrowString &, bool) =0;

		/**
		 * Calls getValidCreditCard with the supplied errorList to capture ValidationExceptions
		 */
		virtual String getValidCreditCard(const NarrowString &, const NarrowString &, bool, ValidationErrorList &) =0;

		/**
		 * Calls getValidDirectoryPath and returns true if no exceptions are thrown.
		 */
		virtual bool isValidDirectoryPath(const NarrowString &, const NarrowString &, std::fstream &, bool) =0;

		/**
		 * Calls getValidDirectoryPath and returns true if no exceptions are thrown.
		 */
		virtual bool isValidDirectoryPath(const NarrowString &, const NarrowString &, std::fstream &, bool, ValidationErrorList &) =0;

		/**
		 * Returns a canonicalized and validated directory path as a String, provided that the input
		 * maps to an existing directory that is an existing subdirectory (at any level) of the specified parent. Invalid input
		 * will generate a descriptive ValidationException, and input that is clearly an attack
		 * will generate a descriptive IntrusionException. Instead of throwing a ValidationException
		 * on error, this variant will store the exception inside of the ValidationErrorList.
		 *
		 * @param context
		 * 		A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
		 * @param input
		 * 		The actual input data to validate.
		 * @param allowNull
		 * 		If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
		 *
		 * @return A valid directory path
		 *
		 * @throws ValidationException
		 * @throws IntrusionException
		 */
		virtual String getValidDirectoryPath(const NarrowString &, const NarrowString &, std::fstream &, bool) =0;

		/**
		 * Calls getValidDirectoryPath with the supplied errorList to capture ValidationExceptions
		 */
		virtual String getValidDirectoryPath(const NarrowString &, const NarrowString &, std::fstream &, bool, ValidationErrorList &) =0;

		/**
		 * Calls getValidFileName with the default list of allowedExtensions
		 */
		virtual bool isValidFileName(const NarrowString &, const NarrowString &, bool) =0;

		/**
		 * Calls getValidFileName with the default list of allowedExtensions
		 */
		virtual bool isValidFileName(const NarrowString &, const NarrowString &, bool, ValidationErrorList &) =0;

		/**
		 * Calls getValidFileName and returns true if no exceptions are thrown.
		 */
		virtual bool isValidFileName(const NarrowString &, const NarrowString &, const std::list<String> &, bool) =0;

		/**
		 * Calls getValidFileName and returns true if no exceptions are thrown.
		 */
		virtual bool isValidFileName(const NarrowString &, const NarrowString &, const std::list<String> &, bool, ValidationErrorList &) =0;

		/**
		 * Returns a canonicalized and validated file name as a String. Implementors should check for allowed file extensions here, as well as allowed file name characters, as declared in "ESAPI.properties". Invalid input
		 * will generate a descriptive ValidationException, and input that is clearly an attack
		 * will generate a descriptive IntrusionException.
		 *
		 * @param context
		 * 		A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
	     * @param input
	     * 		The actual input data to validate.
	     * @param allowNull
	     * 		If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
	     *
	     * @return A valid file name
	     *
	     * @throws ValidationException
	     * @throws IntrusionException
		 */
		virtual String getValidFileName(const NarrowString &, const NarrowString &, const std::list<String> &, bool) =0;

		/**
		 * Calls getValidFileName with the supplied errorList to capture ValidationExceptions
		 */
		virtual String getValidFileName(const NarrowString &, const NarrowString &, const std::list<String> &, bool, ValidationErrorList &) =0;

		/**
		 * Calls getValidNumber and returns true if no exceptions are thrown.
		 */
		virtual bool isValidNumber(const NarrowString &, const NarrowString &, long, long, bool) =0;

		/**
		 * Calls getValidNumber and returns true if no exceptions are thrown.
		 */
		virtual bool isValidNumber(const NarrowString &, const NarrowString &, long, long, bool, ValidationErrorList &) =0;

		/**
		 * Returns a validated number as a double within the range of minValue to maxValue. Invalid input
		 * will generate a descriptive ValidationException, and input that is clearly an attack
		 * will generate a descriptive IntrusionException.
		 *
		 * @param context
		 * 		A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
	     * @param input
	     * 		The actual input data to validate.
	     * @param allowNull
	     * 		If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
	     * @param minValue
	     * 		Lowest legal value for input.
	     * @param maxValue
	     * 		Highest legal value for input.
	     *
	     * @return A validated number as a double.
	     *
	     * @throws ValidationException
	     * @throws IntrusionException
		 */
		virtual double getValidNumber(const NarrowString &, const NarrowString &, long, long, bool) =0;

		/**
		 * Calls getValidSafeHTML with the supplied errorList to capture ValidationExceptions
		 */
		virtual double getValidNumber(const NarrowString &, const NarrowString &, long, long, bool, ValidationErrorList &) =0;

		/**
		 * Calls getValidInteger and returns true if no exceptions are thrown.
		 */
		virtual bool isValidInteger(const NarrowString &, const NarrowString &, int, int, bool) =0;

		/**
		 * Calls getValidInteger and returns true if no exceptions are thrown.
		 */
		virtual bool isValidInteger(const NarrowString &, const NarrowString &, int, int, bool, ValidationErrorList &) =0;

		/**
		 * Returns a validated integer. Invalid input
		 * will generate a descriptive ValidationException, and input that is clearly an attack
		 * will generate a descriptive IntrusionException.
		 *
		 * @param context
		 * 		A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
	     * @param input
	     * 		The actual input data to validate.
	     * @param allowNull
	     * 		If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
	     * @param minValue
	     * 		Lowest legal value for input.
	     * @param maxValue
	     * 		Highest legal value for input.
	     *
	     * @return A validated number as an integer.
	     *
	     * @throws ValidationException
	     * @throws IntrusionException
		 */
		virtual int getValidInteger(const NarrowString &, const NarrowString &, int, int, bool) =0;

		/**
		 * Calls getValidInteger with the supplied errorList to capture ValidationExceptions
		 */
		virtual int getValidInteger(const NarrowString &, const NarrowString &, int, int, bool, ValidationErrorList &) =0;

		/**
		 * Calls getValidDouble and returns true if no exceptions are thrown.
		 */
		virtual bool isValidDouble(const NarrowString &, const NarrowString &, double, double, bool) =0;

		/**
		 * Calls getValidDouble and returns true if no exceptions are thrown.
		 */
		virtual bool isValidDouble(const NarrowString &, const NarrowString &, double, double, bool, ValidationErrorList &) =0;

		/**
		 * Returns a validated real number as a double. Invalid input
		 * will generate a descriptive ValidationException, and input that is clearly an attack
		 * will generate a descriptive IntrusionException.
		 *
		 * @param context
		 * 		A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
	     * @param input
	     * 		The actual input data to validate.
	     * @param allowNull
	     * 		If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
	     * @param minValue
	     * 		Lowest legal value for input.
	     * @param maxValue
	     * 		Highest legal value for input.
	     *
	     * @return A validated real number as a double.
	     *
	     * @throws ValidationException
	     * @throws IntrusionException
		 */
		virtual double getValidDouble(const NarrowString &, const NarrowString &, double, double, bool) =0;

		/**
		 * Calls getValidDouble with the supplied errorList to capture ValidationExceptions
		 */
		virtual double getValidDouble(const NarrowString &, const NarrowString &, double, double, bool, ValidationErrorList &) =0;


		/**
		 * Calls getValidFileContent and returns true if no exceptions are thrown.
		 */
		virtual bool isValidFileContent(const NarrowString &, Char[], int, bool) =0;

		/**
		 * Calls getValidFileContent and returns true if no exceptions are thrown.
		 */
		virtual bool isValidFileContent(const NarrowString &, Char[], int, bool, ValidationErrorList &) =0;

		/**
		 * Returns validated file content as a byte array. This is a good place to check for max file size, allowed character sets, and do virus scans.  Invalid input
		 * will generate a descriptive ValidationException, and input that is clearly an attack
		 * will generate a descriptive IntrusionException.
		 *
		 * @param context
		 * 		A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
		 * @param input
		 * 		The actual input data to validate.
		 * @param maxBytes
		 * 		The maximum number of bytes allowed in a legal file.
		 * @param allowNull
		 * 		If allowNull is true then an input that is NULL or an empty String will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
		 *
		 * @return A byte array containing valid file content.
		 *
		 * @throws ValidationException
		 * @throws IntrusionException
		 */
		virtual Char* getValidFileContent(const NarrowString &, Char[], int, bool) =0;

		/**
		 * Calls getValidFileContent with the supplied errorList to capture ValidationExceptions
		 */
		virtual Char* getValidFileContent(const NarrowString &, Char[], int, bool, ValidationErrorList &) =0;

		/**
		 * Calls getValidFileUpload and returns true if no exceptions are thrown.
		 */
		virtual bool isValidFileUpload(const NarrowString &, const NarrowString &, const NarrowString &, std::fstream &, Char[], int, bool) =0;

		/**
		 * Calls getValidFileUpload and returns true if no exceptions are thrown.
		 */
		virtual bool isValidFileUpload(const NarrowString &, const NarrowString &, const NarrowString &, std::fstream &, Char[], int, bool, ValidationErrorList &) =0;

		/**
		 * Validates the filepath, filename, and content of a file. Invalid input
		 * will generate a descriptive ValidationException, and input that is clearly an attack
		 * will generate a descriptive IntrusionException.
		 *
		 * @param context
		 * 		A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
		 * @param filepath
		 * 		The file path of the uploaded file.
		 * @param filename
		 * 		The filename of the uploaded file
		 * @param content
		 * 		A byte array containing the content of the uploaded file.
		 * @param maxBytes
		 * 		The max number of bytes allowed for a legal file upload.
		 * @param allowNull
		 * 		If allowNull is true then an input that is NULL or an empty String will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
		 *
		 * @throws ValidationException
		 * @throws IntrusionException
		 */
		virtual void assertValidFileUpload(const NarrowString &, const NarrowString &, const NarrowString &, std::fstream &, Char[], int, const std::list<String> &, bool) =0;

		/**
		 * Calls getValidFileUpload with the supplied errorList to capture ValidationExceptions
		 */
		virtual void assertValidFileUpload(const NarrowString &, const NarrowString &, const NarrowString &, std::fstream &, Char[], int, const std::list<String> &, bool, ValidationErrorList &) =0;

		/**
		 * Calls getValidListItem and returns true if no exceptions are thrown.
		 */
		virtual bool isValidListItem(const NarrowString &, const NarrowString &, const std::list<String> &) =0;

		/**
		 * Calls getValidListItem and returns true if no exceptions are thrown.
		 */
		virtual bool isValidListItem(const NarrowString &, const NarrowString &, const std::list<String> &, ValidationErrorList &) =0;

		/**
		 * Returns the list item that exactly matches the canonicalized input. Invalid or non-matching input
		 * will generate a descriptive ValidationException, and input that is clearly an attack
		 * will generate a descriptive IntrusionException.
		 *
		 * @param context
		 * 		A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
		 * @param input
		 * 		The value to search 'list' for.
		 * @param list
		 * 		The list to search for 'input'.
		 *
		 * @return The list item that exactly matches the canonicalized input.
		 *
		 * @throws ValidationException
		 * @throws IntrusionException
		 */
		virtual String getValidListItem(const NarrowString &, const NarrowString &, const std::list<String> &) =0;

		/**
		 * Calls getValidListItem with the supplied errorList to capture ValidationExceptions
		 */
		virtual String getValidListItem(const NarrowString &, const NarrowString &, const std::list<String> &, ValidationErrorList &) =0;

		//virtual bool isValidHTTPRequestParameterSet(const NarrowString &, HttpServletRequest request, Set<String> required, Set<String> optional) throws IntrusionException;
		//bool isValidHTTPRequestParameterSet(const NarrowString & context, HttpServletRequest request, Set<String> required, Set<String> optional, ValidationErrorList errorList) throws IntrusionException;

		//void assertValidHTTPRequestParameterSet(const NarrowString & context, HttpServletRequest request, Set<String> required, Set<String> optional) throws ValidationException, IntrusionException;
		//void assertValidHTTPRequestParameterSet(const NarrowString & context, HttpServletRequest request, Set<String> required, Set<String> optional, ValidationErrorList errorList) throws IntrusionException;

		/**
		 * Calls getValidPrintable and returns true if no exceptions are thrown.
		 */
		virtual bool isValidPrintable(const NarrowString &, Char[], int, bool) =0;

	    /**
		 * Calls getValidPrintable and returns true if no exceptions are thrown.
		 */
		virtual bool isValidPrintable(const NarrowString &, Char[], int, bool, ValidationErrorList &) =0;

		/**
		 * Returns canonicalized and validated printable characters as a byte array. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack
		 * will generate a descriptive IntrusionException.
		 *
		 *  @param context
		 *  		A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
		 *  @param input
		 *  		data to be returned as valid and printable
		 *  @param maxLength
		 *  		Maximum number of bytes stored in 'input'
		 *  @param allowNull
		 *  		If allowNull is true then an input that is NULL or an empty String will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
		 *
		 *  @return a byte array containing only printable characters, made up of data from 'input'
		 *
		 *  @throws ValidationException
		 */
		virtual Char* getValidPrintable(const NarrowString &, Char[], int, bool) =0;

		/**
		 * Calls getValidPrintable with the supplied errorList to capture ValidationExceptions
		 */
		virtual Char* getValidPrintable(const NarrowString &, Char[], int, bool, ValidationErrorList &) =0;


		/**
		 * Calls getValidPrintable and returns true if no exceptions are thrown.
		 */
		virtual bool isValidPrintable(const NarrowString &, const NarrowString &, int, bool) =0;

	    /**
		 * Calls getValidPrintable and returns true if no exceptions are thrown.
		 */
		virtual bool isValidPrintable(const NarrowString &, const NarrowString &, int, bool, ValidationErrorList &) =0;

		/**
		 * Returns canonicalized and validated printable characters as a String. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack
		 * will generate a descriptive IntrusionException.
		 *
		 *  @param context
		 *  		A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
		 *  @param input
		 *  		data to be returned as valid and printable
		 *  @param maxLength
		 *  		Maximum number of bytes stored in 'input' after canonicalization
		 *  @param allowNull
		 *  		If allowNull is true then an input that is NULL or an empty String will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
		 *
		 *  @return a String containing only printable characters, made up of data from 'input'
		 *
		 *  @throws ValidationException
		 */
		virtual String getValidPrintable(const NarrowString &, const NarrowString &, int, bool) =0;

		/**
		 * Calls getValidPrintable with the supplied errorList to capture ValidationExceptions
		 */
		virtual String getValidPrintable(const NarrowString &, const NarrowString &, int, bool, ValidationErrorList &) =0;

		/**
		 * Calls getValidRedirectLocation and returns true if no exceptions are thrown.
		 */
		//bool isValidRedirectLocation(const NarrowString & context, const NarrowString & input, bool allowNull);

	    /**
		 * Calls getValidRedirectLocation and returns true if no exceptions are thrown.
		 */
		//bool isValidRedirectLocation(const NarrowString & context, const NarrowString & input, bool allowNull, ValidationErrorList errorList);

		/**
		 * Returns a canonicalized and validated redirect location as a String. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack
		 * will generate a descriptive IntrusionException.
		 *
		 *  @param context
		 *  		A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
		 *  @param input
		 *  		redirect location to be returned as valid, according to encoding rules set in "ESAPI.properties"
		 *  @param allowNull
		 *  		If allowNull is true then an input that is NULL or an empty String will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
		 *
		 *  @return A canonicalized and validated redirect location, as defined in "ESAPI.properties"
		 *
		 *  @throws ValidationException
		 *  @throws IntrusionException
		 */
		//String getValidRedirectLocation(const NarrowString & context, const NarrowString & input, bool allowNull) throws ValidationException, IntrusionException;

		/**
		 * Calls getValidRedirectLocation with the supplied errorList to capture ValidationExceptions
		 */
		//String getValidRedirectLocation(const NarrowString & context, const NarrowString & input, bool allowNull, ValidationErrorList errorList) throws IntrusionException;

		/**
		 * Reads from an input stream until end-of-line or a maximum number of
		 * characters. This method protects against the inherent denial of service
		 * attack in reading until the end of a line. If an attacker doesn't ever
		 * send a newline character, then a normal input stream reader will read
		 * until all memory is exhausted and the platform throws an OutOfMemoryError
		 * and probably terminates.
		 *
		 * @param inputStream
		 * 		The InputStream from which to read data
		 * @param maxLength
		 * 		Maximum characters allowed to be read in per line
		 *
		 * @return a String containing the current line of inputStream
		 *
		 * @throws ValidationException
		 */
		virtual String safeReadLine(std::fstream &, int) =0;

		virtual ~Validator() {};
	};
} // NAMESPACE

