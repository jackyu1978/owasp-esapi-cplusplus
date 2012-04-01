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
 * @created 2007
 */

#pragma once

#include "Encoder.h"
#include "codecs/Codec.h"
#include "codecs/LDAPCodec.h"
//#include "Logger.h"
#include "errors/EncodingException.h"
#include <list>
#include <string>
#include <set>

namespace esapi {
/**
 * Reference implementation of the Encoder interface. This implementation takes
 * a whitelist approach to encoding, meaning that everything not specifically identified in a
 * list of "immune" characters is encoded.
 *
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 *         href="http://www.aspectsecurity.com">Aspect Security</a>
 * @author Dan Amodio (dan.amodio@aspectsecurity.com)
 * @since June 1, 2007
 * @see org.owasp.esapi.Encoder
 */
class ESAPI_EXPORT DefaultEncoder : public Encoder {

private:
	static Encoder* singletonInstance;
	//const Logger* logger;

	// Codecs
	std::list<const Codec*> codecs;
	LDAPCodec ldapCodec;
	//HTMLEntityCodec htmlCodec;
	//XMLEntityCodec xmlCodec;
	//PercentCodec percentCodec;
	//JavaScriptCodec javaScriptCodec;
	//VBScriptCodec vbScriptCodec;
	//CSSCodec cssCodec;

	/**
	 *  Character sets that define characters (in addition to alphanumerics) that are
	 * immune from encoding in various formats
	 */
	static const Char IMMUNE_HTML [];
	static const Char IMMUNE_HTMLATTR [];
	static const Char IMMUNE_CSS [];
	static const Char IMMUNE_JAVASCRIPT [];
	static const Char IMMUNE_VBSCRIPT [];
	static const Char IMMUNE_XML [];
	static const Char IMMUNE_SQL [];
	static const Char IMMUNE_OS [];
	static const Char IMMUNE_XMLATTR [];
	static const Char IMMUNE_XPATH [];

	DefaultEncoder();

public:
	static const Encoder& getInstance();

	DefaultEncoder( std::set<String> );

	/**
	 * {@inheritDoc}
	 */
	String canonicalize( const String & );

	/**
	 * {@inheritDoc}
	 */
	String canonicalize( const String & , bool);

	/**
	 * {@inheritDoc}
	 */
	String canonicalize( const String & , bool, bool );

	/**
	 * {@inheritDoc}
	 */
	String encodeForHTML(const String &);

	/**
	 * {@inheritDoc}
	 */
	String decodeForHTML(const String &);

	/**
	 * {@inheritDoc}
	 */
	String encodeForHTMLAttribute(const String &);

	/**
	 * {@inheritDoc}
	 */
	String encodeForCSS(const String &);

	/**
	 * {@inheritDoc}
	 */
	String encodeForJavaScript(const String &);

	/**
	 * {@inheritDoc}
	 */
	String encodeForVBScript(const String &);

	/**
	 * {@inheritDoc}
	 */
	String encodeForSQL(const Codec&, const String &);

	/**
	 * {@inheritDoc}
	 */
	String encodeForOS(const Codec*, const String &);
	std::string encodeForOS(const Codec*, const std::string &);

	/**
	 * {@inheritDoc}
	 */
	String encodeForLDAP(const String &);

	/**
	 * {@inheritDoc}
	 */
	String encodeForDN(const String &);

	/**
	 * {@inheritDoc}
	 */
	String encodeForXPath(const String &);

	/**
	 * {@inheritDoc}
	 */
	String encodeForXML(const String &);

	/**
	 * {@inheritDoc}
	 */
	String encodeForXMLAttribute(const String &);

	/**
	 * {@inheritDoc}
	 */
	String encodeForURL(const String &) throw (EncodingException);

	/**
	 * {@inheritDoc}
	 */
	String decodeFromURL(const String &) throw (EncodingException);

	/**
	 * {@inheritDoc}
	 */
	String encodeForBase64(const String &, bool);

	/*
	 * For simplicity of calling encodeForBase64(const String &, bool);
	 */
	String encodeForBase64(const String &);

	/**
	 * {@inheritDoc}
	 */
	String decodeFromBase64(const String &);
};
}; // esapi namespace

