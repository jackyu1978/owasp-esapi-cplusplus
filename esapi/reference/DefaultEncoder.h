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
//#include "Logger.h"
#include "errors/EncodingException.h"
#include <list>
#include <string>

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
class DefaultEncoder : Encoder {

private:
	static Encoder* singletonInstance;
	//const Logger* logger;

	// Codecs
	std::list<Codec*> codecs;
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
	static const char IMMUNE_HTML [];
	static const char IMMUNE_HTMLATTR [];
	static const char IMMUNE_CSS [];
	static const char IMMUNE_JAVASCRIPT [];
	static const char IMMUNE_VBSCRIPT [];
	static const char IMMUNE_XML [];
	static const char IMMUNE_SQL [];
	static const char IMMUNE_OS [];
	static const char IMMUNE_XMLATTR [];
	static const char IMMUNE_XPATH [];

	DefaultEncoder();

public:
	static Encoder* getInstance();

	DefaultEncoder( std::list<std::string> );

	/**
	 * {@inheritDoc}
	 */
	std::string canonicalize( const std::string & );

	/**
	 * {@inheritDoc}
	 */
	std::string canonicalize( const std::string & , bool);

	/**
	 * {@inheritDoc}
	 */
	std::string canonicalize( const std::string & , bool, bool );

	/**
	 * {@inheritDoc}
	 */
	std::string encodeForHTML(const std::string &);

	/**
	 * {@inheritDoc}
	 */
	std::string decodeForHTML(const std::string &);

	/**
	 * {@inheritDoc}
	 */
	std::string encodeForHTMLAttribute(const std::string &);

	/**
	 * {@inheritDoc}
	 */
	std::string encodeForCSS(const std::string &);

	/**
	 * {@inheritDoc}
	 */
	std::string encodeForJavaScript(const std::string &);

	/**
	 * {@inheritDoc}
	 */
	std::string encodeForVBScript(const std::string &);

	/**
	 * {@inheritDoc}
	 */
	std::string encodeForSQL(const Codec&, const std::string &);

	/**
	 * {@inheritDoc}
	 */
	std::string encodeForOS(const Codec&, const std::string &);

	/**
	 * {@inheritDoc}
	 */
	std::string encodeForLDAP(const std::string &);

	/**
	 * {@inheritDoc}
	 */
	std::string encodeForDN(const std::string &);

	/**
	 * {@inheritDoc}
	 */
	std::string encodeForXPath(const std::string &);

	/**
	 * {@inheritDoc}
	 */
	std::string encodeForXML(const std::string &);

	/**
	 * {@inheritDoc}
	 */
	std::string encodeForXMLAttribute(const std::string &);

	/**
	 * {@inheritDoc}
	 */
	std::string encodeForURL(const std::string &) throw (EncodingException);

	/**
	 * {@inheritDoc}
	 */
	std::string decodeFromURL(const std::string &) throw (EncodingException);

	/**
	 * {@inheritDoc}
	 */
	std::string encodeForBase64(const std::string &, bool);

	/**
	 * {@inheritDoc}
	 */
	std::string decodeFromBase64(const std::string &);
};
}; // esapi namespace
