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

#include <string>
#include "errors/EncodingException.h"
#include "codecs/Codec.h"

namespace esapi {
/**
 * The Encoder interface contains a number of methods for decoding input and encoding output
 * so that it will be safe for a variety of interpreters. To prevent
 * double-encoding, callers should make sure input does not already contain encoded characters
 * by calling canonicalize. Validator implementations should call canonicalize on user input
 * <b>before</b> validating to prevent encoded attacks.
 * <p>
 * All of the methods must use a "whitelist" or "positive" security model.
 * For the encoding methods, this means that all characters should be encoded, except for a specific list of
 * "immune" characters that are known to be safe.
 * <p>
 * The Encoder performs two key functions, encoding and decoding. These functions rely
 * on a set of codecs that can be found in the org.owasp.esapi.codecs package. These include:
 * <ul><li>CSS Escaping</li>
 * <li>HTMLEntity Encoding</li>
 * <li>JavaScript Escaping</li>
 * <li>MySQL Escaping</li>
 * <li>Oracle Escaping</li>
 * <li>Percent Encoding (aka URL Encoding)</li>
 * <li>Unix Escaping</li>
 * <li>VBScript Escaping</li>
 * <li>Windows Encoding</li></ul>
 * <p>
 *
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 *         href="http://www.aspectsecurity.com">Aspect Security</a>
 * @author Dan Amodio (dan.amodio@aspectsecurity.com)
 * @since June 1, 2007
 */
class Encoder {
public:

	/**
	 * This method is equivalent to calling <pre>Encoder.canonicalize(input, restrictMultiple, restrictMixed);</pre>
	 *
	 * The default values for restrictMultiple and restrictMixed come from ESAPI.properties
	 * <pre>
	 * Encoder.AllowMultipleEncoding=false
	 * Encoder.AllowMixedEncoding=false
	 * </pre>
	 *
	 * @see Encoder#canonicalize(String, bool, bool) canonicalize
	 * @see <a href="http://www.w3.org/TR/html4/interact/forms.html#h-17.13.4">W3C specifications</a>
	 *
	 * @param input the text to canonicalize
	 * @return a String containing the canonicalized text
	 */
	virtual std::string canonicalize(std::string) =0;

	/**
	 * This method is the equivalent to calling <pre>Encoder.canonicalize(input, strict, strict);</pre>
	 *
	 * @see Encoder#canonicalize(String, bool, bool) canonicalize
	 * @see <a href="http://www.w3.org/TR/html4/interact/forms.html#h-17.13.4">W3C specifications</a>
	 *
	 * @param input
	 * 		the text to canonicalize
	 * @param strict
	 * 		true if checking for multiple and mixed encoding is desired, false otherwise
	 *
	 * @return a String containing the canonicalized text
	 */
	virtual std::string canonicalize(std::string, bool) =0;

	/**
	 * Canonicalization is simply the operation of reducing a possibly encoded
	 * string down to its simplest form. This is important, because attackers
	 * frequently use encoding to change their input in a way that will bypass
	 * validation filters, but still be interpreted properly by the target of
	 * the attack. Note that data encoded more than once is not something that a
	 * normal user would generate and should be regarded as an attack.
	 * <p>
     * Everyone <a href="http://cwe.mitre.org/data/definitions/180.html">says</a> you shouldn't do validation
     * without canonicalizing the data first. This is easier said than done. The canonicalize method can
     * be used to simplify just about any input down to its most basic form. Note that canonicalize doesn't
     * handle Unicode issues, it focuses on higher level encoding and escaping schemes. In addition to simple
     * decoding, canonicalize also handles:
     * <ul><li>Perverse but legal variants of escaping schemes</li>
     * <li>Multiple escaping (%2526 or &#x26;lt;)</li>
     * <li>Mixed escaping (%26lt;)</li>
     * <li>Nested escaping (%%316 or &%6ct;)</li>
     * <li>All combinations of multiple, mixed, and nested encoding/escaping (%2&#x35;3c or &#x2526gt;)</li></ul>
     * <p>
     * Using canonicalize is simple. The default is just...
     * <pre>
     *     String clean = ESAPI.encoder().canonicalize( request.getParameter("input"));
     * </pre>
     * You need to decode untrusted data so that it's safe for ANY downstream interpreter or decoder. For
     * example, if your data goes into a Windows command shell, then into a database, and then to a browser,
     * you're going to need to decode for all of those systems. You can build a custom encoder to canonicalize
     * for your application like this...
     * <pre>
     *     ArrayList list = new ArrayList();
     *     list.add( new WindowsCodec() );
     *     list.add( new MySQLCodec() );
     *     list.add( new PercentCodec() );
     *     Encoder encoder = new DefaultEncoder( list );
     *     String clean = encoder.canonicalize( request.getParameter( "input" ));
     * </pre>
     * In ESAPI, the Validator uses the canonicalize method before it does validation.  So all you need to
     * do is to validate as normal and you'll be protected against a host of encoded attacks.
     * <pre>
     *     String input = request.getParameter( "name" );
     *     String name = ESAPI.validator().isValidInput( "test", input, "FirstName", 20, false);
     * </pre>
     * However, the default canonicalize() method only decodes HTMLEntity, percent (URL) encoding, and JavaScript
     * encoding. If you'd like to use a custom canonicalizer with your validator, that's pretty easy too.
     * <pre>
     *     ... setup custom encoder as above
     *     Validator validator = new DefaultValidator( encoder );
     *     String input = request.getParameter( "name" );
     *     String name = validator.isValidInput( "test", input, "name", 20, false);
     * </pre>
     * Although ESAPI is able to canonicalize multiple, mixed, or nested encoding, it's safer to not accept
     * this stuff in the first place. In ESAPI, the default is "strict" mode that throws an IntrusionException
     * if it receives anything not single-encoded with a single scheme. This is configurable
     * in ESAPI.properties using the properties:
	 * <pre>
	 * Encoder.AllowMultipleEncoding=false
	 * Encoder.AllowMixedEncoding=false
	 * </pre>
	 * This method allows you to override the default behavior by directly specifying whether to restrict
	 * multiple or mixed encoding. Even if you disable restrictions, you'll still get
     * warning messages in the log about each multiple encoding and mixed encoding received.
     * <pre>
     *     // disabling strict mode to allow mixed encoding
     *     String url = ESAPI.encoder().canonicalize( request.getParameter("url"), false, false);
     * </pre>
	 *
	 * @see <a href="http://www.w3.org/TR/html4/interact/forms.html#h-17.13.4">W3C specifications</a>
	 *
	 * @param input
	 * 		the text to canonicalize
	 * @param restrictMultiple
	 * 		true if checking for multiple encoding is desired, false otherwise
	 * @param restrictMixed
	 * 		true if checking for mixed encoding is desired, false otherwise
	 *
	 * @return a String containing the canonicalized text
	 */
	virtual std::string canonicalize(std::string, bool, bool) =0;

	/**
	 * Encode data for use in Cascading Style Sheets (CSS) content.
	 *
	 * @see <a href="http://www.w3.org/TR/CSS21/syndata.html#escaped-characters">CSS Syntax [w3.org]</a>
	 *
	 * @param input
	 * 		the text to encode for CSS
	 *
	 * @return input encoded for CSS
	 */
	virtual std::string encodeForCSS(std::string) =0;

	/**
	 * Encode data for use in HTML using HTML entity encoding
	 * <p>
	 * Note that the following characters:
	 * 00-08, 0B-0C, 0E-1F, and 7F-9F
	 * <p>cannot be used in HTML.
	 *
	 * @see <a href="http://en.wikipedia.org/wiki/Character_encodings_in_HTML">HTML Encodings [wikipedia.org]</a>
	 * @see <a href="http://www.w3.org/TR/html4/sgml/sgmldecl.html">SGML Specification [w3.org]</a>
     * @see <a href="http://www.w3.org/TR/REC-xml/#charsets">XML Specification [w3.org]</a>
	 *
	 * @param input
	 * 		the text to encode for HTML
	 *
	 * @return input encoded for HTML
	 */
	virtual std::string encodeForHTML(std::string) =0;

	/**
     * Decodes HTML entities.
     * @param input the <code>String</code> to decode
     * @return the newly decoded <code>String</code>
     */
	virtual std::string decodeForHTML(std::string) =0;

	/**
	 * Encode data for use in HTML attributes.
	 *
	 * @param input
	 * 		the text to encode for an HTML attribute
	 *
	 * @return input encoded for use as an HTML attribute
	 */
	virtual std::string encodeForHTMLAttribute(std::string) =0;


    /**
     * Encode data for insertion inside a data value or function argument in JavaScript. Including user data
     * directly inside a script is quite dangerous. Great care must be taken to prevent including user data
     * directly into script code itself, as no amount of encoding will prevent attacks there.
     *
     * Please note there are some JavaScript functions that can never safely receive untrusted data
     * as input - even if the user input is encoded.
     *
     * For example:
     *
     *  <script>
     *  window.setInterval('<%= EVEN IF YOU ENCODE UNTRUSTED DATA YOU ARE XSSED HERE %>');
     *  </script>
     *
     * @param input
     *          the text to encode for JavaScript
     *
     * @return input encoded for use in JavaScript
     */
	virtual std::string encodeForJavaScript(std::string) =0;

	/**
	 * Encode data for insertion inside a data value in a Visual Basic script. Putting user data directly
	 * inside a script is quite dangerous. Great care must be taken to prevent putting user data
	 * directly into script code itself, as no amount of encoding will prevent attacks there.
	 *
	 * This method is not recommended as VBScript is only supported by Internet Explorer
	 *
	 * @param input
	 * 		the text to encode for VBScript
	 *
	 * @return input encoded for use in VBScript
	 */
	virtual std::string encodeForVBScript(std::string) =0;


	/**
	 * Encode input for use in a SQL query, according to the selected codec
	 * (appropriate codecs include the MySQLCodec and OracleCodec).
	 *
	 * This method is not recommended. The use of the PreparedStatement
	 * interface is the preferred approach. However, if for some reason
	 * this is impossible, then this method is provided as a weaker
	 * alternative.
	 *
	 * The best approach is to make sure any single-quotes are double-quoted.
	 * Another possible approach is to use the {escape} syntax described in the
	 * JDBC specification in section 1.5.6.
	 *
	 * However, this syntax does not work with all drivers, and requires
	 * modification of all queries.
	 *
	 * @see <a href="http://java.sun.com/j2se/1.4.2/docs/guide/jdbc/getstart/statement.html">JDBC Specification</a>
	 *
	 * @param codec
	 * 		a Codec that declares which database 'input' is being encoded for (ie. MySQL, Oracle, etc.)
	 * @param input
	 * 		the text to encode for SQL
	 *
	 * @return input encoded for use in SQL
	 */
	virtual std::string encodeForSQL(Codec*, std::string) =0;

    /**
     * Encode for an operating system command shell according to the selected codec (appropriate codecs include the WindowsCodec and UnixCodec).
     *
     * Please note the following recommendations before choosing to use this method:
     *
     * 1)      It is strongly recommended that applications avoid making direct OS system calls if possible as such calls are not portable, and they are potentially unsafe. Please use language provided features if at all possible, rather than native OS calls to implement the desired feature.
     * 2)      If an OS call cannot be avoided, then it is recommended that the program to be invoked be invoked directly (e.g., System.exec("nameofcommand" + "parameterstocommand");) as this avoids the use of the command shell. The "parameterstocommand" should of course be validated before passing them to the OS command.
     * 3)      If you must use this method, then we recommend validating all user supplied input passed to the command shell as well, in addition to using this method in order to make the command shell invocation safe.
     *
     * An example use of this method would be: System.exec("dir " + ESAPI.encodeForOS(WindowsCodec, "parameter(s)tocommandwithuserinput");
     *
     * @param codec
     *      a Codec that declares which operating system 'input' is being encoded for (ie. Windows, Unix, etc.)
     * @param input
     *      the text to encode for the command shell
     *
     * @return input encoded for use in command shell
     */
	virtual std::string encodeForOS(Codec*, std::string) =0;

	/**
	 * Encode data for use in LDAP queries.
	 *
	 * @param input
	 * 		the text to encode for LDAP
	 *
	 * @return input encoded for use in LDAP
	 */
	virtual std::string encodeForLDAP(std::string) =0;

	/**
	 * Encode data for use in an LDAP distinguished name.
	 *
	 *  @param input
	 *  		the text to encode for an LDAP distinguished name
	 *
	 *  @return input encoded for use in an LDAP distinguished name
	 */
	virtual std::string encodeForDN(std::string) =0;

	/**
	 * Encode data for use in an XPath query.
	 *
	 * NB: The reference implementation encodes almost everything and may over-encode.
	 *
	 * The difficulty with XPath encoding is that XPath has no built in mechanism for escaping
	 * characters. It is possible to use XQuery in a parameterized way to
	 * prevent injection.
	 *
	 * For more information, refer to <a
	 * href="http://www.ibm.com/developerworks/xml/library/x-xpathinjection.html">this
	 * article</a> which specifies the following list of characters as the most
	 * dangerous: ^&"*';<>(). <a
	 * href="http://www.packetstormsecurity.org/papers/bypass/Blind_XPath_Injection_20040518.pdf">This
	 * paper</a> suggests disallowing ' and " in queries.
	 *
	 * @see <a href="http://www.ibm.com/developerworks/xml/library/x-xpathinjection.html">XPath Injection [ibm.com]</a>
	 * @see <a href="http://www.packetstormsecurity.org/papers/bypass/Blind_XPath_Injection_20040518.pdf">Blind XPath Injection [packetstormsecurity.org]</a>
	 *
	 * @param input
	 *      the text to encode for XPath
	 * @return
	 * 		input encoded for use in XPath
	 */
	virtual std::string encodeForXPath(std::string) =0;

	/**
	 * Encode data for use in an XML element. The implementation should follow the <a
	 * href="http://www.w3schools.com/xml/xml_encoding.asp">XML Encoding
	 * Standard</a> from the W3C.
	 * <p>
	 * The use of a real XML parser is strongly encouraged. However, in the
	 * hopefully rare case that you need to make sure that data is safe for
	 * inclusion in an XML document and cannot use a parse, this method provides
	 * a safe mechanism to do so.
	 *
	 * @see <a href="http://www.w3schools.com/xml/xml_encoding.asp">XML Encoding Standard</a>
	 *
	 * @param input
	 * 			the text to encode for XML
	 *
	 * @return
	 *			input encoded for use in XML
	 */
	virtual std::string encodeForXML(std::string) =0;

	/**
	 * Encode data for use in an XML attribute. The implementation should follow
	 * the <a href="http://www.w3schools.com/xml/xml_encoding.asp">XML Encoding
	 * Standard</a> from the W3C.
	 * <p>
	 * The use of a real XML parser is highly encouraged. However, in the
	 * hopefully rare case that you need to make sure that data is safe for
	 * inclusion in an XML document and cannot use a parse, this method provides
	 * a safe mechanism to do so.
	 *
	 * @see <a href="http://www.w3schools.com/xml/xml_encoding.asp">XML Encoding Standard</a>
	 *
	 * @param input
	 * 			the text to encode for use as an XML attribute
	 *
	 * @return
	 * 			input encoded for use in an XML attribute
	 */
	virtual std::string encodeForXMLAttribute(std::string) =0;

	/**
	 * Encode for use in a URL. This method performs <a
	 * href="http://en.wikipedia.org/wiki/Percent-encoding">URL encoding</a>
	 * on the entire string.
	 *
	 * @see <a href="http://en.wikipedia.org/wiki/Percent-encoding">URL encoding</a>
	 *
	 * @param input
	 * 		the text to encode for use in a URL
	 *
	 * @return input
	 * 		encoded for use in a URL
	 *
	 * @throws EncodingException
	 * 		if encoding fails
	 */
	virtual std::string encodeForURL(std::string) throw (EncodingException) =0;

	/**
	 * Decode from URL. Implementations should first canonicalize and
	 * detect any double-encoding. If this check passes, then the data is decoded using URL
	 * decoding.
	 *
	 * @param input
	 * 		the text to decode from an encoded URL
	 *
	 * @return
	 * 		the decoded URL value
	 *
	 * @throws EncodingException
	 * 		if decoding fails
	 */
	virtual std::string decodeFromURL(std::string) throw (EncodingException) =0;

	/**
	 * Encode for Base64.
	 *
	 * @param input
	 * 		the text to encode for Base64
	 * @param wrap
	 * 		the encoder will wrap lines every 64 characters of output
	 *
	 * @return input encoded for Base64
	 */
	virtual std::string encodeForBase64(char[], bool) =0;

	/**
	 * Decode data encoded with BASE-64 encoding.
	 *
	 * @param input
	 * 		the Base64 text to decode
	 *
	 * @return input
	 * 		decoded from Base64
	 *
	 * @throws IOException
	 */
	virtual char* decodeFromBase64(std::string) =0;

};


}; // esapi namespace
