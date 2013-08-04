/**
* OWASP Enterprise Security API (ESAPI)
*
* This file is part of the Open Web Application Security Project (OWASP)
* Enterprise Security API (ESAPI) project. For details, please see
* http://www.owasp.org/index.php/ESAPI.
*
* Copyright (c) 2011 - The OWASP Foundation
*/

#include "EsapiCommon.h"
#include "EncoderConstants.h"
#include "reference/DefaultEncoder.h"

#include "codecs/Codec.h"
#include "codecs/UnixCodec.h"
#include "codecs/WindowsCodec.h"

#include "util/TextConvert.h"
#include "crypto/CryptoppCommon.h"

#include "errors/NullPointerException.h"
#include "errors/UnsupportedOperationException.h"

namespace esapi
{
  Encoder* DefaultEncoder::singletonInstance = nullptr;
  //Logger* DefaultEncoder::logger = nullptr;

  static StringArray Make_HTML_Vector()
  {
    StringArray sa;
    sa.push_back(","); sa.push_back(".");
    sa.push_back("-"); sa.push_back("_");
    sa.push_back(" ");
    return sa;
  }

  static StringArray Make_HTMLATTR_Vector()
  {
    StringArray sa;
    sa.push_back(","); sa.push_back(".");
    sa.push_back("-"); sa.push_back("_");
    return sa;
  }

  static StringArray Make_CSS_Vector()
  {
    StringArray sa;
    sa.push_back("");
    return sa;
  }

  static StringArray Make_JAVASCRIPT_Vector()
  {
    StringArray sa;
    sa.push_back(","); sa.push_back(".");
    sa.push_back("_");
    return sa;
  }

  static StringArray Make_VBSCRIPT_Vector()
  {
    StringArray sa;
    sa.push_back(","); sa.push_back(".");
    sa.push_back("_");
    return sa;
  }

  static StringArray Make_XML_Vector()
  {
    StringArray sa;
    sa.push_back(","); sa.push_back(".");
    sa.push_back("-"); sa.push_back("_");
    sa.push_back(" ");
    return sa;
  }

  static StringArray Make_SQL_Vector()
  {
    StringArray sa;
    sa.push_back(" ");
    return sa;
  }

  static StringArray Make_OS_Vector()
  {
    StringArray sa;
    sa.push_back("-");
    return sa;
  }

  static StringArray Make_XMLATTR_Vector()
  {
    StringArray sa;
    sa.push_back(","); sa.push_back(".");
    sa.push_back("-"); sa.push_back("_");
    return sa;
  }

  static StringArray Make_XPATH_Vector()
  {
    StringArray sa;
    sa.push_back(","); sa.push_back(".");
    sa.push_back("-"); sa.push_back("_");
    sa.push_back(" ");
    return sa;
  }

  const StringArray DefaultEncoder::IMMUNE_HTML = Make_HTML_Vector();
  const StringArray DefaultEncoder::IMMUNE_HTMLATTR = Make_HTMLATTR_Vector();
  const StringArray DefaultEncoder::IMMUNE_CSS = Make_CSS_Vector();
  const StringArray DefaultEncoder::IMMUNE_JAVASCRIPT = Make_JAVASCRIPT_Vector();
  const StringArray DefaultEncoder::IMMUNE_VBSCRIPT = Make_VBSCRIPT_Vector();
  const StringArray DefaultEncoder::IMMUNE_XML = Make_XML_Vector();
  const StringArray DefaultEncoder::IMMUNE_SQL = Make_SQL_Vector();
  const StringArray DefaultEncoder::IMMUNE_OS = Make_OS_Vector();
  const StringArray DefaultEncoder::IMMUNE_XMLATTR = Make_XMLATTR_Vector();
  const StringArray DefaultEncoder::IMMUNE_XPATH = Make_XPATH_Vector();

  DefaultEncoder::DefaultEncoder()
    : codecs(), ldapCodec()
  {
    //LDAPCodec ldapCodec = new LDAPCodec;
    /*
    codecs.as->dd( htmlCodec );
    codecs.aldd( percentCodec );
    codecs.add( javaScriptCodec );
    */
  }

  const Encoder& DefaultEncoder::getInstance() {
    // TODO singleton?
    /* if ( singletonInstance == null ) {
    synchronized ( DefaultEncoder.class ) {
    if ( singletonInstance == null ) {
    singletonInstance = new DefaultEncoder();
    }
    }
    }
    return singletonInstance;
    */
    static DefaultEncoder encoder;

    MEMORY_BARRIER();
    return encoder;
  }

  DefaultEncoder::DefaultEncoder( std::set<String> codecNames)
    : codecs(), ldapCodec()
  {
    /*
    for ( String clazz : codecNames ) {
    try {
    if ( clazz.indexOf( '.' ) == -1 ) clazz = "org.owasp.esapi.codecs." + clazz;
    codecs.add( Class.forName( clazz ).newInstance() );
    } catch ( Exception e ) {
    logger.warning( Logger.EVENT_FAILURE, "Codec " + clazz + " listed in ESAPI.properties not on classpath" );
    }
    }
    */
    //throw UnsupportedOperationException("This operation is not yet supported");
  }

  String DefaultEncoder::canonicalize( const NarrowString & input) {
    /* TODO Use security configuration
    // Issue 231 - These are reverse boolean logic in the Encoder interface, so we need to invert these values - CS
    return canonicalize(input,
    !ESAPI.securityConfiguration().getAllowMultipleEncoding(),
    !ESAPI.securityConfiguration().getAllowMixedEncoding() );
    */
    if ( input.empty() )
      return String();

    return canonicalize(input, false, false);
  }

  String DefaultEncoder::canonicalize( const NarrowString & input, bool strict) {
    return canonicalize(input, strict, strict);
  }

  String DefaultEncoder::canonicalize( const NarrowString & /*input*/, bool /*restrictMultiple*/, bool /*restrictMixed*/) {
    /*
    if ( input == null ) {
    return null;
    }

    String working = input;
    Codec codecFound = null;
    int mixedCount = 1;
    int foundCount = 0;
    boolean clean = false;
    while( !clean ) {
    clean = true;

    // try each codec and keep track of which ones work
    Iterator i = codecs.iterator();
    while ( i.hasNext() ) {
    Codec codec = (Codec)i.next();
    String old = working;
    working = codec.decode( working );
    if ( !old.equals( working ) ) {
    if ( codecFound != null && codecFound != codec ) {
    mixedCount++;
    }
    codecFound = codec;
    if ( clean ) {
    foundCount++;
    }
    clean = false;
    }
    }
    }

    // do strict tests and handle if any mixed, multiple, nested encoding were found
    if ( foundCount >= 2 && mixedCount > 1 ) {
    if ( restrictMultiple || restrictMixed ) {
    throw IntrusionException( "Input validation failure", "Multiple ("+ foundCount +"x) and mixed encoding ("+ mixedCount +"x) detected in " + input );
    } else {
    logger.warning( Logger.SECURITY_FAILURE, "Multiple ("+ foundCount +"x) and mixed encoding ("+ mixedCount +"x) detected in " + input );
    }
    }
    else if ( foundCount >= 2 ) {
    if ( restrictMultiple ) {
    throw IntrusionException( "Input validation failure", "Multiple ("+ foundCount +"x) encoding detected in " + input );
    } else {
    logger.warning( Logger.SECURITY_FAILURE, "Multiple ("+ foundCount +"x) encoding detected in " + input );
    }
    }
    else if ( mixedCount > 1 ) {
    if ( restrictMixed ) {
    throw IntrusionException( "Input validation failure", "Mixed encoding ("+ mixedCount +"x) detected in " + input );
    } else {
    logger.warning( Logger.SECURITY_FAILURE, "Mixed encoding ("+ mixedCount +"x) detected in " + input );
    }
    }
    return working;
    */

    return "";
  }

  String DefaultEncoder::encodeForHTML(const NarrowString & /*input*/) {
    /*
    if( input == null ) {
    return null;
    }
    return htmlCodec.encode( IMMUNE_HTML, input);
    */

    throw UnsupportedOperationException("This operation has not yet been implemented");
  }

  String DefaultEncoder::decodeForHTML(const NarrowString & /*input*/) {
    /*
    if( input == null ) {
    return null;
    }
    return htmlCodec.decode( input);
    */
    throw UnsupportedOperationException("This operation has not yet been implemented");
  }

  String DefaultEncoder::encodeForHTMLAttribute(const NarrowString & /*input*/) {
    /*
    if( input == null ) {
    return null;
    }
    return htmlCodec.encode( IMMUNE_HTMLATTR, input)
    */

    throw UnsupportedOperationException("This operation has not yet been implemented");
  }

  String DefaultEncoder::encodeForCSS(const NarrowString & /*input*/) {
    /*
    if( input == null ) {
    return null;
    }
    return cssCodec.encode( IMMUNE_CSS, input);
    */
    throw UnsupportedOperationException("This operation has not yet been implemented");
  }

  String DefaultEncoder::encodeForJavaScript(const NarrowString & /*input*/) {
    /*
    if( input == null ) {
    return null;
    }
    return javaScriptCodec.encode(IMMUNE_JAVASCRIPT, input);
    */
    throw UnsupportedOperationException("This operation has not yet been implemented");
  }

  String DefaultEncoder::encodeForVBScript(const NarrowString & /*input*/) {
    /*
    if( input == null ) {
    return null;
    }
    return vbScriptCodec.encode(IMMUNE_VBSCRIPT, input);
    */
    throw UnsupportedOperationException("This operation has not yet been implemented");
  }

  String DefaultEncoder::encodeForSQL(const Codec& /*codec*/, const NarrowString & /*input*/) {
    /*
    if( input == null ) {
    return null;
    }
    return codec.encode(IMMUNE_SQL, input);
    */
    throw UnsupportedOperationException("This operation has not yet been implemented");
  }

  NarrowString DefaultEncoder::encodeForOS(const Codec& codec, const NarrowString & input) {

    if ( input.empty() )
      return NarrowString();

    return codec.encode(IMMUNE_OS, input);

  }

  /*
  WideString DefaultEncoder::encodeForOS(const Codec& codec, const WideString & input) {
  return encodeForOS(codec, input);
  }
  */

  String DefaultEncoder::encodeForLDAP(const NarrowString & input) {
    ASSERT(!input.empty());

    if(input.empty() )
      return String();

    StringArray unused;
    return ldapCodec.encode(unused, input);
  }

  String DefaultEncoder::encodeForDN(const NarrowString & /*input*/) {
    /*
    if( input == null ) {
    return null;
    }
    // TODO: replace with DN codec
    StringBuilder sb = new StringBuilder();
    if ((input.length() > 0) && ((input.charAt(0) == L' ') || (input.charAt(0) == L'#'))) {
    sb.append(L'\\'); // add the leading backslash if needed
    }
    for (int i = 0; i < input.length(); i++) {
    Char c = input.charAt(i);
    switch (c) {
    case '\\':
    sb.append("\\\\");
    break;
    case ',':
    sb.append("\\,");
    break;
    case '+':
    sb.append("\\+");
    break;
    case '"':
    sb.append("\\\"");
    break;
    case '<':
    sb.append("\\<");
    break;
    case '>':
    sb.append("\\>");
    break;
    case ';':
    sb.append("\\;");
    break;
    default:
    sb.append(c);
    }
    }
    // add the trailing backslash if needed
    if ((input.length() > 1) && (input.charAt(input.length() - 1) == L' ')) {
    sb.insert(sb.length() - 1, L'\\');
    }
    return sb.toString();
    */
    throw UnsupportedOperationException("This operation has not yet been implemented");
  }

  String DefaultEncoder::encodeForXPath(const NarrowString & /*input*/) {
    /*
    if( input == null ) {
    return null;
    }
    return htmlCodec.encode( IMMUNE_XPATH, input);
    */
    throw UnsupportedOperationException("This operation has not yet been implemented");
  }

  String DefaultEncoder::encodeForXML(const NarrowString & /*input*/) {
    /*
    if( input == null ) {
    return null;
    }
    return xmlCodec.encode( IMMUNE_XML, input);
    */
    throw UnsupportedOperationException("This operation has not yet been implemented");
  }

  String DefaultEncoder::encodeForXMLAttribute(const NarrowString & /*input*/) {
    /*
    if( input == null ) {
    return null;
    }
    return xmlCodec.encode( IMMUNE_XMLATTR, input);
    */
    throw UnsupportedOperationException("This operation has not yet been implemented");
  }

  String DefaultEncoder::encodeForURL(const NarrowString & /*input*/) {
    /*
    if ( input == null ) {
    return null;
    }
    try {
    return URLEncoder.encode(input, ESAPI.securityConfiguration().getCharacterEncoding());
    } catch (UnsupportedEncodingException ex) {
    throw EncodingException("Encoding failure", "Character encoding not supported", ex);
    } catch (Exception e) {
    throw EncodingException("Encoding failure", "Problem URL encoding input", e);
    }
    */
    throw UnsupportedOperationException("This operation has not yet been implemented");
  }

  String DefaultEncoder::decodeFromURL(const NarrowString & /*input*/) {
    /*
    if ( input == null ) {
    return null;
    }
    String canonical = canonicalize(input);
    try {
    return URLDecoder.decode(canonical, ESAPI.securityConfiguration().getCharacterEncoding());
    } catch (UnsupportedEncodingException ex) {
    throw EncodingException("Decoding failed", "Character encoding not supported", ex);
    } catch (Exception e) {
    throw EncodingException("Decoding failed", "Problem URL decoding input", e);
    }
    */
    throw UnsupportedOperationException("This operation has not yet been implemented");
  }

  NarrowString DefaultEncoder::encodeForBase64(const NarrowString & input, bool wrap) {
    if ( input.empty() )
      return String();

    SecureByteArray sa = TextConvert::GetBytes(input, "UTF-8");
    ASSERT( !sa.empty() );

    std::string encoded;
    CryptoPP::StringSource ss(sa.data(), sa.size(), true,
      new CryptoPP::Base64Encoder(new CryptoPP::StringSink(encoded), wrap));
    ss.MessageEnd();

    return encoded;
  }

  String DefaultEncoder::encodeForBase64(const NarrowString & input) {
    return this->encodeForBase64(input, false);
  }

  NarrowString DefaultEncoder::decodeFromBase64(const NarrowString & input) {
    if ( input.empty() )
      return String();

    SecureByteArray sa = TextConvert::GetBytes(input, "UTF-8");
    ASSERT( !sa.empty() );

    std::string decoded;
    CryptoPP::StringSource ss(sa.data(), sa.size(), true,
      new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decoded)));
    ss.MessageEnd();

    return decoded;
  }

} //espai
