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
#include "crypto/Crypto++Common.h"

#include "errors/NullPointerException.h"
#include "errors/UnsupportedOperationException.h"

namespace esapi
{
  Encoder* DefaultEncoder::singletonInstance = nullptr;
  //Logger* DefaultEncoder::logger = nullptr;

  // not static, so I don't think these need to be defined here
  // Codecs
  //std::list<const Codec*> DefaultEncoder::codecs;
  //HTMLEntityCodec DefaultEncoder::htmlCodec;
  //DefaultEncoder::ldapCodec = new LDAPCodec;
  //XMLEntityCodec DefaultEncoder::xmlCodec;
  //PercentCodec DefaultEncoder::percentCodec;
  //JavaScriptCodec DefaultEncoder::javaScriptCodec;
  //VBScriptCodec DefaultEncoder::vbScriptCodec;
  //CSSCodec DefaultEncoder::cssCodec;

  const Char DefaultEncoder::IMMUNE_HTML [] = { L',', L'.', L'-', L'_', L' ' };
  const Char DefaultEncoder::IMMUNE_HTMLATTR [] = { L',', L'.', L'-', L'_' };
  const Char DefaultEncoder::IMMUNE_CSS [] = { L'\0' };
  const Char DefaultEncoder::IMMUNE_JAVASCRIPT [] = { L',', L'.', L'_' };
  const Char DefaultEncoder::IMMUNE_VBSCRIPT [] = { L',', L'.', L'_' };
  const Char DefaultEncoder::IMMUNE_XML [] = { L',', L'.', L'-', L'_', L' ' };
  const Char DefaultEncoder::IMMUNE_SQL [] = { L' ' };
  const Char DefaultEncoder::IMMUNE_OS [] = { L'-' };
  const Char DefaultEncoder::IMMUNE_XMLATTR [] = { L',', L'.', L'-', L'_' };
  const Char DefaultEncoder::IMMUNE_XPATH [] = { L',', L'.', L'-', L'_', L' ' };

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
    /*         if ( singletonInstance == null ) {
    synchronized ( DefaultEncoder.class ) {
    if ( singletonInstance == null ) {
    singletonInstance = new DefaultEncoder();
    }
    }
    }
    return singletonInstance;
    */
    Encoder* enc = nullptr;
    return *enc;
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
    throw new UnsupportedOperationException(L"This operation is not yet supported");
  }

  String DefaultEncoder::canonicalize( const String & input) {
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

  String DefaultEncoder::canonicalize( const String & input, bool strict) {
    return canonicalize(input, strict, strict);
  }

  String DefaultEncoder::canonicalize( const String & /*input*/, bool /*restrictMultiple*/, bool /*restrictMixed*/) {
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
    throw new IntrusionException( "Input validation failure", "Multiple (L"+ foundCount +"x) and mixed encoding (L"+ mixedCount +"x) detected in " + input );
    } else {
    logger.warning( Logger.SECURITY_FAILURE, "Multiple (L"+ foundCount +"x) and mixed encoding (L"+ mixedCount +"x) detected in " + input );
    }
    }
    else if ( foundCount >= 2 ) {
    if ( restrictMultiple ) {
    throw new IntrusionException( "Input validation failure", "Multiple (L"+ foundCount +"x) encoding detected in " + input );
    } else {
    logger.warning( Logger.SECURITY_FAILURE, "Multiple (L"+ foundCount +"x) encoding detected in " + input );
    }
    }
    else if ( mixedCount > 1 ) {
    if ( restrictMixed ) {
    throw new IntrusionException( "Input validation failure", "Mixed encoding (L"+ mixedCount +"x) detected in " + input );
    } else {
    logger.warning( Logger.SECURITY_FAILURE, "Mixed encoding (L"+ mixedCount +"x) detected in " + input );
    }
    }
    return working;
    */

    return L"";
  }

  String DefaultEncoder::encodeForHTML(const String & /*input*/) {
    /*
    if( input == null ) {
    return null;
    }
    return htmlCodec.encode( IMMUNE_HTML, input);
    */

    throw new UnsupportedOperationException(L"This operation has not yet been implemented.");
  }

  String DefaultEncoder::decodeForHTML(const String & /*input*/) {
    /*
    if( input == null ) {
    return null;
    }
    return htmlCodec.decode( input);
    */
    throw new UnsupportedOperationException(L"This operation has not yet been implemented.");
  }

  String DefaultEncoder::encodeForHTMLAttribute(const String & /*input*/) {
    /*
    if( input == null ) {
    return null;
    }
    return htmlCodec.encode( IMMUNE_HTMLATTR, input)
    */

    throw new UnsupportedOperationException(L"This operation has not yet been implemented.");
  }

  String DefaultEncoder::encodeForCSS(const String & /*input*/) {
    /*
    if( input == null ) {
    return null;
    }
    return cssCodec.encode( IMMUNE_CSS, input);
    */
    throw new UnsupportedOperationException(L"This operation has not yet been implemented.");
  }

  String DefaultEncoder::encodeForJavaScript(const String & /*input*/) {
    /*
    if( input == null ) {
    return null;
    }
    return javaScriptCodec.encode(IMMUNE_JAVASCRIPT, input);
    */
    throw new UnsupportedOperationException(L"This operation has not yet been implemented.");
  }

  String DefaultEncoder::encodeForVBScript(const String & /*input*/) {
    /*
    if( input == null ) {
    return null;
    }
    return vbScriptCodec.encode(IMMUNE_VBSCRIPT, input);
    */
    throw new UnsupportedOperationException(L"This operation has not yet been implemented.");
  }

  String DefaultEncoder::encodeForSQL(const Codec& /*codec*/, const String & /*input*/) {
    /*
    if( input == null ) {
    return null;
    }
    return codec.encode(IMMUNE_SQL, input);
    */
    throw new UnsupportedOperationException(L"This operation has not yet been implemented.");
  }

  String DefaultEncoder::encodeForOS(const Codec *codec, const String & input) {
    ASSERT(codec);

    if (codec == nullptr)
      throw new NullPointerException(L"encoderForOS(..) : Null pointer to codec");

    if ( input.empty() )
      return String();

    return codec->encode( IMMUNE_OS, COUNTOF(IMMUNE_OS), input);

  }

  String DefaultEncoder::encodeForLDAP(const String & input) {
    if ( input.empty() )
      return String();

    return ldapCodec.encode( L"", 0, input);
  }

  String DefaultEncoder::encodeForDN(const String & /*input*/) {
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
    sb.append(L"\\\\");
    break;
    case ',':
    sb.append(L"\\,L");
    break;
    case '+':
    sb.append(L"\\+");
    break;
    case '"':
    sb.append(L"\\\"");
    break;
    case '<':
    sb.append(L"\\<");
    break;
    case '>':
    sb.append(L"\\>");
    break;
    case ';':
    sb.append(L"\\;");
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
    throw new UnsupportedOperationException(L"This operation has not yet been implemented.");
  }

  String DefaultEncoder::encodeForXPath(const String & /*input*/) {
    /*
    if( input == null ) {
    return null;
    }
    return htmlCodec.encode( IMMUNE_XPATH, input);
    */
    throw new UnsupportedOperationException(L"This operation has not yet been implemented.");
  }

  String DefaultEncoder::encodeForXML(const String & /*input*/) {
    /*
    if( input == null ) {
    return null;
    }
    return xmlCodec.encode( IMMUNE_XML, input);
    */
    throw new UnsupportedOperationException(L"This operation has not yet been implemented.");
  }

  String DefaultEncoder::encodeForXMLAttribute(const String & /*input*/) {
    /*
    if( input == null ) {
    return null;
    }
    return xmlCodec.encode( IMMUNE_XMLATTR, input);
    */
    throw new UnsupportedOperationException(L"This operation has not yet been implemented.");
  }

  String DefaultEncoder::encodeForURL(const String & /*input*/) throw (EncodingException) {
    /*
    if ( input == null ) {
    return null;
    }
    try {
    return URLEncoder.encode(input, ESAPI.securityConfiguration().getCharacterEncoding());
    } catch (UnsupportedEncodingException ex) {
    throw new EncodingException(L"Encoding failure", "Character encoding not supported", ex);
    } catch (Exception e) {
    throw new EncodingException(L"Encoding failure", "Problem URL encoding input", e);
    }
    */
    throw new UnsupportedOperationException(L"This operation has not yet been implemented.");
  }

  String DefaultEncoder::decodeFromURL(const String & /*input*/) throw (EncodingException) {
    /*
    if ( input == null ) {
    return null;
    }
    String canonical = canonicalize(input);
    try {
    return URLDecoder.decode(canonical, ESAPI.securityConfiguration().getCharacterEncoding());
    } catch (UnsupportedEncodingException ex) {
    throw new EncodingException(L"Decoding failed", "Character encoding not supported", ex);
    } catch (Exception e) {
    throw new EncodingException(L"Decoding failed", "Problem URL decoding input", e);
    }
    */
    throw new UnsupportedOperationException(L"This operation has not yet been implemented.");
  }

  String DefaultEncoder::encodeForBase64(const String & input, bool wrap) {
    if ( input.empty() )
      return String();

    SecureByteArray sa = TextConvert::GetBytes(input, "UTF-8");
    ASSERT( !sa.empty() );

    std::string encoded;
    CryptoPP::StringSource(sa.data(), sa.size(), true,
      new CryptoPP::Base64Encoder(new CryptoPP::StringSink(encoded), wrap));

    return TextConvert::NarrowToWide(encoded);
  }

  String DefaultEncoder::encodeForBase64(const String & input) {
    return this->encodeForBase64(input, false);
  }

  String DefaultEncoder::decodeFromBase64(const String & input) {
    if ( input.empty() )
      return String();

    SecureByteArray sa = TextConvert::GetBytes(input, "UTF-8");
    ASSERT( !sa.empty() );

    std::string decoded;
    CryptoPP::StringSource(sa.data(), sa.size(), true,
      new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decoded)));

    return TextConvert::NarrowToWide(decoded);
  }

} //espai
