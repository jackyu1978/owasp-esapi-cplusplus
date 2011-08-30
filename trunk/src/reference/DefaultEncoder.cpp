/**
* OWASP Enterprise Security API (ESAPI)
*
* This file is part of the Open Web Application Security Project (OWASP)
* Enterprise Security API (ESAPI) project. For details, please see
* http://www.owasp.org/index.php/ESAPI.
*
* Copyright (c) 2011 - The OWASP Foundation
*/

#include "EncoderConstants.h"
#include "reference/DefaultEncoder.h"

#include "codecs/Codec.h"
#include "codecs/UnixCodec.h"
#include "codecs/WindowsCodec.h"

#include "errors/NullPointerException.h"
#include "errors/UnsupportedOperationException.h"

#include <cryptopp/base64.h>

esapi::Encoder* esapi::DefaultEncoder::singletonInstance = nullptr;
//esapi::Logger* esapi::DefaultEncoder::logger = nullptr;


// not static, so I don't think these need to be defined here
// Codecs
//std::list<const esapi::Codec*> esapi::DefaultEncoder::codecs;
//esapi::HTMLEntityCodec esapi::DefaultEncoder::htmlCodec;
//esapi::DefaultEncoder::ldapCodec = new esapi::LDAPCodec;
//esapi::XMLEntityCodec esapi::DefaultEncoder::xmlCodec;
//esapi::PercentCodec esapi::DefaultEncoder::percentCodec;
//esapi::JavaScriptCodec esapi::DefaultEncoder::javaScriptCodec;
//esapi::VBScriptCodec esapi::DefaultEncoder::vbScriptCodec;
//esapi::CSSCodec esapi::DefaultEncoder::cssCodec;

const char esapi::DefaultEncoder::IMMUNE_HTML [] = { ',', '.', '-', '_', ' ' };
const char esapi::DefaultEncoder::IMMUNE_HTMLATTR [] = { ',', '.', '-', '_' };
const char esapi::DefaultEncoder::IMMUNE_CSS [] = { '\0' };
const char esapi::DefaultEncoder::IMMUNE_JAVASCRIPT [] = { ',', '.', '_' };
const char esapi::DefaultEncoder::IMMUNE_VBSCRIPT [] = { ',', '.', '_' };
const char esapi::DefaultEncoder::IMMUNE_XML [] = { ',', '.', '-', '_', ' ' };
const char esapi::DefaultEncoder::IMMUNE_SQL [] = { ' ' };
const char esapi::DefaultEncoder::IMMUNE_OS [] = { '-' };
const char esapi::DefaultEncoder::IMMUNE_XMLATTR [] = { ',', '.', '-', '_' };
const char esapi::DefaultEncoder::IMMUNE_XPATH [] = { ',', '.', '-', '_', ' ' };

esapi::DefaultEncoder::DefaultEncoder()
  : codecs(), ldapCodec()
{
	//esapi::LDAPCodec ldapCodec = new esapi::LDAPCodec;
/*
                codecs.as->dd( htmlCodec );
                codecs.aldd( percentCodec );
                codecs.add( javaScriptCodec );
 */
}

const esapi::Encoder& esapi::DefaultEncoder::getInstance() {
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

esapi::DefaultEncoder::DefaultEncoder( std::list<std::string> codecNames)
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
}

std::string esapi::DefaultEncoder::canonicalize( const std::string & input) {
	/* TODO Use security configuration
        // Issue 231 - These are reverse boolean logic in the Encoder interface, so we need to invert these values - CS
                return canonicalize(input,
                                                        !ESAPI.securityConfiguration().getAllowMultipleEncoding(),
                                                        !ESAPI.securityConfiguration().getAllowMixedEncoding() );
	 */
	if ( input.compare("") == 0 ) {
			return NULL;
	}
	return canonicalize(input, false, false);
}

std::string esapi::DefaultEncoder::canonicalize( const std::string & input, bool strict) {
	return canonicalize(input, strict, strict);
}

std::string esapi::DefaultEncoder::canonicalize( const std::string & input, bool restrictMultiple, bool restrictMixed) {
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
                throw new IntrusionException( "Input validation failure", "Multiple ("+ foundCount +"x) and mixed encoding ("+ mixedCount +"x) detected in " + input );
            } else {
                logger.warning( Logger.SECURITY_FAILURE, "Multiple ("+ foundCount +"x) and mixed encoding ("+ mixedCount +"x) detected in " + input );
            }
        }
        else if ( foundCount >= 2 ) {
            if ( restrictMultiple ) {
                throw new IntrusionException( "Input validation failure", "Multiple ("+ foundCount +"x) encoding detected in " + input );
            } else {
                logger.warning( Logger.SECURITY_FAILURE, "Multiple ("+ foundCount +"x) encoding detected in " + input );
            }
        }
        else if ( mixedCount > 1 ) {
            if ( restrictMixed ) {
                throw new IntrusionException( "Input validation failure", "Mixed encoding ("+ mixedCount +"x) detected in " + input );
            } else {
                logger.warning( Logger.SECURITY_FAILURE, "Mixed encoding ("+ mixedCount +"x) detected in " + input );
            }
        }
        return working;
	 */

	return "";
}

std::string esapi::DefaultEncoder::encodeForHTML(const std::string & input) {
/*
            if( input == null ) {
                return null;
            }
            return htmlCodec.encode( IMMUNE_HTML, input);
 */

	throw new UnsupportedOperationException("This operation has not yet been implemented.");
}

std::string esapi::DefaultEncoder::decodeForHTML(const std::string & input) {
/*
                if( input == null ) {
                return null;
            }
            return htmlCodec.decode( input);
 */
	throw new UnsupportedOperationException("This operation has not yet been implemented.");
}

std::string esapi::DefaultEncoder::encodeForHTMLAttribute(const std::string & input) {
/*
            if( input == null ) {
                return null;
            }
            return htmlCodec.encode( IMMUNE_HTMLATTR, input)
 */

	throw new UnsupportedOperationException("This operation has not yet been implemented.");
}

std::string esapi::DefaultEncoder::encodeForCSS(const std::string & input) {
/*
            if( input == null ) {
                return null;
            }
            return cssCodec.encode( IMMUNE_CSS, input);
 */
	throw new UnsupportedOperationException("This operation has not yet been implemented.");
}

std::string esapi::DefaultEncoder::encodeForJavaScript(const std::string & input) {
/*
            if( input == null ) {
                return null;
            }
            return javaScriptCodec.encode(IMMUNE_JAVASCRIPT, input);
 */
	throw new UnsupportedOperationException("This operation has not yet been implemented.");
}

std::string esapi::DefaultEncoder::encodeForVBScript(const std::string & input) {
/*
            if( input == null ) {
                return null;
            }
            return vbScriptCodec.encode(IMMUNE_VBSCRIPT, input);
 */
	throw new UnsupportedOperationException("This operation has not yet been implemented.");
}

std::string esapi::DefaultEncoder::encodeForSQL(const Codec &codec, const std::string & input) {
/*
            if( input == null ) {
                return null;
            }
            return codec.encode(IMMUNE_SQL, input);
 */
	throw new UnsupportedOperationException("This operation has not yet been implemented.");
}

std::string esapi::DefaultEncoder::encodeForOS(const Codec *codec, const std::string & input) {
	ASSERT(codec);

	if (codec == nullptr)
		throw new NullPointerException("encoderForOS(..) : Null pointer to codec");

	if( input.compare("") == 0) {
		return NULL;
	}

	return (*codec).encode( IMMUNE_OS, sizeof(IMMUNE_OS)/sizeof(char), input);

}

std::string esapi::DefaultEncoder::encodeForLDAP(const std::string & input) {
    if( input.compare("") == 0) {
        return NULL;
    }
    return ldapCodec.encode( "", 0, input);
}

std::string esapi::DefaultEncoder::encodeForDN(const std::string & input) {
/*
            if( input == null ) {
                return null;
            }
                // TODO: replace with DN codec
            StringBuilder sb = new StringBuilder();
                if ((input.length() > 0) && ((input.charAt(0) == ' ') || (input.charAt(0) == '#'))) {
                        sb.append('\\'); // add the leading backslash if needed
                }
                for (int i = 0; i < input.length(); i++) {
                        char c = input.charAt(i);
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
                if ((input.length() > 1) && (input.charAt(input.length() - 1) == ' ')) {
                        sb.insert(sb.length() - 1, '\\');
                }
                return sb.toString();
 */
	throw new UnsupportedOperationException("This operation has not yet been implemented.");
}

std::string esapi::DefaultEncoder::encodeForXPath(const std::string & input) {
/*
            if( input == null ) {
                return null;
            }
            return htmlCodec.encode( IMMUNE_XPATH, input);
 */
	throw new UnsupportedOperationException("This operation has not yet been implemented.");
}

std::string esapi::DefaultEncoder::encodeForXML(const std::string & input) {
/*
            if( input == null ) {
                return null;
            }
            return xmlCodec.encode( IMMUNE_XML, input);
 */
	throw new UnsupportedOperationException("This operation has not yet been implemented.");
}

std::string esapi::DefaultEncoder::encodeForXMLAttribute(const std::string & input) {
/*
            if( input == null ) {
                return null;
            }
            return xmlCodec.encode( IMMUNE_XMLATTR, input);
 */
	throw new UnsupportedOperationException("This operation has not yet been implemented.");
}

std::string esapi::DefaultEncoder::encodeForURL(const std::string & input) throw (EncodingException) {
/*
                if ( input == null ) {
                        return null;
                }
                try {
                        return URLEncoder.encode(input, ESAPI.securityConfiguration().getCharacterEncoding());
                } catch (UnsupportedEncodingException ex) {
                        throw new EncodingException("Encoding failure", "Character encoding not supported", ex);
                } catch (Exception e) {
                        throw new EncodingException("Encoding failure", "Problem URL encoding input", e);
                }
 */
	throw new UnsupportedOperationException("This operation has not yet been implemented.");
}

std::string esapi::DefaultEncoder::decodeFromURL(const std::string & input) throw (EncodingException) {
/*
                if ( input == null ) {
                        return null;
                }
                String canonical = canonicalize(input);
                try {
                        return URLDecoder.decode(canonical, ESAPI.securityConfiguration().getCharacterEncoding());
                } catch (UnsupportedEncodingException ex) {
                        throw new EncodingException("Decoding failed", "Character encoding not supported", ex);
                } catch (Exception e) {
                        throw new EncodingException("Decoding failed", "Problem URL decoding input", e);
                }
 */
	throw new UnsupportedOperationException("This operation has not yet been implemented.");
}

std::string esapi::DefaultEncoder::encodeForBase64(const std::string & input, bool wrap) {
	if ( input.compare("") == 0 )
			return NULL;

	std::string encoded;

	CryptoPP::StringSource(input, true, new CryptoPP::Base64Encoder(new
	CryptoPP::StringSink(encoded), wrap));

	return encoded;
}

std::string esapi::DefaultEncoder::encodeForBase64(const std::string & input) {
	return this->encodeForBase64(input, false);
}

std::string esapi::DefaultEncoder::decodeFromBase64(const std::string & input) {
	if ( input.compare("") == 0)
            return NULL;

	std::string decoded;

	CryptoPP::StringSource(input, true, new CryptoPP::Base64Decoder(new
	CryptoPP::StringSink(decoded)));

	return decoded;
}
