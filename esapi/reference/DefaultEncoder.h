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
    static const StringArray IMMUNE_HTML;
    static const StringArray IMMUNE_HTMLATTR;
    static const StringArray IMMUNE_CSS;
    static const StringArray IMMUNE_JAVASCRIPT;
    static const StringArray IMMUNE_VBSCRIPT;
    static const StringArray IMMUNE_XML;
    static const StringArray IMMUNE_SQL;
    static const StringArray IMMUNE_OS;
    static const StringArray IMMUNE_XMLATTR;
    static const StringArray IMMUNE_XPATH;

  protected:
    DefaultEncoder();

  public:
    static const Encoder& getInstance();

    DefaultEncoder( std::set<String> );

    /**
    * {@inheritDoc}
    */
    String canonicalize( const NarrowString & );

    /**
    * {@inheritDoc}
    */
    String canonicalize( const NarrowString & , bool);

    /**
    * {@inheritDoc}
    */
    String canonicalize( const NarrowString & , bool, bool );

    /**
    * {@inheritDoc}
    */
    String encodeForHTML(const NarrowString &);

    /**
    * {@inheritDoc}
    */
    String decodeForHTML(const NarrowString &);

    /**
    * {@inheritDoc}
    */
    String encodeForHTMLAttribute(const NarrowString &);

    /**
    * {@inheritDoc}
    */
    String encodeForCSS(const NarrowString &);

    /**
    * {@inheritDoc}
    */
    String encodeForJavaScript(const NarrowString &);

    /**
    * {@inheritDoc}
    */
    String encodeForVBScript(const NarrowString &);

    /**
    * {@inheritDoc}
    */
    String encodeForSQL(const Codec&, const NarrowString &);

    /**
    * {@inheritDoc}
    */
    NarrowString encodeForOS(const Codec&, const NarrowString &);

    /**
    * {@inheritDoc}
    */
    String encodeForLDAP(const NarrowString &);

    /**
    * {@inheritDoc}
    */
    String encodeForDN(const NarrowString &);

    /**
    * {@inheritDoc}
    */
    String encodeForXPath(const NarrowString &);

    /**
    * {@inheritDoc}
    */
    String encodeForXML(const NarrowString &);

    /**
    * {@inheritDoc}
    */
    String encodeForXMLAttribute(const NarrowString &);

    /**
    * {@inheritDoc}
    */
    String encodeForURL(const NarrowString &) throw (EncodingException);

    /**
    * {@inheritDoc}
    */
    String decodeFromURL(const NarrowString &) throw (EncodingException);

    /**
    * {@inheritDoc}
    */
    String encodeForBase64(const NarrowString &, bool);

    /*
    * For simplicity of calling encodeForBase64(const NarrowString &, bool);
    */
    String encodeForBase64(const NarrowString &);

    /**
    * {@inheritDoc}
    */
    String decodeFromBase64(const NarrowString &);
  };
} // NAMESPACE

