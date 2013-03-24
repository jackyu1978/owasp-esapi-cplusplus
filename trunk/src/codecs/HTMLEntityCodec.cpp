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
#include "util/TextConvert.h"
#include "codecs/HTMLEntityCodec.h"

#include <string>
#include <sstream>
#include <iomanip>
#include <cctype>

namespace esapi
{
  NarrowString HTMLEntityCodec::REPLACEMENT_CHAR()
  {
    return NarrowString("\xFF\xDD");
  }

  const NarrowString& HTMLEntityCodec::REPLACEMENT_HEX()
  {
    static const NarrowString str("fffd");
    return str;
  }

  const NarrowString& HTMLEntityCodec::REPLACEMENT_STR()
  {
    static const NarrowString str("\xFF\xDD");
    return str;
  }

  NarrowString HTMLEntityCodec::getNumericEntity(PushbackString&) {
    /*
    Character first = input.peek();
    if ( first == null ) return null;

    if (first == L'x' || first == L'X' ) {
    input.next();
    return parseHex( input );
    }
    return parseNumber( input );
    */
    return 0;
  }

  NarrowString HTMLEntityCodec::parseNumber(PushbackString& /*input*/) {
    /*
    StringBuilder sb = new StringBuilder();
    while( input.hasNext() ) {
    Character c = input.peek();

    // if character is a digit then add it on and keep going
    if ( Character.isDigit( c.charValue() ) ) {
    sb.append( c );
    input.next();

    // if character is a semi-colon, eat it and quit
    } else if (c == L';' ) {
    input.next();
    break;

    // otherwise just quit
    } else {
    break;
    }
    }
    try {
    int i = Integer.parseInt(sb.toString());
    if (Character.isValidCodePoint(i)) {
    return (Char) i;
    }
    } catch( NumberFormatException e ) {
    // throw an exception for malformed entity?
    }
    return null;
    */
    return 0;
  }

  NarrowString HTMLEntityCodec::parseHex(PushbackString&) {
    /*
    StringBuilder sb = new StringBuilder();
    while( input.hasNext() ) {
    Character c = input.peek();

    // if character is a hex digit then add it on and keep going
    if ( "0123456789ABCDEFabcdef".indexOf(c) != -1 ) {
    sb.append( c );
    input.next();

    // if character is a semi-colon, eat it and quit
    } else if (c == L';' ) {
    input.next();
    break;

    // otherwise just quit
    } else {
    break;
    }
    }
    try {
    int i = Integer.parseInt(sb.toString(), 16);
    if (Character.isValidCodePoint(i)) {
    return (Char) i;
    }
    } catch( NumberFormatException e ) {
    // throw an exception for malformed entity?
    }
    return null;
    */
    return 0;
  }

  NarrowString HTMLEntityCodec::getNamedEntity(PushbackString&) {
    /*
    StringBuilder possible = new StringBuilder();
    Map.Entry<CharSequence,Character> entry;
    int len;

    // kludge around PushbackString....
    len = Math.min(input.remainder().length(), entityToCharacterTrie.getMaxKeyLength());
    for(int i=0;i<len;i++)
    possible.append(Character.toLowerCase(input.next()));

    // look up the longest match
    entry = entityToCharacterTrie.getLongestMatch(possible);
    if(entry == null)
    return null; // no match, caller will reset input

    // fixup input
    input.reset();
    input.next(); // read &
    len = entry.getKey().length(); // what matched's length
    for(int i=0;i<len;i++)
    input.next();

    // check for a trailing semicolen
    if(input.peek(L';'))
    input.next();

    return entry.getValue();
    */
    return 0;
  }

  /**
  * Retrieve the class wide intialization lock.
  * @return the mutex used to lock the class.
  */
  Mutex& HTMLEntityCodec::getClassMutex()
  {
    static Mutex s_mutex;
    return s_mutex;
  }

  /**
  * Build a unmodifiable Map from entity Character to Name.
  * @return Unmodifiable map.
  */
  const HTMLEntityCodec::EntityMap& HTMLEntityCodec::getCharacterToEntityMap()
  {
    MutexLock lock(getClassMutex());

    static volatile bool init = false;
    static shared_ptr<EntityMap> map;

    MEMORY_BARRIER();
    if(!init)
    {
      shared_ptr<EntityMap> temp(new EntityMap);
      ASSERT(nullptr != temp.get());

      // Convenience
      EntityMap& tm = *temp.get();

      // 252 items, but no reserve() on std::map
      tm[TextConvert::WideToNarrow(WideString(1,34))] = "quot"; /* quotation mark */
      tm[TextConvert::WideToNarrow(WideString(1,38))] = "amp"; /* ampersand */
      tm[TextConvert::WideToNarrow(WideString(1,60))] = "lt"; /* less-than sign */
      tm[TextConvert::WideToNarrow(WideString(1,62))] = "gt"; /* greater-than sign */
      tm[TextConvert::WideToNarrow(WideString(1,160))] = "nbsp"; /* no-break space */
      tm[TextConvert::WideToNarrow(WideString(1,161))] = "iexcl"; /* inverted exclamation mark */
      tm[TextConvert::WideToNarrow(WideString(1,162))] = "cent"; /* cent sign */
      tm[TextConvert::WideToNarrow(WideString(1,163))] = "pound"; /* pound sign */
      tm[TextConvert::WideToNarrow(WideString(1,164))] = "curren"; /* currency sign */
      tm[TextConvert::WideToNarrow(WideString(1,165))] = "yen"; /* yen sign */
      tm[TextConvert::WideToNarrow(WideString(1,166))] = "brvbar"; /* broken bar */
      tm[TextConvert::WideToNarrow(WideString(1,167))] = "sect"; /* section sign */
      tm[TextConvert::WideToNarrow(WideString(1,168))] = "uml"; /* diaeresis */
      tm[TextConvert::WideToNarrow(WideString(1,169))] = "copy"; /* copyright sign */
      tm[TextConvert::WideToNarrow(WideString(1,170))] = "ordf"; /* feminine ordinal indicator */
      tm[TextConvert::WideToNarrow(WideString(1,171))] = "laquo"; /* left-pointing double angle quotation mark */
      tm[TextConvert::WideToNarrow(WideString(1,172))] = "not"; /* not sign */
      tm[TextConvert::WideToNarrow(WideString(1,173))] = "shy"; /* soft hyphen */
      tm[TextConvert::WideToNarrow(WideString(1,174))] = "reg"; /* registered sign */
      tm[TextConvert::WideToNarrow(WideString(1,175))] = "macr"; /* macron */
      tm[TextConvert::WideToNarrow(WideString(1,176))] = "deg"; /* degree sign */
      tm[TextConvert::WideToNarrow(WideString(1,177))] = "plusmn"; /* plus-minus sign */
      tm[TextConvert::WideToNarrow(WideString(1,178))] = "sup2"; /* superscript two */
      tm[TextConvert::WideToNarrow(WideString(1,179))] = "sup3"; /* superscript three */
      tm[TextConvert::WideToNarrow(WideString(1,180))] = "acute"; /* acute accent */
      tm[TextConvert::WideToNarrow(WideString(1,181))] = "micro"; /* micro sign */
      tm[TextConvert::WideToNarrow(WideString(1,182))] = "para"; /* pilcrow sign */
      tm[TextConvert::WideToNarrow(WideString(1,183))] = "middot"; /* middle dot */
      tm[TextConvert::WideToNarrow(WideString(1,184))] = "cedil"; /* cedilla */
      tm[TextConvert::WideToNarrow(WideString(1,185))] = "sup1"; /* superscript one */
      tm[TextConvert::WideToNarrow(WideString(1,186))] = "ordm"; /* masculine ordinal indicator */
      tm[TextConvert::WideToNarrow(WideString(1,187))] = "raquo"; /* right-pointing double angle quotation mark */
      tm[TextConvert::WideToNarrow(WideString(1,188))] = "frac14"; /* vulgar fraction one quarter */
      tm[TextConvert::WideToNarrow(WideString(1,189))] = "frac12"; /* vulgar fraction one half */
      tm[TextConvert::WideToNarrow(WideString(1,190))] = "frac34"; /* vulgar fraction three quarters */
      tm[TextConvert::WideToNarrow(WideString(1,191))] = "iquest"; /* inverted question mark */
      tm[TextConvert::WideToNarrow(WideString(1,192))] = "Agrave"; /* Latin capital letter a with grave */
      tm[TextConvert::WideToNarrow(WideString(1,193))] = "Aacute"; /* Latin capital letter a with acute */
      tm[TextConvert::WideToNarrow(WideString(1,194))] = "Acirc"; /* Latin capital letter a with circumflex */
      tm[TextConvert::WideToNarrow(WideString(1,195))] = "Atilde"; /* Latin capital letter a with tilde */
      tm[TextConvert::WideToNarrow(WideString(1,196))] = "Aum"; /* Latin capital letter a with diaeresis */
      tm[TextConvert::WideToNarrow(WideString(1,197))] = "Aring"; /* Latin capital letter a with ring above */
      tm[TextConvert::WideToNarrow(WideString(1,198))] = "AElig"; /* Latin capital letter ae */
      tm[TextConvert::WideToNarrow(WideString(1,199))] = "Ccedil"; /* Latin capital letter c with cedilla */
      tm[TextConvert::WideToNarrow(WideString(1,200))] = "Egrave"; /* Latin capital letter e with grave */
      tm[TextConvert::WideToNarrow(WideString(1,201))] = "Eacute"; /* Latin capital letter e with acute */
      tm[TextConvert::WideToNarrow(WideString(1,202))] = "Ecirc"; /* Latin capital letter e with circumflex */
      tm[TextConvert::WideToNarrow(WideString(1,203))] = "Euml"; /* Latin capital letter e with diaeresis */
      tm[TextConvert::WideToNarrow(WideString(1,204))] = "Igrave"; /* Latin capital letter i with grave */
      tm[TextConvert::WideToNarrow(WideString(1,205))] = "Iacute"; /* Latin capital letter i with acute */
      tm[TextConvert::WideToNarrow(WideString(1,206))] = "Icirc"; /* Latin capital letter i with circumflex */
      tm[TextConvert::WideToNarrow(WideString(1,207))] = "Iuml"; /* Latin capital letter i with diaeresis */
      tm[TextConvert::WideToNarrow(WideString(1,208))] = "ETH"; /* Latin capital letter eth */
      tm[TextConvert::WideToNarrow(WideString(1,209))] = "Ntilde"; /* Latin capital letter n with tilde */
      tm[TextConvert::WideToNarrow(WideString(1,210))] = "Ograve"; /* Latin capital letter o with grave */
      tm[TextConvert::WideToNarrow(WideString(1,211))] = "Oacute"; /* Latin capital letter o with acute */
      tm[TextConvert::WideToNarrow(WideString(1,212))] = "Ocirc"; /* Latin capital letter o with circumflex */
      tm[TextConvert::WideToNarrow(WideString(1,213))] = "Otilde"; /* Latin capital letter o with tilde */
      tm[TextConvert::WideToNarrow(WideString(1,214))] = "Ouml"; /* Latin capital letter o with diaeresis */
      tm[TextConvert::WideToNarrow(WideString(1,215))] = "times"; /* multiplication sign */
      tm[TextConvert::WideToNarrow(WideString(1,216))] = "Oslash"; /* Latin capital letter o with stroke */
      tm[TextConvert::WideToNarrow(WideString(1,217))] = "Ugrave"; /* Latin capital letter u with grave */
      tm[TextConvert::WideToNarrow(WideString(1,218))] = "Uacute"; /* Latin capital letter u with acute */
      tm[TextConvert::WideToNarrow(WideString(1,219))] = "Ucirc"; /* Latin capital letter u with circumflex */
      tm[TextConvert::WideToNarrow(WideString(1,220))] = "Uuml"; /* Latin capital letter u with diaeresis */
      tm[TextConvert::WideToNarrow(WideString(1,221))] = "Yacute"; /* Latin capital letter y with acute */
      tm[TextConvert::WideToNarrow(WideString(1,222))] = "THORN"; /* Latin capital letter thorn */
      tm[TextConvert::WideToNarrow(WideString(1,223))] = "szlig"; /* Latin small letter sharp sXCOMMAX German Eszett */
      tm[TextConvert::WideToNarrow(WideString(1,224))] = "agrave"; /* Latin small letter a with grave */
      tm[TextConvert::WideToNarrow(WideString(1,225))] = "aacute"; /* Latin small letter a with acute */
      tm[TextConvert::WideToNarrow(WideString(1,226))] = "acirc"; /* Latin small letter a with circumflex */
      tm[TextConvert::WideToNarrow(WideString(1,227))] = "atilde"; /* Latin small letter a with tilde */
      tm[TextConvert::WideToNarrow(WideString(1,228))] = "auml"; /* Latin small letter a with diaeresis */
      tm[TextConvert::WideToNarrow(WideString(1,229))] = "aring"; /* Latin small letter a with ring above */
      tm[TextConvert::WideToNarrow(WideString(1,230))] = "aelig"; /* Latin lowercase ligature ae */
      tm[TextConvert::WideToNarrow(WideString(1,231))] = "ccedil"; /* Latin small letter c with cedilla */
      tm[TextConvert::WideToNarrow(WideString(1,232))] = "egrave"; /* Latin small letter e with grave */
      tm[TextConvert::WideToNarrow(WideString(1,233))] = "eacute"; /* Latin small letter e with acute */
      tm[TextConvert::WideToNarrow(WideString(1,234))] = "ecirc"; /* Latin small letter e with circumflex */
      tm[TextConvert::WideToNarrow(WideString(1,235))] = "euml"; /* Latin small letter e with diaeresis */
      tm[TextConvert::WideToNarrow(WideString(1,236))] = "igrave"; /* Latin small letter i with grave */
      tm[TextConvert::WideToNarrow(WideString(1,237))] = "iacute"; /* Latin small letter i with acute */
      tm[TextConvert::WideToNarrow(WideString(1,238))] = "icirc"; /* Latin small letter i with circumflex */
      tm[TextConvert::WideToNarrow(WideString(1,239))] = "iuml"; /* Latin small letter i with diaeresis */
      tm[TextConvert::WideToNarrow(WideString(1,240))] = "eth"; /* Latin small letter eth */
      tm[TextConvert::WideToNarrow(WideString(1,241))] = "ntilde"; /* Latin small letter n with tilde */
      tm[TextConvert::WideToNarrow(WideString(1,242))] = "ograve"; /* Latin small letter o with grave */
      tm[TextConvert::WideToNarrow(WideString(1,243))] = "oacute"; /* Latin small letter o with acute */
      tm[TextConvert::WideToNarrow(WideString(1,244))] = "ocirc"; /* Latin small letter o with circumflex */
      tm[TextConvert::WideToNarrow(WideString(1,245))] = "otilde"; /* Latin small letter o with tilde */
      tm[TextConvert::WideToNarrow(WideString(1,246))] = "ouml"; /* Latin small letter o with diaeresis */
      tm[TextConvert::WideToNarrow(WideString(1,247))] = "divide"; /* division sign */
      tm[TextConvert::WideToNarrow(WideString(1,248))] = "oslash"; /* Latin small letter o with stroke */
      tm[TextConvert::WideToNarrow(WideString(1,249))] = "ugrave"; /* Latin small letter u with grave */
      tm[TextConvert::WideToNarrow(WideString(1,250))] = "uacute"; /* Latin small letter u with acute */
      tm[TextConvert::WideToNarrow(WideString(1,251))] = "ucirc"; /* Latin small letter u with circumflex */
      tm[TextConvert::WideToNarrow(WideString(1,252))] = "uuml"; /* Latin small letter u with diaeresis */
      tm[TextConvert::WideToNarrow(WideString(1,253))] = "yacute"; /* Latin small letter y with acute */
      tm[TextConvert::WideToNarrow(WideString(1,254))] = "thorn"; /* Latin small letter thorn */
      tm[TextConvert::WideToNarrow(WideString(1,255))] = "yuml"; /* Latin small letter y with diaeresis */
      tm[TextConvert::WideToNarrow(WideString(1,338))] = "OElig"; /* Latin capital ligature oe */
      tm[TextConvert::WideToNarrow(WideString(1,339))] = "oelig"; /* Latin small ligature oe */
      tm[TextConvert::WideToNarrow(WideString(1,352))] = "Scaron"; /* Latin capital letter s with caron */
      tm[TextConvert::WideToNarrow(WideString(1,353))] = "scaron"; /* Latin small letter s with caron */
      tm[TextConvert::WideToNarrow(WideString(1,376))] = "Yuml"; /* Latin capital letter y with diaeresis */
      tm[TextConvert::WideToNarrow(WideString(1,402))] = "fnof"; /* Latin small letter f with hook */
      tm[TextConvert::WideToNarrow(WideString(1,710))] = "circ"; /* modifier letter circumflex accent */
      tm[TextConvert::WideToNarrow(WideString(1,732))] = "tilde"; /* small tilde */
      tm[TextConvert::WideToNarrow(WideString(1,913))] = "Alpha"; /* Greek capital letter alpha */
      tm[TextConvert::WideToNarrow(WideString(1,914))] = "Beta"; /* Greek capital letter beta */
      tm[TextConvert::WideToNarrow(WideString(1,915))] = "Gamma"; /* Greek capital letter gamma */
      tm[TextConvert::WideToNarrow(WideString(1,916))] = "Delta"; /* Greek capital letter delta */
      tm[TextConvert::WideToNarrow(WideString(1,917))] = "Epsilon"; /* Greek capital letter epsilon */
      tm[TextConvert::WideToNarrow(WideString(1,918))] = "Zeta"; /* Greek capital letter zeta */
      tm[TextConvert::WideToNarrow(WideString(1,919))] = "Eta"; /* Greek capital letter eta */
      tm[TextConvert::WideToNarrow(WideString(1,920))] = "Theta"; /* Greek capital letter theta */
      tm[TextConvert::WideToNarrow(WideString(1,921))] = "Iota"; /* Greek capital letter iota */
      tm[TextConvert::WideToNarrow(WideString(1,922))] = "Kappa"; /* Greek capital letter kappa */
      tm[TextConvert::WideToNarrow(WideString(1,923))] = "Lambda"; /* Greek capital letter lambda */
      tm[TextConvert::WideToNarrow(WideString(1,924))] = "Mu"; /* Greek capital letter mu */
      tm[TextConvert::WideToNarrow(WideString(1,925))] = "Nu"; /* Greek capital letter nu */
      tm[TextConvert::WideToNarrow(WideString(1,926))] = "Xi"; /* Greek capital letter xi */
      tm[TextConvert::WideToNarrow(WideString(1,927))] = "Omicron"; /* Greek capital letter omicron */
      tm[TextConvert::WideToNarrow(WideString(1,928))] = "Pi"; /* Greek capital letter pi */
      tm[TextConvert::WideToNarrow(WideString(1,929))] = "Rho"; /* Greek capital letter rho */
      tm[TextConvert::WideToNarrow(WideString(1,931))] = "Sigma"; /* Greek capital letter sigma */
      tm[TextConvert::WideToNarrow(WideString(1,932))] = "Tau"; /* Greek capital letter tau */
      tm[TextConvert::WideToNarrow(WideString(1,933))] = "Upsilon"; /* Greek capital letter upsilon */
      tm[TextConvert::WideToNarrow(WideString(1,934))] = "Phi"; /* Greek capital letter phi */
      tm[TextConvert::WideToNarrow(WideString(1,935))] = "Chi"; /* Greek capital letter chi */
      tm[TextConvert::WideToNarrow(WideString(1,936))] = "Psi"; /* Greek capital letter psi */
      tm[TextConvert::WideToNarrow(WideString(1,937))] = "Omega"; /* Greek capital letter omega */
      tm[TextConvert::WideToNarrow(WideString(1,945))] = "alpha"; /* Greek small letter alpha */
      tm[TextConvert::WideToNarrow(WideString(1,946))] = "beta"; /* Greek small letter beta */
      tm[TextConvert::WideToNarrow(WideString(1,947))] = "gamma"; /* Greek small letter gamma */
      tm[TextConvert::WideToNarrow(WideString(1,948))] = "delta"; /* Greek small letter delta */
      tm[TextConvert::WideToNarrow(WideString(1,949))] = "epsilon"; /* Greek small letter epsilon */
      tm[TextConvert::WideToNarrow(WideString(1,950))] = "zeta"; /* Greek small letter zeta */
      tm[TextConvert::WideToNarrow(WideString(1,951))] = "eta"; /* Greek small letter eta */
      tm[TextConvert::WideToNarrow(WideString(1,952))] = "theta"; /* Greek small letter theta */
      tm[TextConvert::WideToNarrow(WideString(1,953))] = "iota"; /* Greek small letter iota */
      tm[TextConvert::WideToNarrow(WideString(1,954))] = "kappa"; /* Greek small letter kappa */
      tm[TextConvert::WideToNarrow(WideString(1,955))] = "lambda"; /* Greek small letter lambda */
      tm[TextConvert::WideToNarrow(WideString(1,956))] = "mu"; /* Greek small letter mu */
      tm[TextConvert::WideToNarrow(WideString(1,957))] = "nu"; /* Greek small letter nu */
      tm[TextConvert::WideToNarrow(WideString(1,958))] = "xi"; /* Greek small letter xi */
      tm[TextConvert::WideToNarrow(WideString(1,959))] = "omicron"; /* Greek small letter omicron */
      tm[TextConvert::WideToNarrow(WideString(1,960))] = "pi"; /* Greek small letter pi */
      tm[TextConvert::WideToNarrow(WideString(1,961))] = "rho"; /* Greek small letter rho */
      tm[TextConvert::WideToNarrow(WideString(1,962))] = "sigmaf"; /* Greek small letter final sigma */
      tm[TextConvert::WideToNarrow(WideString(1,963))] = "sigma"; /* Greek small letter sigma */
      tm[TextConvert::WideToNarrow(WideString(1,964))] = "tau"; /* Greek small letter tau */
      tm[TextConvert::WideToNarrow(WideString(1,965))] = "upsilon"; /* Greek small letter upsilon */
      tm[TextConvert::WideToNarrow(WideString(1,966))] = "phi"; /* Greek small letter phi */
      tm[TextConvert::WideToNarrow(WideString(1,967))] = "chi"; /* Greek small letter chi */
      tm[TextConvert::WideToNarrow(WideString(1,968))] = "psi"; /* Greek small letter psi */
      tm[TextConvert::WideToNarrow(WideString(1,969))] = "omega"; /* Greek small letter omega */
      tm[TextConvert::WideToNarrow(WideString(1,977))] = "thetasym"; /* Greek theta symbol */
      tm[TextConvert::WideToNarrow(WideString(1,978))] = "upsih"; /* Greek upsilon with hook symbol */
      tm[TextConvert::WideToNarrow(WideString(1,982))] = "piv"; /* Greek pi symbol */
      tm[TextConvert::WideToNarrow(WideString(1,8194))] = "ensp"; /* en space */
      tm[TextConvert::WideToNarrow(WideString(1,8195))] = "emsp"; /* em space */
      tm[TextConvert::WideToNarrow(WideString(1,8201))] = "thinsp"; /* thin space */
      tm[TextConvert::WideToNarrow(WideString(1,8204))] = "zwnj"; /* zero width non-joiner */
      tm[TextConvert::WideToNarrow(WideString(1,8205))] = "zwj"; /* zero width joiner */
      tm[TextConvert::WideToNarrow(WideString(1,8206))] = "lrm"; /* left-to-right mark */
      tm[TextConvert::WideToNarrow(WideString(1,8207))] = "rlm"; /* right-to-left mark */
      tm[TextConvert::WideToNarrow(WideString(1,8211))] = "ndash"; /* en dash */
      tm[TextConvert::WideToNarrow(WideString(1,8212))] = "mdash"; /* em dash */
      tm[TextConvert::WideToNarrow(WideString(1,8216))] = "lsquo"; /* left single quotation mark */
      tm[TextConvert::WideToNarrow(WideString(1,8217))] = "rsquo"; /* right single quotation mark */
      tm[TextConvert::WideToNarrow(WideString(1,8218))] = "sbquo"; /* single low-9 quotation mark */
      tm[TextConvert::WideToNarrow(WideString(1,8220))] = "ldquo"; /* left double quotation mark */
      tm[TextConvert::WideToNarrow(WideString(1,8221))] = "rdquo"; /* right double quotation mark */
      tm[TextConvert::WideToNarrow(WideString(1,8222))] = "bdquo"; /* double low-9 quotation mark */
      tm[TextConvert::WideToNarrow(WideString(1,8224))] = "dagger"; /* dagger */
      tm[TextConvert::WideToNarrow(WideString(1,8225))] = "Dagger"; /* double dagger */
      tm[TextConvert::WideToNarrow(WideString(1,8226))] = "bull"; /* bullet */
      tm[TextConvert::WideToNarrow(WideString(1,8230))] = "hellip"; /* horizontal ellipsis */
      tm[TextConvert::WideToNarrow(WideString(1,8240))] = "permil"; /* per mille sign */
      tm[TextConvert::WideToNarrow(WideString(1,8242))] = "prime"; /* prime */
      tm[TextConvert::WideToNarrow(WideString(1,8243))] = "Prime"; /* double prime */
      tm[TextConvert::WideToNarrow(WideString(1,8249))] = "lsaquo"; /* single left-pointing angle quotation mark */
      tm[TextConvert::WideToNarrow(WideString(1,8250))] = "rsaquo"; /* single right-pointing angle quotation mark */
      tm[TextConvert::WideToNarrow(WideString(1,8254))] = "oline"; /* overline */
      tm[TextConvert::WideToNarrow(WideString(1,8260))] = "frasl"; /* fraction slash */
      tm[TextConvert::WideToNarrow(WideString(1,8364))] = "euro"; /* euro sign */
      tm[TextConvert::WideToNarrow(WideString(1,8465))] = "image"; /* black-letter capital i */
      tm[TextConvert::WideToNarrow(WideString(1,8472))] = "weierp"; /* script capital pXCOMMAX Weierstrass p */
      tm[TextConvert::WideToNarrow(WideString(1,8476))] = "real"; /* black-letter capital r */
      tm[TextConvert::WideToNarrow(WideString(1,8482))] = "trade"; /* trademark sign */
      tm[TextConvert::WideToNarrow(WideString(1,8501))] = "alefsym"; /* alef symbol */
      tm[TextConvert::WideToNarrow(WideString(1,8592))] = "larr"; /* leftwards arrow */
      tm[TextConvert::WideToNarrow(WideString(1,8593))] = "uarr"; /* upwards arrow */
      tm[TextConvert::WideToNarrow(WideString(1,8594))] = "rarr"; /* rightwards arrow */
      tm[TextConvert::WideToNarrow(WideString(1,8595))] = "darr"; /* downwards arrow */
      tm[TextConvert::WideToNarrow(WideString(1,8596))] = "harr"; /* left right arrow */
      tm[TextConvert::WideToNarrow(WideString(1,8629))] = "crarr"; /* downwards arrow with corner leftwards */
      tm[TextConvert::WideToNarrow(WideString(1,8656))] = "lArr"; /* leftwards double arrow */
      tm[TextConvert::WideToNarrow(WideString(1,8657))] = "uArr"; /* upwards double arrow */
      tm[TextConvert::WideToNarrow(WideString(1,8658))] = "rArr"; /* rightwards double arrow */
      tm[TextConvert::WideToNarrow(WideString(1,8659))] = "dArr"; /* downwards double arrow */
      tm[TextConvert::WideToNarrow(WideString(1,8660))] = "hArr"; /* left right double arrow */
      tm[TextConvert::WideToNarrow(WideString(1,8704))] = "forall"; /* for all */
      tm[TextConvert::WideToNarrow(WideString(1,8706))] = "part"; /* partial differential */
      tm[TextConvert::WideToNarrow(WideString(1,8707))] = "exist"; /* there exists */
      tm[TextConvert::WideToNarrow(WideString(1,8709))] = "empty"; /* empty set */
      tm[TextConvert::WideToNarrow(WideString(1,8711))] = "nabla"; /* nabla */
      tm[TextConvert::WideToNarrow(WideString(1,8712))] = "isin"; /* element of */
      tm[TextConvert::WideToNarrow(WideString(1,8713))] = "notin"; /* not an element of */
      tm[TextConvert::WideToNarrow(WideString(1,8715))] = "ni"; /* contains as member */
      tm[TextConvert::WideToNarrow(WideString(1,8719))] = "prod"; /* n-ary product */
      tm[TextConvert::WideToNarrow(WideString(1,8721))] = "sum"; /* n-ary summation */
      tm[TextConvert::WideToNarrow(WideString(1,8722))] = "minus"; /* minus sign */
      tm[TextConvert::WideToNarrow(WideString(1,8727))] = "lowast"; /* asterisk operator */
      tm[TextConvert::WideToNarrow(WideString(1,8730))] = "radic"; /* square root */
      tm[TextConvert::WideToNarrow(WideString(1,8733))] = "prop"; /* proportional to */
      tm[TextConvert::WideToNarrow(WideString(1,8734))] = "infin"; /* infinity */
      tm[TextConvert::WideToNarrow(WideString(1,8736))] = "ang"; /* angle */
      tm[TextConvert::WideToNarrow(WideString(1,8743))] = "and"; /* logical and */
      tm[TextConvert::WideToNarrow(WideString(1,8744))] = "or"; /* logical or */
      tm[TextConvert::WideToNarrow(WideString(1,8745))] = "cap"; /* intersection */
      tm[TextConvert::WideToNarrow(WideString(1,8746))] = "cup"; /* union */
      tm[TextConvert::WideToNarrow(WideString(1,8747))] = "int"; /* integral */
      tm[TextConvert::WideToNarrow(WideString(1,8756))] = "there4"; /* therefore */
      tm[TextConvert::WideToNarrow(WideString(1,8764))] = "sim"; /* tilde operator */
      tm[TextConvert::WideToNarrow(WideString(1,8773))] = "cong"; /* congruent to */
      tm[TextConvert::WideToNarrow(WideString(1,8776))] = "asymp"; /* almost equal to */
      tm[TextConvert::WideToNarrow(WideString(1,8800))] = "ne"; /* not equal to */
      tm[TextConvert::WideToNarrow(WideString(1,8801))] = "equiv"; /* identical toXCOMMAX equivalent to */
      tm[TextConvert::WideToNarrow(WideString(1,8804))] = "le"; /* less-than or equal to */
      tm[TextConvert::WideToNarrow(WideString(1,8805))] = "ge"; /* greater-than or equal to */
      tm[TextConvert::WideToNarrow(WideString(1,8834))] = "sub"; /* subset of */
      tm[TextConvert::WideToNarrow(WideString(1,8835))] = "sup"; /* superset of */
      tm[TextConvert::WideToNarrow(WideString(1,8836))] = "nsub"; /* not a subset of */
      tm[TextConvert::WideToNarrow(WideString(1,8838))] = "sube"; /* subset of or equal to */
      tm[TextConvert::WideToNarrow(WideString(1,8839))] = "supe"; /* superset of or equal to */
      tm[TextConvert::WideToNarrow(WideString(1,8853))] = "oplus"; /* circled plus */
      tm[TextConvert::WideToNarrow(WideString(1,8855))] = "otimes"; /* circled times */
      tm[TextConvert::WideToNarrow(WideString(1,8869))] = "perp"; /* up tack */
      tm[TextConvert::WideToNarrow(WideString(1,8901))] = "sdot"; /* dot operator */
      tm[TextConvert::WideToNarrow(WideString(1,8968))] = "lceil"; /* left ceiling */
      tm[TextConvert::WideToNarrow(WideString(1,8969))] = "rceil"; /* right ceiling */
      tm[TextConvert::WideToNarrow(WideString(1,8970))] = "lfloor"; /* left floor */
      tm[TextConvert::WideToNarrow(WideString(1,8971))] = "rfloor"; /* right floor */
      tm[TextConvert::WideToNarrow(WideString(1,9001))] = "lang"; /* left-pointing angle bracket */
      tm[TextConvert::WideToNarrow(WideString(1,9002))] = "rang"; /* right-pointing angle bracket */
      tm[TextConvert::WideToNarrow(WideString(1,9674))] = "loz"; /* lozenge */
      tm[TextConvert::WideToNarrow(WideString(1,9824))] = "spades"; /* black spade suit */
      tm[TextConvert::WideToNarrow(WideString(1,9827))] = "clubs"; /* black club suit */
      tm[TextConvert::WideToNarrow(WideString(1,9829))] = "hearts"; /* black heart suit */
      tm[TextConvert::WideToNarrow(WideString(1,9830))] = "diams"; /* black diamond suit */

      map.swap(temp);
      init = true;

      MEMORY_BARRIER();

    } // !init

    return *map.get();
  }

  NarrowString HTMLEntityCodec::encodeCharacter(const StringArray& immune, const NarrowString& ch) const
  {
    // ASSERT(!immune.empty());
    ASSERT(!ch.empty());

    if(ch.empty())
      return NarrowString();

    // check for immune characters
    StringArray::const_iterator it1 = std::find(immune.begin(), immune.end(), ch);
    if(it1 != immune.end())
      return ch;

    // check for simple alphanumeric characters
    if(ch.length() == 1 && ::isalnum(ch[0]))
      return ch;

    // check for illegal characterss
    //if ( ( c <= 0x1f && c != L'\t' && c != L'\n' && c != L'\r' ) || ( c >= 0x7f && c <= 0x9f ) )
    //{
    // hex = REPLACEMENT_HEX(); // Let's entity encode this instead of returning it
    // c = REPLACEMENT_CHAR();
    //}

    // check if there's a defined entity
    const EntityMap& map = getCharacterToEntityMap();
    EntityMapIterator it2 = map.find(ch);
    if(it2 != map.end())
      return String("&") + it2->second + String(";");

    // return the hex entity as suggested in the spec
    return NarrowString("&#x") + toHex(ch) + NarrowString(";");
  }

  NarrowString HTMLEntityCodec::decodeCharacter(PushbackString& /*input*/) const {
    /*
    input.mark();
    Character first = input.next();
    if ( first == null ) {
    input.reset();
    return null;
    }

    // if this is not an encoded character, return null
    if (first != L'&' ) {
    input.reset();
    return null;
    }

    // test for numeric encodings
    Character second = input.next();
    if ( second == null ) {
    input.reset();
    return null;
    }

    if (second == L'#' ) {
    // handle numbers
    Character c = getNumericEntity( input );
    if ( c != null ) return c;
    } else if ( Character.isLetter( second.charValue() ) ) {
    // handle entities
    input.pushback( second );
    Character c = getNamedEntity( input );
    if ( c != null ) return c;
    }
    input.reset();
    return null;
    */
    return 0;
  }
} // esapi
