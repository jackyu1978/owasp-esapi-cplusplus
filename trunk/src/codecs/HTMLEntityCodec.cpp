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

  static inline NarrowString WideCharToNarrowStr(wchar_t ch) {
    return TextConvert::WideToNarrow(WideString(1, ch));
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
      tm[WideCharToNarrowStr(34)] = "quot"; /* quotation mark */
      tm[WideCharToNarrowStr(38)] = "amp"; /* ampersand */
      tm[WideCharToNarrowStr(60)] = "lt"; /* less-than sign */
      tm[WideCharToNarrowStr(62)] = "gt"; /* greater-than sign */
      tm[WideCharToNarrowStr(160)] = "nbsp"; /* no-break space */
      tm[WideCharToNarrowStr(161)] = "iexcl"; /* inverted exclamation mark */
      tm[WideCharToNarrowStr(162)] = "cent"; /* cent sign */
      tm[WideCharToNarrowStr(163)] = "pound"; /* pound sign */
      tm[WideCharToNarrowStr(164)] = "curren"; /* currency sign */
      tm[WideCharToNarrowStr(165)] = "yen"; /* yen sign */
      tm[WideCharToNarrowStr(166)] = "brvbar"; /* broken bar */
      tm[WideCharToNarrowStr(167)] = "sect"; /* section sign */
      tm[WideCharToNarrowStr(168)] = "uml"; /* diaeresis */
      tm[WideCharToNarrowStr(169)] = "copy"; /* copyright sign */
      tm[WideCharToNarrowStr(170)] = "ordf"; /* feminine ordinal indicator */
      tm[WideCharToNarrowStr(171)] = "laquo"; /* left-pointing double angle quotation mark */
      tm[WideCharToNarrowStr(172)] = "not"; /* not sign */
      tm[WideCharToNarrowStr(173)] = "shy"; /* soft hyphen */
      tm[WideCharToNarrowStr(174)] = "reg"; /* registered sign */
      tm[WideCharToNarrowStr(175)] = "macr"; /* macron */
      tm[WideCharToNarrowStr(176)] = "deg"; /* degree sign */
      tm[WideCharToNarrowStr(177)] = "plusmn"; /* plus-minus sign */
      tm[WideCharToNarrowStr(178)] = "sup2"; /* superscript two */
      tm[WideCharToNarrowStr(179)] = "sup3"; /* superscript three */
      tm[WideCharToNarrowStr(180)] = "acute"; /* acute accent */
      tm[WideCharToNarrowStr(181)] = "micro"; /* micro sign */
      tm[WideCharToNarrowStr(182)] = "para"; /* pilcrow sign */
      tm[WideCharToNarrowStr(183)] = "middot"; /* middle dot */
      tm[WideCharToNarrowStr(184)] = "cedil"; /* cedilla */
      tm[WideCharToNarrowStr(185)] = "sup1"; /* superscript one */
      tm[WideCharToNarrowStr(186)] = "ordm"; /* masculine ordinal indicator */
      tm[WideCharToNarrowStr(187)] = "raquo"; /* right-pointing double angle quotation mark */
      tm[WideCharToNarrowStr(188)] = "frac14"; /* vulgar fraction one quarter */
      tm[WideCharToNarrowStr(189)] = "frac12"; /* vulgar fraction one half */
      tm[WideCharToNarrowStr(190)] = "frac34"; /* vulgar fraction three quarters */
      tm[WideCharToNarrowStr(191)] = "iquest"; /* inverted question mark */
      tm[WideCharToNarrowStr(192)] = "Agrave"; /* Latin capital letter a with grave */
      tm[WideCharToNarrowStr(193)] = "Aacute"; /* Latin capital letter a with acute */
      tm[WideCharToNarrowStr(194)] = "Acirc"; /* Latin capital letter a with circumflex */
      tm[WideCharToNarrowStr(195)] = "Atilde"; /* Latin capital letter a with tilde */
      tm[WideCharToNarrowStr(196)] = "Aum"; /* Latin capital letter a with diaeresis */
      tm[WideCharToNarrowStr(197)] = "Aring"; /* Latin capital letter a with ring above */
      tm[WideCharToNarrowStr(198)] = "AElig"; /* Latin capital letter ae */
      tm[WideCharToNarrowStr(199)] = "Ccedil"; /* Latin capital letter c with cedilla */
      tm[WideCharToNarrowStr(200)] = "Egrave"; /* Latin capital letter e with grave */
      tm[WideCharToNarrowStr(201)] = "Eacute"; /* Latin capital letter e with acute */
      tm[WideCharToNarrowStr(202)] = "Ecirc"; /* Latin capital letter e with circumflex */
      tm[WideCharToNarrowStr(203)] = "Euml"; /* Latin capital letter e with diaeresis */
      tm[WideCharToNarrowStr(204)] = "Igrave"; /* Latin capital letter i with grave */
      tm[WideCharToNarrowStr(205)] = "Iacute"; /* Latin capital letter i with acute */
      tm[WideCharToNarrowStr(206)] = "Icirc"; /* Latin capital letter i with circumflex */
      tm[WideCharToNarrowStr(207)] = "Iuml"; /* Latin capital letter i with diaeresis */
      tm[WideCharToNarrowStr(208)] = "ETH"; /* Latin capital letter eth */
      tm[WideCharToNarrowStr(209)] = "Ntilde"; /* Latin capital letter n with tilde */
      tm[WideCharToNarrowStr(210)] = "Ograve"; /* Latin capital letter o with grave */
      tm[WideCharToNarrowStr(211)] = "Oacute"; /* Latin capital letter o with acute */
      tm[WideCharToNarrowStr(212)] = "Ocirc"; /* Latin capital letter o with circumflex */
      tm[WideCharToNarrowStr(213)] = "Otilde"; /* Latin capital letter o with tilde */
      tm[WideCharToNarrowStr(214)] = "Ouml"; /* Latin capital letter o with diaeresis */
      tm[WideCharToNarrowStr(215)] = "times"; /* multiplication sign */
      tm[WideCharToNarrowStr(216)] = "Oslash"; /* Latin capital letter o with stroke */
      tm[WideCharToNarrowStr(217)] = "Ugrave"; /* Latin capital letter u with grave */
      tm[WideCharToNarrowStr(218)] = "Uacute"; /* Latin capital letter u with acute */
      tm[WideCharToNarrowStr(219)] = "Ucirc"; /* Latin capital letter u with circumflex */
      tm[WideCharToNarrowStr(220)] = "Uuml"; /* Latin capital letter u with diaeresis */
      tm[WideCharToNarrowStr(221)] = "Yacute"; /* Latin capital letter y with acute */
      tm[WideCharToNarrowStr(222)] = "THORN"; /* Latin capital letter thorn */
      tm[WideCharToNarrowStr(223)] = "szlig"; /* Latin small letter sharp sXCOMMAX German Eszett */
      tm[WideCharToNarrowStr(224)] = "agrave"; /* Latin small letter a with grave */
      tm[WideCharToNarrowStr(225)] = "aacute"; /* Latin small letter a with acute */
      tm[WideCharToNarrowStr(226)] = "acirc"; /* Latin small letter a with circumflex */
      tm[WideCharToNarrowStr(227)] = "atilde"; /* Latin small letter a with tilde */
      tm[WideCharToNarrowStr(228)] = "auml"; /* Latin small letter a with diaeresis */
      tm[WideCharToNarrowStr(229)] = "aring"; /* Latin small letter a with ring above */
      tm[WideCharToNarrowStr(230)] = "aelig"; /* Latin lowercase ligature ae */
      tm[WideCharToNarrowStr(231)] = "ccedil"; /* Latin small letter c with cedilla */
      tm[WideCharToNarrowStr(232)] = "egrave"; /* Latin small letter e with grave */
      tm[WideCharToNarrowStr(233)] = "eacute"; /* Latin small letter e with acute */
      tm[WideCharToNarrowStr(234)] = "ecirc"; /* Latin small letter e with circumflex */
      tm[WideCharToNarrowStr(235)] = "euml"; /* Latin small letter e with diaeresis */
      tm[WideCharToNarrowStr(236)] = "igrave"; /* Latin small letter i with grave */
      tm[WideCharToNarrowStr(237)] = "iacute"; /* Latin small letter i with acute */
      tm[WideCharToNarrowStr(238)] = "icirc"; /* Latin small letter i with circumflex */
      tm[WideCharToNarrowStr(239)] = "iuml"; /* Latin small letter i with diaeresis */
      tm[WideCharToNarrowStr(240)] = "eth"; /* Latin small letter eth */
      tm[WideCharToNarrowStr(241)] = "ntilde"; /* Latin small letter n with tilde */
      tm[WideCharToNarrowStr(242)] = "ograve"; /* Latin small letter o with grave */
      tm[WideCharToNarrowStr(243)] = "oacute"; /* Latin small letter o with acute */
      tm[WideCharToNarrowStr(244)] = "ocirc"; /* Latin small letter o with circumflex */
      tm[WideCharToNarrowStr(245)] = "otilde"; /* Latin small letter o with tilde */
      tm[WideCharToNarrowStr(246)] = "ouml"; /* Latin small letter o with diaeresis */
      tm[WideCharToNarrowStr(247)] = "divide"; /* division sign */
      tm[WideCharToNarrowStr(248)] = "oslash"; /* Latin small letter o with stroke */
      tm[WideCharToNarrowStr(249)] = "ugrave"; /* Latin small letter u with grave */
      tm[WideCharToNarrowStr(250)] = "uacute"; /* Latin small letter u with acute */
      tm[WideCharToNarrowStr(251)] = "ucirc"; /* Latin small letter u with circumflex */
      tm[WideCharToNarrowStr(252)] = "uuml"; /* Latin small letter u with diaeresis */
      tm[WideCharToNarrowStr(253)] = "yacute"; /* Latin small letter y with acute */
      tm[WideCharToNarrowStr(254)] = "thorn"; /* Latin small letter thorn */
      tm[WideCharToNarrowStr(255)] = "yuml"; /* Latin small letter y with diaeresis */
      tm[WideCharToNarrowStr(338)] = "OElig"; /* Latin capital ligature oe */
      tm[WideCharToNarrowStr(339)] = "oelig"; /* Latin small ligature oe */
      tm[WideCharToNarrowStr(352)] = "Scaron"; /* Latin capital letter s with caron */
      tm[WideCharToNarrowStr(353)] = "scaron"; /* Latin small letter s with caron */
      tm[WideCharToNarrowStr(376)] = "Yuml"; /* Latin capital letter y with diaeresis */
      tm[WideCharToNarrowStr(402)] = "fnof"; /* Latin small letter f with hook */
      tm[WideCharToNarrowStr(710)] = "circ"; /* modifier letter circumflex accent */
      tm[WideCharToNarrowStr(732)] = "tilde"; /* small tilde */
      tm[WideCharToNarrowStr(913)] = "Alpha"; /* Greek capital letter alpha */
      tm[WideCharToNarrowStr(914)] = "Beta"; /* Greek capital letter beta */
      tm[WideCharToNarrowStr(915)] = "Gamma"; /* Greek capital letter gamma */
      tm[WideCharToNarrowStr(916)] = "Delta"; /* Greek capital letter delta */
      tm[WideCharToNarrowStr(917)] = "Epsilon"; /* Greek capital letter epsilon */
      tm[WideCharToNarrowStr(918)] = "Zeta"; /* Greek capital letter zeta */
      tm[WideCharToNarrowStr(919)] = "Eta"; /* Greek capital letter eta */
      tm[WideCharToNarrowStr(920)] = "Theta"; /* Greek capital letter theta */
      tm[WideCharToNarrowStr(921)] = "Iota"; /* Greek capital letter iota */
      tm[WideCharToNarrowStr(922)] = "Kappa"; /* Greek capital letter kappa */
      tm[WideCharToNarrowStr(923)] = "Lambda"; /* Greek capital letter lambda */
      tm[WideCharToNarrowStr(924)] = "Mu"; /* Greek capital letter mu */
      tm[WideCharToNarrowStr(925)] = "Nu"; /* Greek capital letter nu */
      tm[WideCharToNarrowStr(926)] = "Xi"; /* Greek capital letter xi */
      tm[WideCharToNarrowStr(927)] = "Omicron"; /* Greek capital letter omicron */
      tm[WideCharToNarrowStr(928)] = "Pi"; /* Greek capital letter pi */
      tm[WideCharToNarrowStr(929)] = "Rho"; /* Greek capital letter rho */
      tm[WideCharToNarrowStr(931)] = "Sigma"; /* Greek capital letter sigma */
      tm[WideCharToNarrowStr(932)] = "Tau"; /* Greek capital letter tau */
      tm[WideCharToNarrowStr(933)] = "Upsilon"; /* Greek capital letter upsilon */
      tm[WideCharToNarrowStr(934)] = "Phi"; /* Greek capital letter phi */
      tm[WideCharToNarrowStr(935)] = "Chi"; /* Greek capital letter chi */
      tm[WideCharToNarrowStr(936)] = "Psi"; /* Greek capital letter psi */
      tm[WideCharToNarrowStr(937)] = "Omega"; /* Greek capital letter omega */
      tm[WideCharToNarrowStr(945)] = "alpha"; /* Greek small letter alpha */
      tm[WideCharToNarrowStr(946)] = "beta"; /* Greek small letter beta */
      tm[WideCharToNarrowStr(947)] = "gamma"; /* Greek small letter gamma */
      tm[WideCharToNarrowStr(948)] = "delta"; /* Greek small letter delta */
      tm[WideCharToNarrowStr(949)] = "epsilon"; /* Greek small letter epsilon */
      tm[WideCharToNarrowStr(950)] = "zeta"; /* Greek small letter zeta */
      tm[WideCharToNarrowStr(951)] = "eta"; /* Greek small letter eta */
      tm[WideCharToNarrowStr(952)] = "theta"; /* Greek small letter theta */
      tm[WideCharToNarrowStr(953)] = "iota"; /* Greek small letter iota */
      tm[WideCharToNarrowStr(954)] = "kappa"; /* Greek small letter kappa */
      tm[WideCharToNarrowStr(955)] = "lambda"; /* Greek small letter lambda */
      tm[WideCharToNarrowStr(956)] = "mu"; /* Greek small letter mu */
      tm[WideCharToNarrowStr(957)] = "nu"; /* Greek small letter nu */
      tm[WideCharToNarrowStr(958)] = "xi"; /* Greek small letter xi */
      tm[WideCharToNarrowStr(959)] = "omicron"; /* Greek small letter omicron */
      tm[WideCharToNarrowStr(960)] = "pi"; /* Greek small letter pi */
      tm[WideCharToNarrowStr(961)] = "rho"; /* Greek small letter rho */
      tm[WideCharToNarrowStr(962)] = "sigmaf"; /* Greek small letter final sigma */
      tm[WideCharToNarrowStr(963)] = "sigma"; /* Greek small letter sigma */
      tm[WideCharToNarrowStr(964)] = "tau"; /* Greek small letter tau */
      tm[WideCharToNarrowStr(965)] = "upsilon"; /* Greek small letter upsilon */
      tm[WideCharToNarrowStr(966)] = "phi"; /* Greek small letter phi */
      tm[WideCharToNarrowStr(967)] = "chi"; /* Greek small letter chi */
      tm[WideCharToNarrowStr(968)] = "psi"; /* Greek small letter psi */
      tm[WideCharToNarrowStr(969)] = "omega"; /* Greek small letter omega */
      tm[WideCharToNarrowStr(977)] = "thetasym"; /* Greek theta symbol */
      tm[WideCharToNarrowStr(978)] = "upsih"; /* Greek upsilon with hook symbol */
      tm[WideCharToNarrowStr(982)] = "piv"; /* Greek pi symbol */
      tm[WideCharToNarrowStr(8194)] = "ensp"; /* en space */
      tm[WideCharToNarrowStr(8195)] = "emsp"; /* em space */
      tm[WideCharToNarrowStr(8201)] = "thinsp"; /* thin space */
      tm[WideCharToNarrowStr(8204)] = "zwnj"; /* zero width non-joiner */
      tm[WideCharToNarrowStr(8205)] = "zwj"; /* zero width joiner */
      tm[WideCharToNarrowStr(8206)] = "lrm"; /* left-to-right mark */
      tm[WideCharToNarrowStr(8207)] = "rlm"; /* right-to-left mark */
      tm[WideCharToNarrowStr(8211)] = "ndash"; /* en dash */
      tm[WideCharToNarrowStr(8212)] = "mdash"; /* em dash */
      tm[WideCharToNarrowStr(8216)] = "lsquo"; /* left single quotation mark */
      tm[WideCharToNarrowStr(8217)] = "rsquo"; /* right single quotation mark */
      tm[WideCharToNarrowStr(8218)] = "sbquo"; /* single low-9 quotation mark */
      tm[WideCharToNarrowStr(8220)] = "ldquo"; /* left double quotation mark */
      tm[WideCharToNarrowStr(8221)] = "rdquo"; /* right double quotation mark */
      tm[WideCharToNarrowStr(8222)] = "bdquo"; /* double low-9 quotation mark */
      tm[WideCharToNarrowStr(8224)] = "dagger"; /* dagger */
      tm[WideCharToNarrowStr(8225)] = "Dagger"; /* double dagger */
      tm[WideCharToNarrowStr(8226)] = "bull"; /* bullet */
      tm[WideCharToNarrowStr(8230)] = "hellip"; /* horizontal ellipsis */
      tm[WideCharToNarrowStr(8240)] = "permil"; /* per mille sign */
      tm[WideCharToNarrowStr(8242)] = "prime"; /* prime */
      tm[WideCharToNarrowStr(8243)] = "Prime"; /* double prime */
      tm[WideCharToNarrowStr(8249)] = "lsaquo"; /* single left-pointing angle quotation mark */
      tm[WideCharToNarrowStr(8250)] = "rsaquo"; /* single right-pointing angle quotation mark */
      tm[WideCharToNarrowStr(8254)] = "oline"; /* overline */
      tm[WideCharToNarrowStr(8260)] = "frasl"; /* fraction slash */
      tm[WideCharToNarrowStr(8364)] = "euro"; /* euro sign */
      tm[WideCharToNarrowStr(8465)] = "image"; /* black-letter capital i */
      tm[WideCharToNarrowStr(8472)] = "weierp"; /* script capital pXCOMMAX Weierstrass p */
      tm[WideCharToNarrowStr(8476)] = "real"; /* black-letter capital r */
      tm[WideCharToNarrowStr(8482)] = "trade"; /* trademark sign */
      tm[WideCharToNarrowStr(8501)] = "alefsym"; /* alef symbol */
      tm[WideCharToNarrowStr(8592)] = "larr"; /* leftwards arrow */
      tm[WideCharToNarrowStr(8593)] = "uarr"; /* upwards arrow */
      tm[WideCharToNarrowStr(8594)] = "rarr"; /* rightwards arrow */
      tm[WideCharToNarrowStr(8595)] = "darr"; /* downwards arrow */
      tm[WideCharToNarrowStr(8596)] = "harr"; /* left right arrow */
      tm[WideCharToNarrowStr(8629)] = "crarr"; /* downwards arrow with corner leftwards */
      tm[WideCharToNarrowStr(8656)] = "lArr"; /* leftwards double arrow */
      tm[WideCharToNarrowStr(8657)] = "uArr"; /* upwards double arrow */
      tm[WideCharToNarrowStr(8658)] = "rArr"; /* rightwards double arrow */
      tm[WideCharToNarrowStr(8659)] = "dArr"; /* downwards double arrow */
      tm[WideCharToNarrowStr(8660)] = "hArr"; /* left right double arrow */
      tm[WideCharToNarrowStr(8704)] = "forall"; /* for all */
      tm[WideCharToNarrowStr(8706)] = "part"; /* partial differential */
      tm[WideCharToNarrowStr(8707)] = "exist"; /* there exists */
      tm[WideCharToNarrowStr(8709)] = "empty"; /* empty set */
      tm[WideCharToNarrowStr(8711)] = "nabla"; /* nabla */
      tm[WideCharToNarrowStr(8712)] = "isin"; /* element of */
      tm[WideCharToNarrowStr(8713)] = "notin"; /* not an element of */
      tm[WideCharToNarrowStr(8715)] = "ni"; /* contains as member */
      tm[WideCharToNarrowStr(8719)] = "prod"; /* n-ary product */
      tm[WideCharToNarrowStr(8721)] = "sum"; /* n-ary summation */
      tm[WideCharToNarrowStr(8722)] = "minus"; /* minus sign */
      tm[WideCharToNarrowStr(8727)] = "lowast"; /* asterisk operator */
      tm[WideCharToNarrowStr(8730)] = "radic"; /* square root */
      tm[WideCharToNarrowStr(8733)] = "prop"; /* proportional to */
      tm[WideCharToNarrowStr(8734)] = "infin"; /* infinity */
      tm[WideCharToNarrowStr(8736)] = "ang"; /* angle */
      tm[WideCharToNarrowStr(8743)] = "and"; /* logical and */
      tm[WideCharToNarrowStr(8744)] = "or"; /* logical or */
      tm[WideCharToNarrowStr(8745)] = "cap"; /* intersection */
      tm[WideCharToNarrowStr(8746)] = "cup"; /* union */
      tm[WideCharToNarrowStr(8747)] = "int"; /* integral */
      tm[WideCharToNarrowStr(8756)] = "there4"; /* therefore */
      tm[WideCharToNarrowStr(8764)] = "sim"; /* tilde operator */
      tm[WideCharToNarrowStr(8773)] = "cong"; /* congruent to */
      tm[WideCharToNarrowStr(8776)] = "asymp"; /* almost equal to */
      tm[WideCharToNarrowStr(8800)] = "ne"; /* not equal to */
      tm[WideCharToNarrowStr(8801)] = "equiv"; /* identical toXCOMMAX equivalent to */
      tm[WideCharToNarrowStr(8804)] = "le"; /* less-than or equal to */
      tm[WideCharToNarrowStr(8805)] = "ge"; /* greater-than or equal to */
      tm[WideCharToNarrowStr(8834)] = "sub"; /* subset of */
      tm[WideCharToNarrowStr(8835)] = "sup"; /* superset of */
      tm[WideCharToNarrowStr(8836)] = "nsub"; /* not a subset of */
      tm[WideCharToNarrowStr(8838)] = "sube"; /* subset of or equal to */
      tm[WideCharToNarrowStr(8839)] = "supe"; /* superset of or equal to */
      tm[WideCharToNarrowStr(8853)] = "oplus"; /* circled plus */
      tm[WideCharToNarrowStr(8855)] = "otimes"; /* circled times */
      tm[WideCharToNarrowStr(8869)] = "perp"; /* up tack */
      tm[WideCharToNarrowStr(8901)] = "sdot"; /* dot operator */
      tm[WideCharToNarrowStr(8968)] = "lceil"; /* left ceiling */
      tm[WideCharToNarrowStr(8969)] = "rceil"; /* right ceiling */
      tm[WideCharToNarrowStr(8970)] = "lfloor"; /* left floor */
      tm[WideCharToNarrowStr(8971)] = "rfloor"; /* right floor */
      tm[WideCharToNarrowStr(9001)] = "lang"; /* left-pointing angle bracket */
      tm[WideCharToNarrowStr(9002)] = "rang"; /* right-pointing angle bracket */
      tm[WideCharToNarrowStr(9674)] = "loz"; /* lozenge */
      tm[WideCharToNarrowStr(9824)] = "spades"; /* black spade suit */
      tm[WideCharToNarrowStr(9827)] = "clubs"; /* black club suit */
      tm[WideCharToNarrowStr(9829)] = "hearts"; /* black heart suit */
      tm[WideCharToNarrowStr(9830)] = "diams"; /* black diamond suit */

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
