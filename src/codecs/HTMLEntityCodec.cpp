/**
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * http://www.owasp.org/index.php/ESAPI.
 *
 * Copyright (c) 2011 - The OWASP Foundation
 */

#include "codecs/HTMLEntityCodec.h"
#include "crypto/Crypto++Common.h"
#include <boost/shared_ptr.hpp>

//
// Thread safe, multiprocessor initialization
// http://www.aristeia.com/Papers/DDJ_Jul_Aug_2004_revised.pdf
//

unsigned int esapi::HTMLEntityCodec::REPLACEMENT_CHAR()
{
  return 65533;
}

const std::string& esapi::HTMLEntityCodec::REPLACEMENT_HEX()
{
  static const std::string str("fffd");
  return str;
}

const std::string& esapi::HTMLEntityCodec::REPLACEMENT_STR()
{
  // return "\uFFFD";
  static const char cch[] = { (char)0xff, (char)0xfd, (char)0x00 };
  static const std::string str(cch);
  return str;
}

char esapi::HTMLEntityCodec::getNumericEntity(PushbackString&) {
  /*
    Character first = input.peek();
    if ( first == null ) return null;

    if (first == 'x' || first == 'X' ) {
    input.next();
    return parseHex( input );
    }
    return parseNumber( input );
  */
  return 0;
}

char esapi::HTMLEntityCodec::parseNumber(PushbackString& input) {
  /*
    StringBuilder sb = new StringBuilder();
    while( input.hasNext() ) {
    Character c = input.peek();

    // if character is a digit then add it on and keep going
    if ( Character.isDigit( c.charValue() ) ) {
    sb.append( c );
    input.next();

    // if character is a semi-colon, eat it and quit
    } else if (c == ';' ) {
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
    return (char) i;
    }
    } catch( NumberFormatException e ) {
    // throw an exception for malformed entity?
    }
    return null;
  */
  return 0;
}

char esapi::HTMLEntityCodec::parseHex(PushbackString&) {
  /*
    StringBuilder sb = new StringBuilder();
    while( input.hasNext() ) {
    Character c = input.peek();

    // if character is a hex digit then add it on and keep going
    if ( "0123456789ABCDEFabcdef".indexOf(c) != -1 ) {
    sb.append( c );
    input.next();

    // if character is a semi-colon, eat it and quit
    } else if (c == ';' ) {
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
    return (char) i;
    }
    } catch( NumberFormatException e ) {
    // throw an exception for malformed entity?
    }
    return null;
  */
  return 0;
}

char esapi::HTMLEntityCodec::getNamedEntity(PushbackString&) {
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
    return null;    // no match, caller will reset input

    // fixup input
    input.reset();
    input.next();   // read &
    len = entry.getKey().length();  // what matched's length
    for(int i=0;i<len;i++)
    input.next();

    // check for a trailing semicolen
    if(input.peek(';'))
    input.next();

    return entry.getValue();
  */
  return 0;
}

/**
 * Retrieve the class wide intialization lock.
 * @return the mutex used to lock the class.
 */
esapi::Mutex& esapi::HTMLEntityCodec::getClassMutex()
{
  static esapi::Mutex s_mutex;
  return s_mutex;
}

/**
 * Build a unmodifiable Map from entity Character to Name.
 * @return Unmodifiable map.
 */
const esapi::HTMLEntityCodec::EntityMap& esapi::HTMLEntityCodec::getCharacterToEntityMap()
{
  MutexLock lock(getClassMutex());

  static volatile bool init = false;
  static boost::shared_ptr<EntityMap> map;

  MEMORY_BARRIER();
  if(!init)
    {
      boost::shared_ptr<EntityMap> temp(new EntityMap);
      ASSERT(nullptr != temp.get());
      if(nullptr == temp.get())
        throw std::bad_alloc();

      // Convenience
      EntityMap& tm = *temp.get();

      // 252 items, but no reserve() on std::map
      tm[34]  = "quot";        /* quotation mark */
      tm[38]  = "amp";         /* ampersand */
      tm[60]  = "lt";          /* less-than sign */
      tm[62]  = "gt";          /* greater-than sign */
      tm[160] =    "nbsp";        /* no-break space */
      tm[161] =    "iexcl";       /* inverted exclamation mark */
      tm[162] =    "cent";        /* cent sign */
      tm[163] =    "pound";       /* pound sign */
      tm[164] =    "curren";      /* currency sign */
      tm[165] =    "yen";         /* yen sign */
      tm[166] =    "brvbar";      /* broken bar */
      tm[167] =    "sect";        /* section sign */
      tm[168] =    "uml";         /* diaeresis */
      tm[169] =    "copy";        /* copyright sign */
      tm[170] =    "ordf";        /* feminine ordinal indicator */
      tm[171] =    "laquo";       /* left-pointing double angle quotation mark */
      tm[172] =    "not";         /* not sign */
      tm[173] =    "shy";         /* soft hyphen */
      tm[174] =    "reg";         /* registered sign */
      tm[175] =    "macr";        /* macron */
      tm[176] =    "deg";         /* degree sign */
      tm[177] =    "plusmn";      /* plus-minus sign */
      tm[178] =    "sup2";        /* superscript two */
      tm[179] =    "sup3";        /* superscript three */
      tm[180] =    "acute";       /* acute accent */
      tm[181] =    "micro";       /* micro sign */
      tm[182] =    "para";        /* pilcrow sign */
      tm[183] =    "middot";      /* middle dot */
      tm[184] =    "cedil";       /* cedilla */
      tm[185] =    "sup1";        /* superscript one */
      tm[186] =    "ordm";        /* masculine ordinal indicator */
      tm[187] =    "raquo";       /* right-pointing double angle quotation mark */
      tm[188] =    "frac14";      /* vulgar fraction one quarter */
      tm[189] =    "frac12";      /* vulgar fraction one half */
      tm[190] =    "frac34";      /* vulgar fraction three quarters */
      tm[191] =    "iquest";      /* inverted question mark */
      tm[192] =    "Agrave";      /* Latin capital letter a with grave */
      tm[193] =    "Aacute";      /* Latin capital letter a with acute */
      tm[194] =    "Acirc";       /* Latin capital letter a with circumflex */
      tm[195] =    "Atilde";      /* Latin capital letter a with tilde */
      tm[196] =    "Auml";        /* Latin capital letter a with diaeresis */
      tm[197] =    "Aring";       /* Latin capital letter a with ring above */
      tm[198] =    "AElig";       /* Latin capital letter ae */
      tm[199] =    "Ccedil";      /* Latin capital letter c with cedilla */
      tm[200] =    "Egrave";      /* Latin capital letter e with grave */
      tm[201] =    "Eacute";      /* Latin capital letter e with acute */
      tm[202] =    "Ecirc";       /* Latin capital letter e with circumflex */
      tm[203] =    "Euml";        /* Latin capital letter e with diaeresis */
      tm[204] =    "Igrave";      /* Latin capital letter i with grave */
      tm[205] =    "Iacute";      /* Latin capital letter i with acute */
      tm[206] =    "Icirc";       /* Latin capital letter i with circumflex */
      tm[207] =    "Iuml";        /* Latin capital letter i with diaeresis */
      tm[208] =    "ETH";         /* Latin capital letter eth */
      tm[209] =    "Ntilde";      /* Latin capital letter n with tilde */
      tm[210] =    "Ograve";      /* Latin capital letter o with grave */
      tm[211] =    "Oacute";      /* Latin capital letter o with acute */
      tm[212] =    "Ocirc";       /* Latin capital letter o with circumflex */
      tm[213] =    "Otilde";      /* Latin capital letter o with tilde */
      tm[214] =    "Ouml";        /* Latin capital letter o with diaeresis */
      tm[215] =    "times";       /* multiplication sign */
      tm[216] =    "Oslash";      /* Latin capital letter o with stroke */
      tm[217] =    "Ugrave";      /* Latin capital letter u with grave */
      tm[218] =    "Uacute";      /* Latin capital letter u with acute */
      tm[219] =    "Ucirc";       /* Latin capital letter u with circumflex */
      tm[220] =    "Uuml";        /* Latin capital letter u with diaeresis */
      tm[221] =    "Yacute";      /* Latin capital letter y with acute */
      tm[222] =    "THORN";       /* Latin capital letter thorn */
      tm[223] =    "szlig";       /* Latin small letter sharp sXCOMMAX German Eszett */
      tm[224] =    "agrave";      /* Latin small letter a with grave */
      tm[225] =    "aacute";      /* Latin small letter a with acute */
      tm[226] =    "acirc";       /* Latin small letter a with circumflex */
      tm[227] =    "atilde";      /* Latin small letter a with tilde */
      tm[228] =    "auml";        /* Latin small letter a with diaeresis */
      tm[229] =    "aring";       /* Latin small letter a with ring above */
      tm[230] =    "aelig";       /* Latin lowercase ligature ae */
      tm[231] =    "ccedil";      /* Latin small letter c with cedilla */
      tm[232] =    "egrave";      /* Latin small letter e with grave */
      tm[233] =    "eacute";      /* Latin small letter e with acute */
      tm[234] =    "ecirc";       /* Latin small letter e with circumflex */
      tm[235] =    "euml";        /* Latin small letter e with diaeresis */
      tm[236] =    "igrave";      /* Latin small letter i with grave */
      tm[237] =    "iacute";      /* Latin small letter i with acute */
      tm[238] =    "icirc";       /* Latin small letter i with circumflex */
      tm[239] =    "iuml";        /* Latin small letter i with diaeresis */
      tm[240] =    "eth";         /* Latin small letter eth */
      tm[241] =    "ntilde";      /* Latin small letter n with tilde */
      tm[242] =    "ograve";      /* Latin small letter o with grave */
      tm[243] =    "oacute";      /* Latin small letter o with acute */
      tm[244] =    "ocirc";       /* Latin small letter o with circumflex */
      tm[245] =    "otilde";      /* Latin small letter o with tilde */
      tm[246] =    "ouml";        /* Latin small letter o with diaeresis */
      tm[247] =    "divide";      /* division sign */
      tm[248] =    "oslash";      /* Latin small letter o with stroke */
      tm[249] =    "ugrave";      /* Latin small letter u with grave */
      tm[250] =    "uacute";      /* Latin small letter u with acute */
      tm[251] =    "ucirc";       /* Latin small letter u with circumflex */
      tm[252] =    "uuml";        /* Latin small letter u with diaeresis */
      tm[253] =    "yacute";      /* Latin small letter y with acute */
      tm[254] =    "thorn";       /* Latin small letter thorn */
      tm[255] =    "yuml";        /* Latin small letter y with diaeresis */
      tm[338] =    "OElig";       /* Latin capital ligature oe */
      tm[339] =    "oelig";       /* Latin small ligature oe */
      tm[352] =    "Scaron";      /* Latin capital letter s with caron */
      tm[353] =    "scaron";      /* Latin small letter s with caron */
      tm[376] =    "Yuml";        /* Latin capital letter y with diaeresis */
      tm[402] =    "fnof";        /* Latin small letter f with hook */
      tm[710] =    "circ";        /* modifier letter circumflex accent */
      tm[732] =    "tilde";       /* small tilde */
      tm[913] =    "Alpha";       /* Greek capital letter alpha */
      tm[914] =    "Beta";        /* Greek capital letter beta */
      tm[915] =    "Gamma";       /* Greek capital letter gamma */
      tm[916] =    "Delta";       /* Greek capital letter delta */
      tm[917] =    "Epsilon";     /* Greek capital letter epsilon */
      tm[918] =    "Zeta";        /* Greek capital letter zeta */
      tm[919] =    "Eta";         /* Greek capital letter eta */
      tm[920] =    "Theta";       /* Greek capital letter theta */
      tm[921] =    "Iota";        /* Greek capital letter iota */
      tm[922] =    "Kappa";       /* Greek capital letter kappa */
      tm[923] =    "Lambda";      /* Greek capital letter lambda */
      tm[924] =    "Mu";          /* Greek capital letter mu */
      tm[925] =    "Nu";          /* Greek capital letter nu */
      tm[926] =    "Xi";          /* Greek capital letter xi */
      tm[927] =    "Omicron";     /* Greek capital letter omicron */
      tm[928] =    "Pi";          /* Greek capital letter pi */
      tm[929] =    "Rho";         /* Greek capital letter rho */
      tm[931] =    "Sigma";       /* Greek capital letter sigma */
      tm[932] =    "Tau";         /* Greek capital letter tau */
      tm[933] =    "Upsilon";     /* Greek capital letter upsilon */
      tm[934] =    "Phi";         /* Greek capital letter phi */
      tm[935] =    "Chi";         /* Greek capital letter chi */
      tm[936] =    "Psi";         /* Greek capital letter psi */
      tm[937] =    "Omega";       /* Greek capital letter omega */
      tm[945] =    "alpha";       /* Greek small letter alpha */
      tm[946] =    "beta";        /* Greek small letter beta */
      tm[947] =    "gamma";       /* Greek small letter gamma */
      tm[948] =    "delta";       /* Greek small letter delta */
      tm[949] =    "epsilon";     /* Greek small letter epsilon */
      tm[950] =    "zeta";        /* Greek small letter zeta */
      tm[951] =    "eta";         /* Greek small letter eta */
      tm[952] =    "theta";       /* Greek small letter theta */
      tm[953] =    "iota";        /* Greek small letter iota */
      tm[954] =    "kappa";       /* Greek small letter kappa */
      tm[955] =    "lambda";      /* Greek small letter lambda */
      tm[956] =    "mu";          /* Greek small letter mu */
      tm[957] =    "nu";          /* Greek small letter nu */
      tm[958] =    "xi";          /* Greek small letter xi */
      tm[959] =    "omicron";     /* Greek small letter omicron */
      tm[960] =    "pi";          /* Greek small letter pi */
      tm[961] =    "rho";         /* Greek small letter rho */
      tm[962] =    "sigmaf";      /* Greek small letter final sigma */
      tm[963] =    "sigma";       /* Greek small letter sigma */
      tm[964] =    "tau";         /* Greek small letter tau */
      tm[965] =    "upsilon";     /* Greek small letter upsilon */
      tm[966] =    "phi";         /* Greek small letter phi */
      tm[967] =    "chi";         /* Greek small letter chi */
      tm[968] =    "psi";         /* Greek small letter psi */
      tm[969] =    "omega";       /* Greek small letter omega */
      tm[977] =    "thetasym";    /* Greek theta symbol */
      tm[978] =    "upsih";       /* Greek upsilon with hook symbol */
      tm[982] =    "piv";         /* Greek pi symbol */
      tm[8194] =   "ensp";        /* en space */
      tm[8195] =   "emsp";        /* em space */
      tm[8201] =   "thinsp";      /* thin space */
      tm[8204] =   "zwnj";        /* zero width non-joiner */
      tm[8205] =   "zwj";         /* zero width joiner */
      tm[8206] =   "lrm";         /* left-to-right mark */
      tm[8207] =   "rlm";         /* right-to-left mark */
      tm[8211] =   "ndash";       /* en dash */
      tm[8212] =   "mdash";       /* em dash */
      tm[8216] =   "lsquo";       /* left single quotation mark */
      tm[8217] =   "rsquo";       /* right single quotation mark */
      tm[8218] =   "sbquo";       /* single low-9 quotation mark */
      tm[8220] =   "ldquo";       /* left double quotation mark */
      tm[8221] =   "rdquo";       /* right double quotation mark */
      tm[8222] =   "bdquo";       /* double low-9 quotation mark */
      tm[8224] =   "dagger";      /* dagger */
      tm[8225] =   "Dagger";      /* double dagger */
      tm[8226] =   "bull";        /* bullet */
      tm[8230] =   "hellip";      /* horizontal ellipsis */
      tm[8240] =   "permil";      /* per mille sign */
      tm[8242] =   "prime";       /* prime */
      tm[8243] =   "Prime";       /* double prime */
      tm[8249] =   "lsaquo";      /* single left-pointing angle quotation mark */
      tm[8250] =   "rsaquo";      /* single right-pointing angle quotation mark */
      tm[8254] =   "oline";       /* overline */
      tm[8260] =   "frasl";       /* fraction slash */
      tm[8364] =   "euro";        /* euro sign */
      tm[8465] =   "image";       /* black-letter capital i */
      tm[8472] =   "weierp";      /* script capital pXCOMMAX Weierstrass p */
      tm[8476] =   "real";        /* black-letter capital r */
      tm[8482] =   "trade";       /* trademark sign */
      tm[8501] =   "alefsym";     /* alef symbol */
      tm[8592] =   "larr";        /* leftwards arrow */
      tm[8593] =   "uarr";        /* upwards arrow */
      tm[8594] =   "rarr";        /* rightwards arrow */
      tm[8595] =   "darr";        /* downwards arrow */
      tm[8596] =   "harr";        /* left right arrow */
      tm[8629] =   "crarr";       /* downwards arrow with corner leftwards */
      tm[8656] =   "lArr";        /* leftwards double arrow */
      tm[8657] =   "uArr";        /* upwards double arrow */
      tm[8658] =   "rArr";        /* rightwards double arrow */
      tm[8659] =   "dArr";        /* downwards double arrow */
      tm[8660] =   "hArr";        /* left right double arrow */
      tm[8704] =   "forall";      /* for all */
      tm[8706] =   "part";        /* partial differential */
      tm[8707] =   "exist";       /* there exists */
      tm[8709] =   "empty";       /* empty set */
      tm[8711] =   "nabla";       /* nabla */
      tm[8712] =   "isin";        /* element of */
      tm[8713] =   "notin";       /* not an element of */
      tm[8715] =   "ni";          /* contains as member */
      tm[8719] =   "prod";        /* n-ary product */
      tm[8721] =   "sum";         /* n-ary summation */
      tm[8722] =   "minus";       /* minus sign */
      tm[8727] =   "lowast";      /* asterisk operator */
      tm[8730] =   "radic";       /* square root */
      tm[8733] =   "prop";        /* proportional to */
      tm[8734] =   "infin";       /* infinity */
      tm[8736] =   "ang";         /* angle */
      tm[8743] =   "and";         /* logical and */
      tm[8744] =   "or";          /* logical or */
      tm[8745] =   "cap";         /* intersection */
      tm[8746] =   "cup";         /* union */
      tm[8747] =   "int";         /* integral */
      tm[8756] =   "there4";      /* therefore */
      tm[8764] =   "sim";         /* tilde operator */
      tm[8773] =   "cong";        /* congruent to */
      tm[8776] =   "asymp";       /* almost equal to */
      tm[8800] =   "ne";          /* not equal to */
      tm[8801] =   "equiv";       /* identical toXCOMMAX equivalent to */
      tm[8804] =   "le";          /* less-than or equal to */
      tm[8805] =   "ge";          /* greater-than or equal to */
      tm[8834] =   "sub";         /* subset of */
      tm[8835] =   "sup";         /* superset of */
      tm[8836] =   "nsub";        /* not a subset of */
      tm[8838] =   "sube";        /* subset of or equal to */
      tm[8839] =   "supe";        /* superset of or equal to */
      tm[8853] =   "oplus";       /* circled plus */
      tm[8855] =   "otimes";      /* circled times */
      tm[8869] =   "perp";        /* up tack */
      tm[8901] =   "sdot";        /* dot operator */
      tm[8968] =   "lceil";       /* left ceiling */
      tm[8969] =   "rceil";       /* right ceiling */
      tm[8970] =   "lfloor";      /* left floor */
      tm[8971] =   "rfloor";      /* right floor */
      tm[9001] =   "lang";        /* left-pointing angle bracket */
      tm[9002] =   "rang";        /* right-pointing angle bracket */
      tm[9674] =   "loz";         /* lozenge */
      tm[9824] =   "spades";      /* black spade suit */
      tm[9827] =   "clubs";       /* black club suit */
      tm[9829] =   "hearts";      /* black heart suit */
      tm[9830] =   "diams";       /* black diamond suit */

      map.swap(temp);
      init = true;

      MEMORY_BARRIER();

    } // !init

  return *map.get();
}

std::string esapi::HTMLEntityCodec::encodeCharacter( const char* immune, size_t length, char c) const
{
  ASSERT(immune);
  ASSERT(length);
  /*

  // check for immune characters
  if ( containsCharacter(c, immune ) ) {
  return ""+c;
  }

  // check for alphanumeric characters
  String hex = Codec.getHexForNonAlphanumeric(c);
  if ( hex == null ) {
  return ""+c;
  }

  // check for illegal characters
  if ( ( c <= 0x1f && c != '\t' && c != '\n' && c != '\r' ) || ( c >= 0x7f && c <= 0x9f ) )
  {
  hex = REPLACEMENT_HEX;  // Let's entity encode this instead of returning it
  c = REPLACEMENT_CHAR;
  }

  // check if there's a defined entity
  String entityName = (String) characterToEntityMap.get(c);
  if (entityName != null) {
  return "&" + entityName + ";";
  }

  // return the hex entity as suggested in the spec
  return "&#x" + hex + ";";
  */
  return std::string();
}

char esapi::HTMLEntityCodec::decodeCharacter(PushbackString& input) const {
  /*
    input.mark();
    Character first = input.next();
    if ( first == null ) {
    input.reset();
    return null;
    }

    // if this is not an encoded character, return null
    if (first != '&' ) {
    input.reset();
    return null;
    }

    // test for numeric encodings
    Character second = input.next();
    if ( second == null ) {
    input.reset();
    return null;
    }

    if (second == '#' ) {
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
