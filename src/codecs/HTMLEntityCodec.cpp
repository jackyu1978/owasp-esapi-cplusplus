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

//const char esapi::HTMLEntityCodec::REPLACEMENT_CHAR = '\uFFFD';
const std::string esapi::HTMLEntityCodec::REPLACEMENT_HEX = "fffd";
const std::string esapi::HTMLEntityCodec::REPLACEMENT_STR = "" + esapi::HTMLEntityCodec::REPLACEMENT_CHAR;
esapi::Mutex esapi::HTMLEntityCodec::s_mutex;
const std::map<char,std::string> esapi::HTMLEntityCodec::characterToEntityMap = mkCharacterToEntityMap();

//TODO
//Trie<Character> entityToCharacterTrie  = mkEntityToCharacterTrie();

char esapi::HTMLEntityCodec::getNumericEntity( PushbackString ) {
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

char esapi::HTMLEntityCodec::parseNumber( PushbackString input ) {
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

char esapi::HTMLEntityCodec::parseHex( PushbackString ) {
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

char esapi::HTMLEntityCodec::getNamedEntity( PushbackString ) {
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

const std::map<char,std::string>& esapi::HTMLEntityCodec::mkCharacterToEntityMap() {
  // Double checked intialization
  static volatile bool init = false;
  static std::map<char, std::string> map;

  // First check
  if(!init)
  {
    // Acquire the lock
    MutexAutoLock lock(s_mutex);

    // Verify we did not acquire the lock after another thread initialized and and released
    if(!init)
    {
      map[(char)34]  = "quot";        /* quotation mark */
      map[(char)38]  = "amp";         /* ampersand */
      map[(char)60]  = "lt";          /* less-than sign */
      map[(char)62]  = "gt";          /* greater-than sign */
      map[(char)160] =    "nbsp";        /* no-break space */
      map[(char)161] =    "iexcl";       /* inverted exclamation mark */
      map[(char)162] =    "cent";        /* cent sign */
      map[(char)163] =    "pound";       /* pound sign */
      map[(char)164] =    "curren";      /* currency sign */
      map[(char)165] =    "yen";         /* yen sign */
      map[(char)166] =    "brvbar";      /* broken bar */
      map[(char)167] =    "sect";        /* section sign */
      map[(char)168] =    "uml";         /* diaeresis */
      map[(char)169] =    "copy";        /* copyright sign */
      map[(char)170] =    "ordf";        /* feminine ordinal indicator */
      map[(char)171] =    "laquo";       /* left-pointing double angle quotation mark */
      map[(char)172] =    "not";         /* not sign */
      map[(char)173] =    "shy";         /* soft hyphen */
      map[(char)174] =    "reg";         /* registered sign */
      map[(char)175] =    "macr";        /* macron */
      map[(char)176] =    "deg";         /* degree sign */
      map[(char)177] =    "plusmn";      /* plus-minus sign */
      map[(char)178] =    "sup2";        /* superscript two */
      map[(char)179] =    "sup3";        /* superscript three */
      map[(char)180] =    "acute";       /* acute accent */
      map[(char)181] =    "micro";       /* micro sign */
      map[(char)182] =    "para";        /* pilcrow sign */
      map[(char)183] =    "middot";      /* middle dot */
      map[(char)184] =    "cedil";       /* cedilla */
      map[(char)185] =    "sup1";        /* superscript one */
      map[(char)186] =    "ordm";        /* masculine ordinal indicator */
      map[(char)187] =    "raquo";       /* right-pointing double angle quotation mark */
      map[(char)188] =    "frac14";      /* vulgar fraction one quarter */
      map[(char)189] =    "frac12";      /* vulgar fraction one half */
      map[(char)190] =    "frac34";      /* vulgar fraction three quarters */
      map[(char)191] =    "iquest";      /* inverted question mark */
      map[(char)192] =    "Agrave";      /* Latin capital letter a with grave */
      map[(char)193] =    "Aacute";      /* Latin capital letter a with acute */
      map[(char)194] =    "Acirc";       /* Latin capital letter a with circumflex */
      map[(char)195] =    "Atilde";      /* Latin capital letter a with tilde */
      map[(char)196] =    "Auml";        /* Latin capital letter a with diaeresis */
      map[(char)197] =    "Aring";       /* Latin capital letter a with ring above */
      map[(char)198] =    "AElig";       /* Latin capital letter ae */
      map[(char)199] =    "Ccedil";      /* Latin capital letter c with cedilla */
      map[(char)200] =    "Egrave";      /* Latin capital letter e with grave */
      map[(char)201] =    "Eacute";      /* Latin capital letter e with acute */
      map[(char)202] =    "Ecirc";       /* Latin capital letter e with circumflex */
      map[(char)203] =    "Euml";        /* Latin capital letter e with diaeresis */
      map[(char)204] =    "Igrave";      /* Latin capital letter i with grave */
      map[(char)205] =    "Iacute";      /* Latin capital letter i with acute */
      map[(char)206] =    "Icirc";       /* Latin capital letter i with circumflex */
      map[(char)207] =    "Iuml";        /* Latin capital letter i with diaeresis */
      map[(char)208] =    "ETH";         /* Latin capital letter eth */
      map[(char)209] =    "Ntilde";      /* Latin capital letter n with tilde */
      map[(char)210] =    "Ograve";      /* Latin capital letter o with grave */
      map[(char)211] =    "Oacute";      /* Latin capital letter o with acute */
      map[(char)212] =    "Ocirc";       /* Latin capital letter o with circumflex */
      map[(char)213] =    "Otilde";      /* Latin capital letter o with tilde */
      map[(char)214] =    "Ouml";        /* Latin capital letter o with diaeresis */
      map[(char)215] =    "times";       /* multiplication sign */
      map[(char)216] =    "Oslash";      /* Latin capital letter o with stroke */
      map[(char)217] =    "Ugrave";      /* Latin capital letter u with grave */
      map[(char)218] =    "Uacute";      /* Latin capital letter u with acute */
      map[(char)219] =    "Ucirc";       /* Latin capital letter u with circumflex */
      map[(char)220] =    "Uuml";        /* Latin capital letter u with diaeresis */
      map[(char)221] =    "Yacute";      /* Latin capital letter y with acute */
      map[(char)222] =    "THORN";       /* Latin capital letter thorn */
      map[(char)223] =    "szlig";       /* Latin small letter sharp sXCOMMAX German Eszett */
      map[(char)224] =    "agrave";      /* Latin small letter a with grave */
      map[(char)225] =    "aacute";      /* Latin small letter a with acute */
      map[(char)226] =    "acirc";       /* Latin small letter a with circumflex */
      map[(char)227] =    "atilde";      /* Latin small letter a with tilde */
      map[(char)228] =    "auml";        /* Latin small letter a with diaeresis */
      map[(char)229] =    "aring";       /* Latin small letter a with ring above */
      map[(char)230] =    "aelig";       /* Latin lowercase ligature ae */
      map[(char)231] =    "ccedil";      /* Latin small letter c with cedilla */
      map[(char)232] =    "egrave";      /* Latin small letter e with grave */
      map[(char)233] =    "eacute";      /* Latin small letter e with acute */
      map[(char)234] =    "ecirc";       /* Latin small letter e with circumflex */
      map[(char)235] =    "euml";        /* Latin small letter e with diaeresis */
      map[(char)236] =    "igrave";      /* Latin small letter i with grave */
      map[(char)237] =    "iacute";      /* Latin small letter i with acute */
      map[(char)238] =    "icirc";       /* Latin small letter i with circumflex */
      map[(char)239] =    "iuml";        /* Latin small letter i with diaeresis */
      map[(char)240] =    "eth";         /* Latin small letter eth */
      map[(char)241] =    "ntilde";      /* Latin small letter n with tilde */
      map[(char)242] =    "ograve";      /* Latin small letter o with grave */
      map[(char)243] =    "oacute";      /* Latin small letter o with acute */
      map[(char)244] =    "ocirc";       /* Latin small letter o with circumflex */
      map[(char)245] =    "otilde";      /* Latin small letter o with tilde */
      map[(char)246] =    "ouml";        /* Latin small letter o with diaeresis */
      map[(char)247] =    "divide";      /* division sign */
      map[(char)248] =    "oslash";      /* Latin small letter o with stroke */
      map[(char)249] =    "ugrave";      /* Latin small letter u with grave */
      map[(char)250] =    "uacute";      /* Latin small letter u with acute */
      map[(char)251] =    "ucirc";       /* Latin small letter u with circumflex */
      map[(char)252] =    "uuml";        /* Latin small letter u with diaeresis */
      map[(char)253] =    "yacute";      /* Latin small letter y with acute */
      map[(char)254] =    "thorn";       /* Latin small letter thorn */
      map[(char)255] =    "yuml";        /* Latin small letter y with diaeresis */
      map[(char)338] =    "OElig";       /* Latin capital ligature oe */
      map[(char)339] =    "oelig";       /* Latin small ligature oe */
      map[(char)352] =    "Scaron";      /* Latin capital letter s with caron */
      map[(char)353] =    "scaron";      /* Latin small letter s with caron */
      map[(char)376] =    "Yuml";        /* Latin capital letter y with diaeresis */
      map[(char)402] =    "fnof";        /* Latin small letter f with hook */
      map[(char)710] =    "circ";        /* modifier letter circumflex accent */
      map[(char)732] =    "tilde";       /* small tilde */
      map[(char)913] =    "Alpha";       /* Greek capital letter alpha */
      map[(char)914] =    "Beta";        /* Greek capital letter beta */
      map[(char)915] =    "Gamma";       /* Greek capital letter gamma */
      map[(char)916] =    "Delta";       /* Greek capital letter delta */
      map[(char)917] =    "Epsilon";     /* Greek capital letter epsilon */
      map[(char)918] =    "Zeta";        /* Greek capital letter zeta */
      map[(char)919] =    "Eta";         /* Greek capital letter eta */
      map[(char)920] =    "Theta";       /* Greek capital letter theta */
      map[(char)921] =    "Iota";        /* Greek capital letter iota */
      map[(char)922] =    "Kappa";       /* Greek capital letter kappa */
      map[(char)923] =    "Lambda";      /* Greek capital letter lambda */
      map[(char)924] =    "Mu";          /* Greek capital letter mu */
      map[(char)925] =    "Nu";          /* Greek capital letter nu */
      map[(char)926] =    "Xi";          /* Greek capital letter xi */
      map[(char)927] =    "Omicron";     /* Greek capital letter omicron */
      map[(char)928] =    "Pi";          /* Greek capital letter pi */
      map[(char)929] =    "Rho";         /* Greek capital letter rho */
      map[(char)931] =    "Sigma";       /* Greek capital letter sigma */
      map[(char)932] =    "Tau";         /* Greek capital letter tau */
      map[(char)933] =    "Upsilon";     /* Greek capital letter upsilon */
      map[(char)934] =    "Phi";         /* Greek capital letter phi */
      map[(char)935] =    "Chi";         /* Greek capital letter chi */
      map[(char)936] =    "Psi";         /* Greek capital letter psi */
      map[(char)937] =    "Omega";       /* Greek capital letter omega */
      map[(char)945] =    "alpha";       /* Greek small letter alpha */
      map[(char)946] =    "beta";        /* Greek small letter beta */
      map[(char)947] =    "gamma";       /* Greek small letter gamma */
      map[(char)948] =    "delta";       /* Greek small letter delta */
      map[(char)949] =    "epsilon";     /* Greek small letter epsilon */
      map[(char)950] =    "zeta";        /* Greek small letter zeta */
      map[(char)951] =    "eta";         /* Greek small letter eta */
      map[(char)952] =    "theta";       /* Greek small letter theta */
      map[(char)953] =    "iota";        /* Greek small letter iota */
      map[(char)954] =    "kappa";       /* Greek small letter kappa */
      map[(char)955] =    "lambda";      /* Greek small letter lambda */
      map[(char)956] =    "mu";          /* Greek small letter mu */
      map[(char)957] =    "nu";          /* Greek small letter nu */
      map[(char)958] =    "xi";          /* Greek small letter xi */
      map[(char)959] =    "omicron";     /* Greek small letter omicron */
      map[(char)960] =    "pi";          /* Greek small letter pi */
      map[(char)961] =    "rho";         /* Greek small letter rho */
      map[(char)962] =    "sigmaf";      /* Greek small letter final sigma */
      map[(char)963] =    "sigma";       /* Greek small letter sigma */
      map[(char)964] =    "tau";         /* Greek small letter tau */
      map[(char)965] =    "upsilon";     /* Greek small letter upsilon */
      map[(char)966] =    "phi";         /* Greek small letter phi */
      map[(char)967] =    "chi";         /* Greek small letter chi */
      map[(char)968] =    "psi";         /* Greek small letter psi */
      map[(char)969] =    "omega";       /* Greek small letter omega */
      map[(char)977] =    "thetasym";    /* Greek theta symbol */
      map[(char)978] =    "upsih";       /* Greek upsilon with hook symbol */
      map[(char)982] =    "piv";         /* Greek pi symbol */
      map[(char)8194] =   "ensp";        /* en space */
      map[(char)8195] =   "emsp";        /* em space */
      map[(char)8201] =   "thinsp";      /* thin space */
      map[(char)8204] =   "zwnj";        /* zero width non-joiner */
      map[(char)8205] =   "zwj";         /* zero width joiner */
      map[(char)8206] =   "lrm";         /* left-to-right mark */
      map[(char)8207] =   "rlm";         /* right-to-left mark */
      map[(char)8211] =   "ndash";       /* en dash */
      map[(char)8212] =   "mdash";       /* em dash */
      map[(char)8216] =   "lsquo";       /* left single quotation mark */
      map[(char)8217] =   "rsquo";       /* right single quotation mark */
      map[(char)8218] =   "sbquo";       /* single low-9 quotation mark */
      map[(char)8220] =   "ldquo";       /* left double quotation mark */
      map[(char)8221] =   "rdquo";       /* right double quotation mark */
      map[(char)8222] =   "bdquo";       /* double low-9 quotation mark */
      map[(char)8224] =   "dagger";      /* dagger */
      map[(char)8225] =   "Dagger";      /* double dagger */
      map[(char)8226] =   "bull";        /* bullet */
      map[(char)8230] =   "hellip";      /* horizontal ellipsis */
      map[(char)8240] =   "permil";      /* per mille sign */
      map[(char)8242] =   "prime";       /* prime */
      map[(char)8243] =   "Prime";       /* double prime */
      map[(char)8249] =   "lsaquo";      /* single left-pointing angle quotation mark */
      map[(char)8250] =   "rsaquo";      /* single right-pointing angle quotation mark */
      map[(char)8254] =   "oline";       /* overline */
      map[(char)8260] =   "frasl";       /* fraction slash */
      map[(char)8364] =   "euro";        /* euro sign */
      map[(char)8465] =   "image";       /* black-letter capital i */
      map[(char)8472] =   "weierp";      /* script capital pXCOMMAX Weierstrass p */
      map[(char)8476] =   "real";        /* black-letter capital r */
      map[(char)8482] =   "trade";       /* trademark sign */
      map[(char)8501] =   "alefsym";     /* alef symbol */
      map[(char)8592] =   "larr";        /* leftwards arrow */
      map[(char)8593] =   "uarr";        /* upwards arrow */
      map[(char)8594] =   "rarr";        /* rightwards arrow */
      map[(char)8595] =   "darr";        /* downwards arrow */
      map[(char)8596] =   "harr";        /* left right arrow */
      map[(char)8629] =   "crarr";       /* downwards arrow with corner leftwards */
      map[(char)8656] =   "lArr";        /* leftwards double arrow */
      map[(char)8657] =   "uArr";        /* upwards double arrow */
      map[(char)8658] =   "rArr";        /* rightwards double arrow */
      map[(char)8659] =   "dArr";        /* downwards double arrow */
      map[(char)8660] =   "hArr";        /* left right double arrow */
      map[(char)8704] =   "forall";      /* for all */
      map[(char)8706] =   "part";        /* partial differential */
      map[(char)8707] =   "exist";       /* there exists */
      map[(char)8709] =   "empty";       /* empty set */
      map[(char)8711] =   "nabla";       /* nabla */
      map[(char)8712] =   "isin";        /* element of */
      map[(char)8713] =   "notin";       /* not an element of */
      map[(char)8715] =   "ni";          /* contains as member */
      map[(char)8719] =   "prod";        /* n-ary product */
      map[(char)8721] =   "sum";         /* n-ary summation */
      map[(char)8722] =   "minus";       /* minus sign */
      map[(char)8727] =   "lowast";      /* asterisk operator */
      map[(char)8730] =   "radic";       /* square root */
      map[(char)8733] =   "prop";        /* proportional to */
      map[(char)8734] =   "infin";       /* infinity */
      map[(char)8736] =   "ang";         /* angle */
      map[(char)8743] =   "and";         /* logical and */
      map[(char)8744] =   "or";          /* logical or */
      map[(char)8745] =   "cap";         /* intersection */
      map[(char)8746] =   "cup";         /* union */
      map[(char)8747] =   "int";         /* integral */
      map[(char)8756] =   "there4";      /* therefore */
      map[(char)8764] =   "sim";         /* tilde operator */
      map[(char)8773] =   "cong";        /* congruent to */
      map[(char)8776] =   "asymp";       /* almost equal to */
      map[(char)8800] =   "ne";          /* not equal to */
      map[(char)8801] =   "equiv";       /* identical toXCOMMAX equivalent to */
      map[(char)8804] =   "le";          /* less-than or equal to */
      map[(char)8805] =   "ge";          /* greater-than or equal to */
      map[(char)8834] =   "sub";         /* subset of */
      map[(char)8835] =   "sup";         /* superset of */
      map[(char)8836] =   "nsub";        /* not a subset of */
      map[(char)8838] =   "sube";        /* subset of or equal to */
      map[(char)8839] =   "supe";        /* superset of or equal to */
      map[(char)8853] =   "oplus";       /* circled plus */
      map[(char)8855] =   "otimes";      /* circled times */
      map[(char)8869] =   "perp";        /* up tack */
      map[(char)8901] =   "sdot";        /* dot operator */
      map[(char)8968] =   "lceil";       /* left ceiling */
      map[(char)8969] =   "rceil";       /* right ceiling */
      map[(char)8970] =   "lfloor";      /* left floor */
      map[(char)8971] =   "rfloor";      /* right floor */
      map[(char)9001] =   "lang";        /* left-pointing angle bracket */
      map[(char)9002] =   "rang";        /* right-pointing angle bracket */
      map[(char)9674] =   "loz";         /* lozenge */
      map[(char)9824] =   "spades";      /* black spade suit */
      map[(char)9827] =   "clubs";       /* black club suit */
      map[(char)9829] =   "hearts";      /* black heart suit */
      map[(char)9830] =   "diams";       /* black diamond suit */

      init = true;

    } // Inner !init
  } // Outer !init

  return map;
}

/*TODO static Trie<Character> mkEntityToCharacterTrie() {
//TODO Thread safety?
Trie<Character> trie = new HashTrie<Character>();

for(Map.Entry<Character,String> entry : characterToEntityMap.entrySet())
trie.put(entry.getValue(),entry.getKey());
return Trie.Util.unmodifiable(trie);
}
*/

std::string esapi::HTMLEntityCodec::encodeCharacter( const char* immune, size_t length, char c) const{
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
  return "";
}

char esapi::HTMLEntityCodec::decodeCharacter( PushbackString& input) const {
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
