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
const std::string esapi::HTMLEntityCodec::REPLACEMENT_STR = "\uFFFD";
esapi::Mutex esapi::HTMLEntityCodec::s_mutex;
const std::map<int,std::string> esapi::HTMLEntityCodec::characterToEntityMap = mkCharacterToEntityMap();

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

const std::map<int,std::string>& esapi::HTMLEntityCodec::mkCharacterToEntityMap() {
  // Double checked intialization
  static volatile bool init = false;
  static std::map<int, std::string> map;

  // First check
  if(!init)
  {
    // Acquire the lock
    MutexAutoLock lock(s_mutex);

    // Verify we did not acquire the lock after another thread initialized and and released
    if(!init)
    {
      map[34]  = "quot";        /* quotation mark */
      map[38]  = "amp";         /* ampersand */
      map[60]  = "lt";          /* less-than sign */
      map[62]  = "gt";          /* greater-than sign */
      map[160] =    "nbsp";        /* no-break space */
      map[161] =    "iexcl";       /* inverted exclamation mark */
      map[162] =    "cent";        /* cent sign */
      map[163] =    "pound";       /* pound sign */
      map[164] =    "curren";      /* currency sign */
      map[165] =    "yen";         /* yen sign */
      map[166] =    "brvbar";      /* broken bar */
      map[167] =    "sect";        /* section sign */
      map[168] =    "uml";         /* diaeresis */
      map[169] =    "copy";        /* copyright sign */
      map[170] =    "ordf";        /* feminine ordinal indicator */
      map[171] =    "laquo";       /* left-pointing double angle quotation mark */
      map[172] =    "not";         /* not sign */
      map[173] =    "shy";         /* soft hyphen */
      map[174] =    "reg";         /* registered sign */
      map[175] =    "macr";        /* macron */
      map[176] =    "deg";         /* degree sign */
      map[177] =    "plusmn";      /* plus-minus sign */
      map[178] =    "sup2";        /* superscript two */
      map[179] =    "sup3";        /* superscript three */
      map[180] =    "acute";       /* acute accent */
      map[181] =    "micro";       /* micro sign */
      map[182] =    "para";        /* pilcrow sign */
      map[183] =    "middot";      /* middle dot */
      map[184] =    "cedil";       /* cedilla */
      map[185] =    "sup1";        /* superscript one */
      map[186] =    "ordm";        /* masculine ordinal indicator */
      map[187] =    "raquo";       /* right-pointing double angle quotation mark */
      map[188] =    "frac14";      /* vulgar fraction one quarter */
      map[189] =    "frac12";      /* vulgar fraction one half */
      map[190] =    "frac34";      /* vulgar fraction three quarters */
      map[191] =    "iquest";      /* inverted question mark */
      map[192] =    "Agrave";      /* Latin capital letter a with grave */
      map[193] =    "Aacute";      /* Latin capital letter a with acute */
      map[194] =    "Acirc";       /* Latin capital letter a with circumflex */
      map[195] =    "Atilde";      /* Latin capital letter a with tilde */
      map[196] =    "Auml";        /* Latin capital letter a with diaeresis */
      map[197] =    "Aring";       /* Latin capital letter a with ring above */
      map[198] =    "AElig";       /* Latin capital letter ae */
      map[199] =    "Ccedil";      /* Latin capital letter c with cedilla */
      map[200] =    "Egrave";      /* Latin capital letter e with grave */
      map[201] =    "Eacute";      /* Latin capital letter e with acute */
      map[202] =    "Ecirc";       /* Latin capital letter e with circumflex */
      map[203] =    "Euml";        /* Latin capital letter e with diaeresis */
      map[204] =    "Igrave";      /* Latin capital letter i with grave */
      map[205] =    "Iacute";      /* Latin capital letter i with acute */
      map[206] =    "Icirc";       /* Latin capital letter i with circumflex */
      map[207] =    "Iuml";        /* Latin capital letter i with diaeresis */
      map[208] =    "ETH";         /* Latin capital letter eth */
      map[209] =    "Ntilde";      /* Latin capital letter n with tilde */
      map[210] =    "Ograve";      /* Latin capital letter o with grave */
      map[211] =    "Oacute";      /* Latin capital letter o with acute */
      map[212] =    "Ocirc";       /* Latin capital letter o with circumflex */
      map[213] =    "Otilde";      /* Latin capital letter o with tilde */
      map[214] =    "Ouml";        /* Latin capital letter o with diaeresis */
      map[215] =    "times";       /* multiplication sign */
      map[216] =    "Oslash";      /* Latin capital letter o with stroke */
      map[217] =    "Ugrave";      /* Latin capital letter u with grave */
      map[218] =    "Uacute";      /* Latin capital letter u with acute */
      map[219] =    "Ucirc";       /* Latin capital letter u with circumflex */
      map[220] =    "Uuml";        /* Latin capital letter u with diaeresis */
      map[221] =    "Yacute";      /* Latin capital letter y with acute */
      map[222] =    "THORN";       /* Latin capital letter thorn */
      map[223] =    "szlig";       /* Latin small letter sharp sXCOMMAX German Eszett */
      map[224] =    "agrave";      /* Latin small letter a with grave */
      map[225] =    "aacute";      /* Latin small letter a with acute */
      map[226] =    "acirc";       /* Latin small letter a with circumflex */
      map[227] =    "atilde";      /* Latin small letter a with tilde */
      map[228] =    "auml";        /* Latin small letter a with diaeresis */
      map[229] =    "aring";       /* Latin small letter a with ring above */
      map[230] =    "aelig";       /* Latin lowercase ligature ae */
      map[231] =    "ccedil";      /* Latin small letter c with cedilla */
      map[232] =    "egrave";      /* Latin small letter e with grave */
      map[233] =    "eacute";      /* Latin small letter e with acute */
      map[234] =    "ecirc";       /* Latin small letter e with circumflex */
      map[235] =    "euml";        /* Latin small letter e with diaeresis */
      map[236] =    "igrave";      /* Latin small letter i with grave */
      map[237] =    "iacute";      /* Latin small letter i with acute */
      map[238] =    "icirc";       /* Latin small letter i with circumflex */
      map[239] =    "iuml";        /* Latin small letter i with diaeresis */
      map[240] =    "eth";         /* Latin small letter eth */
      map[241] =    "ntilde";      /* Latin small letter n with tilde */
      map[242] =    "ograve";      /* Latin small letter o with grave */
      map[243] =    "oacute";      /* Latin small letter o with acute */
      map[244] =    "ocirc";       /* Latin small letter o with circumflex */
      map[245] =    "otilde";      /* Latin small letter o with tilde */
      map[246] =    "ouml";        /* Latin small letter o with diaeresis */
      map[247] =    "divide";      /* division sign */
      map[248] =    "oslash";      /* Latin small letter o with stroke */
      map[249] =    "ugrave";      /* Latin small letter u with grave */
      map[250] =    "uacute";      /* Latin small letter u with acute */
      map[251] =    "ucirc";       /* Latin small letter u with circumflex */
      map[252] =    "uuml";        /* Latin small letter u with diaeresis */
      map[253] =    "yacute";      /* Latin small letter y with acute */
      map[254] =    "thorn";       /* Latin small letter thorn */
      map[255] =    "yuml";        /* Latin small letter y with diaeresis */
      map[338] =    "OElig";       /* Latin capital ligature oe */
      map[339] =    "oelig";       /* Latin small ligature oe */
      map[352] =    "Scaron";      /* Latin capital letter s with caron */
      map[353] =    "scaron";      /* Latin small letter s with caron */
      map[376] =    "Yuml";        /* Latin capital letter y with diaeresis */
      map[402] =    "fnof";        /* Latin small letter f with hook */
      map[710] =    "circ";        /* modifier letter circumflex accent */
      map[732] =    "tilde";       /* small tilde */
      map[913] =    "Alpha";       /* Greek capital letter alpha */
      map[914] =    "Beta";        /* Greek capital letter beta */
      map[915] =    "Gamma";       /* Greek capital letter gamma */
      map[916] =    "Delta";       /* Greek capital letter delta */
      map[917] =    "Epsilon";     /* Greek capital letter epsilon */
      map[918] =    "Zeta";        /* Greek capital letter zeta */
      map[919] =    "Eta";         /* Greek capital letter eta */
      map[920] =    "Theta";       /* Greek capital letter theta */
      map[921] =    "Iota";        /* Greek capital letter iota */
      map[922] =    "Kappa";       /* Greek capital letter kappa */
      map[923] =    "Lambda";      /* Greek capital letter lambda */
      map[924] =    "Mu";          /* Greek capital letter mu */
      map[925] =    "Nu";          /* Greek capital letter nu */
      map[926] =    "Xi";          /* Greek capital letter xi */
      map[927] =    "Omicron";     /* Greek capital letter omicron */
      map[928] =    "Pi";          /* Greek capital letter pi */
      map[929] =    "Rho";         /* Greek capital letter rho */
      map[931] =    "Sigma";       /* Greek capital letter sigma */
      map[932] =    "Tau";         /* Greek capital letter tau */
      map[933] =    "Upsilon";     /* Greek capital letter upsilon */
      map[934] =    "Phi";         /* Greek capital letter phi */
      map[935] =    "Chi";         /* Greek capital letter chi */
      map[936] =    "Psi";         /* Greek capital letter psi */
      map[937] =    "Omega";       /* Greek capital letter omega */
      map[945] =    "alpha";       /* Greek small letter alpha */
      map[946] =    "beta";        /* Greek small letter beta */
      map[947] =    "gamma";       /* Greek small letter gamma */
      map[948] =    "delta";       /* Greek small letter delta */
      map[949] =    "epsilon";     /* Greek small letter epsilon */
      map[950] =    "zeta";        /* Greek small letter zeta */
      map[951] =    "eta";         /* Greek small letter eta */
      map[952] =    "theta";       /* Greek small letter theta */
      map[953] =    "iota";        /* Greek small letter iota */
      map[954] =    "kappa";       /* Greek small letter kappa */
      map[955] =    "lambda";      /* Greek small letter lambda */
      map[956] =    "mu";          /* Greek small letter mu */
      map[957] =    "nu";          /* Greek small letter nu */
      map[958] =    "xi";          /* Greek small letter xi */
      map[959] =    "omicron";     /* Greek small letter omicron */
      map[960] =    "pi";          /* Greek small letter pi */
      map[961] =    "rho";         /* Greek small letter rho */
      map[962] =    "sigmaf";      /* Greek small letter final sigma */
      map[963] =    "sigma";       /* Greek small letter sigma */
      map[964] =    "tau";         /* Greek small letter tau */
      map[965] =    "upsilon";     /* Greek small letter upsilon */
      map[966] =    "phi";         /* Greek small letter phi */
      map[967] =    "chi";         /* Greek small letter chi */
      map[968] =    "psi";         /* Greek small letter psi */
      map[969] =    "omega";       /* Greek small letter omega */
      map[977] =    "thetasym";    /* Greek theta symbol */
      map[978] =    "upsih";       /* Greek upsilon with hook symbol */
      map[982] =    "piv";         /* Greek pi symbol */
      map[8194] =   "ensp";        /* en space */
      map[8195] =   "emsp";        /* em space */
      map[8201] =   "thinsp";      /* thin space */
      map[8204] =   "zwnj";        /* zero width non-joiner */
      map[8205] =   "zwj";         /* zero width joiner */
      map[8206] =   "lrm";         /* left-to-right mark */
      map[8207] =   "rlm";         /* right-to-left mark */
      map[8211] =   "ndash";       /* en dash */
      map[8212] =   "mdash";       /* em dash */
      map[8216] =   "lsquo";       /* left single quotation mark */
      map[8217] =   "rsquo";       /* right single quotation mark */
      map[8218] =   "sbquo";       /* single low-9 quotation mark */
      map[8220] =   "ldquo";       /* left double quotation mark */
      map[8221] =   "rdquo";       /* right double quotation mark */
      map[8222] =   "bdquo";       /* double low-9 quotation mark */
      map[8224] =   "dagger";      /* dagger */
      map[8225] =   "Dagger";      /* double dagger */
      map[8226] =   "bull";        /* bullet */
      map[8230] =   "hellip";      /* horizontal ellipsis */
      map[8240] =   "permil";      /* per mille sign */
      map[8242] =   "prime";       /* prime */
      map[8243] =   "Prime";       /* double prime */
      map[8249] =   "lsaquo";      /* single left-pointing angle quotation mark */
      map[8250] =   "rsaquo";      /* single right-pointing angle quotation mark */
      map[8254] =   "oline";       /* overline */
      map[8260] =   "frasl";       /* fraction slash */
      map[8364] =   "euro";        /* euro sign */
      map[8465] =   "image";       /* black-letter capital i */
      map[8472] =   "weierp";      /* script capital pXCOMMAX Weierstrass p */
      map[8476] =   "real";        /* black-letter capital r */
      map[8482] =   "trade";       /* trademark sign */
      map[8501] =   "alefsym";     /* alef symbol */
      map[8592] =   "larr";        /* leftwards arrow */
      map[8593] =   "uarr";        /* upwards arrow */
      map[8594] =   "rarr";        /* rightwards arrow */
      map[8595] =   "darr";        /* downwards arrow */
      map[8596] =   "harr";        /* left right arrow */
      map[8629] =   "crarr";       /* downwards arrow with corner leftwards */
      map[8656] =   "lArr";        /* leftwards double arrow */
      map[8657] =   "uArr";        /* upwards double arrow */
      map[8658] =   "rArr";        /* rightwards double arrow */
      map[8659] =   "dArr";        /* downwards double arrow */
      map[8660] =   "hArr";        /* left right double arrow */
      map[8704] =   "forall";      /* for all */
      map[8706] =   "part";        /* partial differential */
      map[8707] =   "exist";       /* there exists */
      map[8709] =   "empty";       /* empty set */
      map[8711] =   "nabla";       /* nabla */
      map[8712] =   "isin";        /* element of */
      map[8713] =   "notin";       /* not an element of */
      map[8715] =   "ni";          /* contains as member */
      map[8719] =   "prod";        /* n-ary product */
      map[8721] =   "sum";         /* n-ary summation */
      map[8722] =   "minus";       /* minus sign */
      map[8727] =   "lowast";      /* asterisk operator */
      map[8730] =   "radic";       /* square root */
      map[8733] =   "prop";        /* proportional to */
      map[8734] =   "infin";       /* infinity */
      map[8736] =   "ang";         /* angle */
      map[8743] =   "and";         /* logical and */
      map[8744] =   "or";          /* logical or */
      map[8745] =   "cap";         /* intersection */
      map[8746] =   "cup";         /* union */
      map[8747] =   "int";         /* integral */
      map[8756] =   "there4";      /* therefore */
      map[8764] =   "sim";         /* tilde operator */
      map[8773] =   "cong";        /* congruent to */
      map[8776] =   "asymp";       /* almost equal to */
      map[8800] =   "ne";          /* not equal to */
      map[8801] =   "equiv";       /* identical toXCOMMAX equivalent to */
      map[8804] =   "le";          /* less-than or equal to */
      map[8805] =   "ge";          /* greater-than or equal to */
      map[8834] =   "sub";         /* subset of */
      map[8835] =   "sup";         /* superset of */
      map[8836] =   "nsub";        /* not a subset of */
      map[8838] =   "sube";        /* subset of or equal to */
      map[8839] =   "supe";        /* superset of or equal to */
      map[8853] =   "oplus";       /* circled plus */
      map[8855] =   "otimes";      /* circled times */
      map[8869] =   "perp";        /* up tack */
      map[8901] =   "sdot";        /* dot operator */
      map[8968] =   "lceil";       /* left ceiling */
      map[8969] =   "rceil";       /* right ceiling */
      map[8970] =   "lfloor";      /* left floor */
      map[8971] =   "rfloor";      /* right floor */
      map[9001] =   "lang";        /* left-pointing angle bracket */
      map[9002] =   "rang";        /* right-pointing angle bracket */
      map[9674] =   "loz";         /* lozenge */
      map[9824] =   "spades";      /* black spade suit */
      map[9827] =   "clubs";       /* black club suit */
      map[9829] =   "hearts";      /* black heart suit */
      map[9830] =   "diams";       /* black diamond suit */

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
