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
esapi::Mutex& esapi::HTMLEntityCodec::getClassMutex() {
  static esapi::Mutex s_mutex;
  return s_mutex;
}

/**
* Build a unmodifiable Map from entity Character to Name.
* @return Unmodifiable map.
*/
const esapi::HTMLEntityCodec::EntityMap& esapi::HTMLEntityCodec::getCharacterToEntityMap() {

  // Double checked intialization
  static volatile bool init = false;
  static boost::shared_ptr<EntityMap> map;

  MEMORY_BARRIER();

  // First check
  if(!init)
  {
    // Acquire the lock
    MutexLock lock(getClassMutex());

    // Verify we did not acquire the lock after another thread initialized and and released
    if(!init)
    {
      map = boost::shared_ptr<EntityMap>(new EntityMap);
      ASSERT(map);
      if(nullptr == map.get())
        throw std::bad_alloc();

      // Convenience
      EntityMap& m = *map.get();

      // 252 items, but no reserve() on std::map
      m[34]  = "quot";        /* quotation mark */
      m[38]  = "amp";         /* ampersand */
      m[60]  = "lt";          /* less-than sign */
      m[62]  = "gt";          /* greater-than sign */
      m[160] =    "nbsp";        /* no-break space */
      m[161] =    "iexcl";       /* inverted exclamation mark */
      m[162] =    "cent";        /* cent sign */
      m[163] =    "pound";       /* pound sign */
      m[164] =    "curren";      /* currency sign */
      m[165] =    "yen";         /* yen sign */
      m[166] =    "brvbar";      /* broken bar */
      m[167] =    "sect";        /* section sign */
      m[168] =    "uml";         /* diaeresis */
      m[169] =    "copy";        /* copyright sign */
      m[170] =    "ordf";        /* feminine ordinal indicator */
      m[171] =    "laquo";       /* left-pointing double angle quotation mark */
      m[172] =    "not";         /* not sign */
      m[173] =    "shy";         /* soft hyphen */
      m[174] =    "reg";         /* registered sign */
      m[175] =    "macr";        /* macron */
      m[176] =    "deg";         /* degree sign */
      m[177] =    "plusmn";      /* plus-minus sign */
      m[178] =    "sup2";        /* superscript two */
      m[179] =    "sup3";        /* superscript three */
      m[180] =    "acute";       /* acute accent */
      m[181] =    "micro";       /* micro sign */
      m[182] =    "para";        /* pilcrow sign */
      m[183] =    "middot";      /* middle dot */
      m[184] =    "cedil";       /* cedilla */
      m[185] =    "sup1";        /* superscript one */
      m[186] =    "ordm";        /* masculine ordinal indicator */
      m[187] =    "raquo";       /* right-pointing double angle quotation mark */
      m[188] =    "frac14";      /* vulgar fraction one quarter */
      m[189] =    "frac12";      /* vulgar fraction one half */
      m[190] =    "frac34";      /* vulgar fraction three quarters */
      m[191] =    "iquest";      /* inverted question mark */
      m[192] =    "Agrave";      /* Latin capital letter a with grave */
      m[193] =    "Aacute";      /* Latin capital letter a with acute */
      m[194] =    "Acirc";       /* Latin capital letter a with circumflex */
      m[195] =    "Atilde";      /* Latin capital letter a with tilde */
      m[196] =    "Auml";        /* Latin capital letter a with diaeresis */
      m[197] =    "Aring";       /* Latin capital letter a with ring above */
      m[198] =    "AElig";       /* Latin capital letter ae */
      m[199] =    "Ccedil";      /* Latin capital letter c with cedilla */
      m[200] =    "Egrave";      /* Latin capital letter e with grave */
      m[201] =    "Eacute";      /* Latin capital letter e with acute */
      m[202] =    "Ecirc";       /* Latin capital letter e with circumflex */
      m[203] =    "Euml";        /* Latin capital letter e with diaeresis */
      m[204] =    "Igrave";      /* Latin capital letter i with grave */
      m[205] =    "Iacute";      /* Latin capital letter i with acute */
      m[206] =    "Icirc";       /* Latin capital letter i with circumflex */
      m[207] =    "Iuml";        /* Latin capital letter i with diaeresis */
      m[208] =    "ETH";         /* Latin capital letter eth */
      m[209] =    "Ntilde";      /* Latin capital letter n with tilde */
      m[210] =    "Ograve";      /* Latin capital letter o with grave */
      m[211] =    "Oacute";      /* Latin capital letter o with acute */
      m[212] =    "Ocirc";       /* Latin capital letter o with circumflex */
      m[213] =    "Otilde";      /* Latin capital letter o with tilde */
      m[214] =    "Ouml";        /* Latin capital letter o with diaeresis */
      m[215] =    "times";       /* multiplication sign */
      m[216] =    "Oslash";      /* Latin capital letter o with stroke */
      m[217] =    "Ugrave";      /* Latin capital letter u with grave */
      m[218] =    "Uacute";      /* Latin capital letter u with acute */
      m[219] =    "Ucirc";       /* Latin capital letter u with circumflex */
      m[220] =    "Uuml";        /* Latin capital letter u with diaeresis */
      m[221] =    "Yacute";      /* Latin capital letter y with acute */
      m[222] =    "THORN";       /* Latin capital letter thorn */
      m[223] =    "szlig";       /* Latin small letter sharp sXCOMMAX German Eszett */
      m[224] =    "agrave";      /* Latin small letter a with grave */
      m[225] =    "aacute";      /* Latin small letter a with acute */
      m[226] =    "acirc";       /* Latin small letter a with circumflex */
      m[227] =    "atilde";      /* Latin small letter a with tilde */
      m[228] =    "auml";        /* Latin small letter a with diaeresis */
      m[229] =    "aring";       /* Latin small letter a with ring above */
      m[230] =    "aelig";       /* Latin lowercase ligature ae */
      m[231] =    "ccedil";      /* Latin small letter c with cedilla */
      m[232] =    "egrave";      /* Latin small letter e with grave */
      m[233] =    "eacute";      /* Latin small letter e with acute */
      m[234] =    "ecirc";       /* Latin small letter e with circumflex */
      m[235] =    "euml";        /* Latin small letter e with diaeresis */
      m[236] =    "igrave";      /* Latin small letter i with grave */
      m[237] =    "iacute";      /* Latin small letter i with acute */
      m[238] =    "icirc";       /* Latin small letter i with circumflex */
      m[239] =    "iuml";        /* Latin small letter i with diaeresis */
      m[240] =    "eth";         /* Latin small letter eth */
      m[241] =    "ntilde";      /* Latin small letter n with tilde */
      m[242] =    "ograve";      /* Latin small letter o with grave */
      m[243] =    "oacute";      /* Latin small letter o with acute */
      m[244] =    "ocirc";       /* Latin small letter o with circumflex */
      m[245] =    "otilde";      /* Latin small letter o with tilde */
      m[246] =    "ouml";        /* Latin small letter o with diaeresis */
      m[247] =    "divide";      /* division sign */
      m[248] =    "oslash";      /* Latin small letter o with stroke */
      m[249] =    "ugrave";      /* Latin small letter u with grave */
      m[250] =    "uacute";      /* Latin small letter u with acute */
      m[251] =    "ucirc";       /* Latin small letter u with circumflex */
      m[252] =    "uuml";        /* Latin small letter u with diaeresis */
      m[253] =    "yacute";      /* Latin small letter y with acute */
      m[254] =    "thorn";       /* Latin small letter thorn */
      m[255] =    "yuml";        /* Latin small letter y with diaeresis */
      m[338] =    "OElig";       /* Latin capital ligature oe */
      m[339] =    "oelig";       /* Latin small ligature oe */
      m[352] =    "Scaron";      /* Latin capital letter s with caron */
      m[353] =    "scaron";      /* Latin small letter s with caron */
      m[376] =    "Yuml";        /* Latin capital letter y with diaeresis */
      m[402] =    "fnof";        /* Latin small letter f with hook */
      m[710] =    "circ";        /* modifier letter circumflex accent */
      m[732] =    "tilde";       /* small tilde */
      m[913] =    "Alpha";       /* Greek capital letter alpha */
      m[914] =    "Beta";        /* Greek capital letter beta */
      m[915] =    "Gamma";       /* Greek capital letter gamma */
      m[916] =    "Delta";       /* Greek capital letter delta */
      m[917] =    "Epsilon";     /* Greek capital letter epsilon */
      m[918] =    "Zeta";        /* Greek capital letter zeta */
      m[919] =    "Eta";         /* Greek capital letter eta */
      m[920] =    "Theta";       /* Greek capital letter theta */
      m[921] =    "Iota";        /* Greek capital letter iota */
      m[922] =    "Kappa";       /* Greek capital letter kappa */
      m[923] =    "Lambda";      /* Greek capital letter lambda */
      m[924] =    "Mu";          /* Greek capital letter mu */
      m[925] =    "Nu";          /* Greek capital letter nu */
      m[926] =    "Xi";          /* Greek capital letter xi */
      m[927] =    "Omicron";     /* Greek capital letter omicron */
      m[928] =    "Pi";          /* Greek capital letter pi */
      m[929] =    "Rho";         /* Greek capital letter rho */
      m[931] =    "Sigma";       /* Greek capital letter sigma */
      m[932] =    "Tau";         /* Greek capital letter tau */
      m[933] =    "Upsilon";     /* Greek capital letter upsilon */
      m[934] =    "Phi";         /* Greek capital letter phi */
      m[935] =    "Chi";         /* Greek capital letter chi */
      m[936] =    "Psi";         /* Greek capital letter psi */
      m[937] =    "Omega";       /* Greek capital letter omega */
      m[945] =    "alpha";       /* Greek small letter alpha */
      m[946] =    "beta";        /* Greek small letter beta */
      m[947] =    "gamma";       /* Greek small letter gamma */
      m[948] =    "delta";       /* Greek small letter delta */
      m[949] =    "epsilon";     /* Greek small letter epsilon */
      m[950] =    "zeta";        /* Greek small letter zeta */
      m[951] =    "eta";         /* Greek small letter eta */
      m[952] =    "theta";       /* Greek small letter theta */
      m[953] =    "iota";        /* Greek small letter iota */
      m[954] =    "kappa";       /* Greek small letter kappa */
      m[955] =    "lambda";      /* Greek small letter lambda */
      m[956] =    "mu";          /* Greek small letter mu */
      m[957] =    "nu";          /* Greek small letter nu */
      m[958] =    "xi";          /* Greek small letter xi */
      m[959] =    "omicron";     /* Greek small letter omicron */
      m[960] =    "pi";          /* Greek small letter pi */
      m[961] =    "rho";         /* Greek small letter rho */
      m[962] =    "sigmaf";      /* Greek small letter final sigma */
      m[963] =    "sigma";       /* Greek small letter sigma */
      m[964] =    "tau";         /* Greek small letter tau */
      m[965] =    "upsilon";     /* Greek small letter upsilon */
      m[966] =    "phi";         /* Greek small letter phi */
      m[967] =    "chi";         /* Greek small letter chi */
      m[968] =    "psi";         /* Greek small letter psi */
      m[969] =    "omega";       /* Greek small letter omega */
      m[977] =    "thetasym";    /* Greek theta symbol */
      m[978] =    "upsih";       /* Greek upsilon with hook symbol */
      m[982] =    "piv";         /* Greek pi symbol */
      m[8194] =   "ensp";        /* en space */
      m[8195] =   "emsp";        /* em space */
      m[8201] =   "thinsp";      /* thin space */
      m[8204] =   "zwnj";        /* zero width non-joiner */
      m[8205] =   "zwj";         /* zero width joiner */
      m[8206] =   "lrm";         /* left-to-right mark */
      m[8207] =   "rlm";         /* right-to-left mark */
      m[8211] =   "ndash";       /* en dash */
      m[8212] =   "mdash";       /* em dash */
      m[8216] =   "lsquo";       /* left single quotation mark */
      m[8217] =   "rsquo";       /* right single quotation mark */
      m[8218] =   "sbquo";       /* single low-9 quotation mark */
      m[8220] =   "ldquo";       /* left double quotation mark */
      m[8221] =   "rdquo";       /* right double quotation mark */
      m[8222] =   "bdquo";       /* double low-9 quotation mark */
      m[8224] =   "dagger";      /* dagger */
      m[8225] =   "Dagger";      /* double dagger */
      m[8226] =   "bull";        /* bullet */
      m[8230] =   "hellip";      /* horizontal ellipsis */
      m[8240] =   "permil";      /* per mille sign */
      m[8242] =   "prime";       /* prime */
      m[8243] =   "Prime";       /* double prime */
      m[8249] =   "lsaquo";      /* single left-pointing angle quotation mark */
      m[8250] =   "rsaquo";      /* single right-pointing angle quotation mark */
      m[8254] =   "oline";       /* overline */
      m[8260] =   "frasl";       /* fraction slash */
      m[8364] =   "euro";        /* euro sign */
      m[8465] =   "image";       /* black-letter capital i */
      m[8472] =   "weierp";      /* script capital pXCOMMAX Weierstrass p */
      m[8476] =   "real";        /* black-letter capital r */
      m[8482] =   "trade";       /* trademark sign */
      m[8501] =   "alefsym";     /* alef symbol */
      m[8592] =   "larr";        /* leftwards arrow */
      m[8593] =   "uarr";        /* upwards arrow */
      m[8594] =   "rarr";        /* rightwards arrow */
      m[8595] =   "darr";        /* downwards arrow */
      m[8596] =   "harr";        /* left right arrow */
      m[8629] =   "crarr";       /* downwards arrow with corner leftwards */
      m[8656] =   "lArr";        /* leftwards double arrow */
      m[8657] =   "uArr";        /* upwards double arrow */
      m[8658] =   "rArr";        /* rightwards double arrow */
      m[8659] =   "dArr";        /* downwards double arrow */
      m[8660] =   "hArr";        /* left right double arrow */
      m[8704] =   "forall";      /* for all */
      m[8706] =   "part";        /* partial differential */
      m[8707] =   "exist";       /* there exists */
      m[8709] =   "empty";       /* empty set */
      m[8711] =   "nabla";       /* nabla */
      m[8712] =   "isin";        /* element of */
      m[8713] =   "notin";       /* not an element of */
      m[8715] =   "ni";          /* contains as member */
      m[8719] =   "prod";        /* n-ary product */
      m[8721] =   "sum";         /* n-ary summation */
      m[8722] =   "minus";       /* minus sign */
      m[8727] =   "lowast";      /* asterisk operator */
      m[8730] =   "radic";       /* square root */
      m[8733] =   "prop";        /* proportional to */
      m[8734] =   "infin";       /* infinity */
      m[8736] =   "ang";         /* angle */
      m[8743] =   "and";         /* logical and */
      m[8744] =   "or";          /* logical or */
      m[8745] =   "cap";         /* intersection */
      m[8746] =   "cup";         /* union */
      m[8747] =   "int";         /* integral */
      m[8756] =   "there4";      /* therefore */
      m[8764] =   "sim";         /* tilde operator */
      m[8773] =   "cong";        /* congruent to */
      m[8776] =   "asymp";       /* almost equal to */
      m[8800] =   "ne";          /* not equal to */
      m[8801] =   "equiv";       /* identical toXCOMMAX equivalent to */
      m[8804] =   "le";          /* less-than or equal to */
      m[8805] =   "ge";          /* greater-than or equal to */
      m[8834] =   "sub";         /* subset of */
      m[8835] =   "sup";         /* superset of */
      m[8836] =   "nsub";        /* not a subset of */
      m[8838] =   "sube";        /* subset of or equal to */
      m[8839] =   "supe";        /* superset of or equal to */
      m[8853] =   "oplus";       /* circled plus */
      m[8855] =   "otimes";      /* circled times */
      m[8869] =   "perp";        /* up tack */
      m[8901] =   "sdot";        /* dot operator */
      m[8968] =   "lceil";       /* left ceiling */
      m[8969] =   "rceil";       /* right ceiling */
      m[8970] =   "lfloor";      /* left floor */
      m[8971] =   "rfloor";      /* right floor */
      m[9001] =   "lang";        /* left-pointing angle bracket */
      m[9002] =   "rang";        /* right-pointing angle bracket */
      m[9674] =   "loz";         /* lozenge */
      m[9824] =   "spades";      /* black spade suit */
      m[9827] =   "clubs";       /* black club suit */
      m[9829] =   "hearts";      /* black heart suit */
      m[9830] =   "diams";       /* black diamond suit */

      init = true;
      MEMORY_BARRIER();

    } // Inner !init
  } // Outer !init

  return *map.get();
}

/**
* Build a unmodifiable Trie from entitiy Name to Character
* @return Unmodifiable trie.
*/
const esapi::Trie<int>& esapi::HTMLEntityCodec::getEntityToCharacterTrie()
{
  //for(Map.Entry<Character,String> entry : characterToEntityMap.entrySet())
  //trie.put(entry.getValue(), entry.getKey());
  //return Trie.Util.unmodifiable(trie);  

   // Double checked intialization
  static volatile bool init = false;
  static boost::shared_ptr<EntityTrie> trie;

  MEMORY_BARRIER();

  // First check
  if(!init)
  {
    // Acquire the lock
    MutexLock lock(getClassMutex());

    // Verify we did not acquire the lock after another thread initialized and and released
    if(!init)
    {
      trie = boost::shared_ptr<EntityTrie>(new EntityTrie);
      ASSERT(trie);
      if(nullptr == trie.get())
        throw std::bad_alloc();

      // Convenience
      EntityTrie& t = *trie.get();

      const EntityMap& entityMap = esapi::HTMLEntityCodec::getCharacterToEntityMap();
      EntityMap::const_iterator it = entityMap.begin();

      for(; it != entityMap.end(); it++)
      {
        // trie.insert( std::pair<char, std::string>(it->second, it->first) );
      }

      init = true;
      MEMORY_BARRIER();

    } // Inner !init
  } // Outer !init

  return *trie.get();
}

std::string esapi::HTMLEntityCodec::encodeCharacter( const char* immune, size_t length, char c) const{
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
