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
#include "codecs/HTMLEntityCodec.h"


#include <string>
#include <sstream>
#include <iomanip>
#include <cctype>

#define HEX(x) std::hex << std::setw(x) << std::setfill(L'0')
#define OCT(x) std::octal << std::setw(x) << std::setfill(L'0')

namespace esapi
{
  Char HTMLEntityCodec::REPLACEMENT_CHAR()
  {
    return 65533;
  }

  const String& HTMLEntityCodec::REPLACEMENT_HEX()
  {
    static const String str(L"fffd");
    return str;
  }

  const String& HTMLEntityCodec::REPLACEMENT_STR()
  {
    static const String str(1, L'\uFFFD');
    return str;
  }

  Char HTMLEntityCodec::getNumericEntity(PushbackString&) {
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

  Char HTMLEntityCodec::parseNumber(PushbackString& /*input*/) {
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

  Char HTMLEntityCodec::parseHex(PushbackString&) {
    /*
      StringBuilder sb = new StringBuilder();
      while( input.hasNext() ) {
      Character c = input.peek();

      // if character is a hex digit then add it on and keep going
      if ( L"0123456789ABCDEFabcdefL".indexOf(c) != -1 ) {
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

  Char HTMLEntityCodec::getNamedEntity(PushbackString&) {
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
    static std::shared_ptr<EntityMap> map;

    MEMORY_BARRIER();
    if(!init)
      {
        std::shared_ptr<EntityMap> temp(new EntityMap);
        ASSERT(nullptr != temp.get());

        // Convenience
        EntityMap& tm = *temp.get();

        // 252 items, but no reserve() on std::map
        tm[34]  = L"quot";        /* quotation mark */
        tm[38]  = L"amp";         /* ampersand */
        tm[60]  = L"lt";          /* less-than sign */
        tm[62]  = L"gt";          /* greater-than sign */
        tm[160] =    L"nbsp";        /* no-break space */
        tm[161] =    L"iexcl";       /* inverted exclamation mark */
        tm[162] =    L"cent";        /* cent sign */
        tm[163] =    L"pound";       /* pound sign */
        tm[164] =    L"curren";      /* currency sign */
        tm[165] =    L"yen";         /* yen sign */
        tm[166] =    L"brvbar";      /* broken bar */
        tm[167] =    L"sect";        /* section sign */
        tm[168] =    L"uml";         /* diaeresis */
        tm[169] =    L"copy";        /* copyright sign */
        tm[170] =    L"ordf";        /* feminine ordinal indicator */
        tm[171] =    L"laquo";       /* left-pointing double angle quotation mark */
        tm[172] =    L"not";         /* not sign */
        tm[173] =    L"shy";         /* soft hyphen */
        tm[174] =    L"reg";         /* registered sign */
        tm[175] =    L"macr";        /* macron */
        tm[176] =    L"deg";         /* degree sign */
        tm[177] =    L"plusmn";      /* plus-minus sign */
        tm[178] =    L"sup2";        /* superscript two */
        tm[179] =    L"sup3";        /* superscript three */
        tm[180] =    L"acute";       /* acute accent */
        tm[181] =    L"micro";       /* micro sign */
        tm[182] =    L"para";        /* pilcrow sign */
        tm[183] =    L"middot";      /* middle dot */
        tm[184] =    L"cedil";       /* cedilla */
        tm[185] =    L"sup1";        /* superscript one */
        tm[186] =    L"ordm";        /* masculine ordinal indicator */
        tm[187] =    L"raquo";       /* right-pointing double angle quotation mark */
        tm[188] =    L"frac14";      /* vulgar fraction one quarter */
        tm[189] =    L"frac12";      /* vulgar fraction one half */
        tm[190] =    L"frac34";      /* vulgar fraction three quarters */
        tm[191] =    L"iquest";      /* inverted question mark */
        tm[192] =    L"Agrave";      /* Latin capital letter a with grave */
        tm[193] =    L"Aacute";      /* Latin capital letter a with acute */
        tm[194] =    L"Acirc";       /* Latin capital letter a with circumflex */
        tm[195] =    L"Atilde";      /* Latin capital letter a with tilde */
        tm[196] =    L"Auml";        /* Latin capital letter a with diaeresis */
        tm[197] =    L"Aring";       /* Latin capital letter a with ring above */
        tm[198] =    L"AElig";       /* Latin capital letter ae */
        tm[199] =    L"Ccedil";      /* Latin capital letter c with cedilla */
        tm[200] =    L"Egrave";      /* Latin capital letter e with grave */
        tm[201] =    L"Eacute";      /* Latin capital letter e with acute */
        tm[202] =    L"Ecirc";       /* Latin capital letter e with circumflex */
        tm[203] =    L"Euml";        /* Latin capital letter e with diaeresis */
        tm[204] =    L"Igrave";      /* Latin capital letter i with grave */
        tm[205] =    L"Iacute";      /* Latin capital letter i with acute */
        tm[206] =    L"Icirc";       /* Latin capital letter i with circumflex */
        tm[207] =    L"Iuml";        /* Latin capital letter i with diaeresis */
        tm[208] =    L"ETH";         /* Latin capital letter eth */
        tm[209] =    L"Ntilde";      /* Latin capital letter n with tilde */
        tm[210] =    L"Ograve";      /* Latin capital letter o with grave */
        tm[211] =    L"Oacute";      /* Latin capital letter o with acute */
        tm[212] =    L"Ocirc";       /* Latin capital letter o with circumflex */
        tm[213] =    L"Otilde";      /* Latin capital letter o with tilde */
        tm[214] =    L"Ouml";        /* Latin capital letter o with diaeresis */
        tm[215] =    L"times";       /* multiplication sign */
        tm[216] =    L"Oslash";      /* Latin capital letter o with stroke */
        tm[217] =    L"Ugrave";      /* Latin capital letter u with grave */
        tm[218] =    L"Uacute";      /* Latin capital letter u with acute */
        tm[219] =    L"Ucirc";       /* Latin capital letter u with circumflex */
        tm[220] =    L"Uuml";        /* Latin capital letter u with diaeresis */
        tm[221] =    L"Yacute";      /* Latin capital letter y with acute */
        tm[222] =    L"THORN";       /* Latin capital letter thorn */
        tm[223] =    L"szlig";       /* Latin small letter sharp sXCOMMAX German Eszett */
        tm[224] =    L"agrave";      /* Latin small letter a with grave */
        tm[225] =    L"aacute";      /* Latin small letter a with acute */
        tm[226] =    L"acirc";       /* Latin small letter a with circumflex */
        tm[227] =    L"atilde";      /* Latin small letter a with tilde */
        tm[228] =    L"auml";        /* Latin small letter a with diaeresis */
        tm[229] =    L"aring";       /* Latin small letter a with ring above */
        tm[230] =    L"aelig";       /* Latin lowercase ligature ae */
        tm[231] =    L"ccedil";      /* Latin small letter c with cedilla */
        tm[232] =    L"egrave";      /* Latin small letter e with grave */
        tm[233] =    L"eacute";      /* Latin small letter e with acute */
        tm[234] =    L"ecirc";       /* Latin small letter e with circumflex */
        tm[235] =    L"euml";        /* Latin small letter e with diaeresis */
        tm[236] =    L"igrave";      /* Latin small letter i with grave */
        tm[237] =    L"iacute";      /* Latin small letter i with acute */
        tm[238] =    L"icirc";       /* Latin small letter i with circumflex */
        tm[239] =    L"iuml";        /* Latin small letter i with diaeresis */
        tm[240] =    L"eth";         /* Latin small letter eth */
        tm[241] =    L"ntilde";      /* Latin small letter n with tilde */
        tm[242] =    L"ograve";      /* Latin small letter o with grave */
        tm[243] =    L"oacute";      /* Latin small letter o with acute */
        tm[244] =    L"ocirc";       /* Latin small letter o with circumflex */
        tm[245] =    L"otilde";      /* Latin small letter o with tilde */
        tm[246] =    L"ouml";        /* Latin small letter o with diaeresis */
        tm[247] =    L"divide";      /* division sign */
        tm[248] =    L"oslash";      /* Latin small letter o with stroke */
        tm[249] =    L"ugrave";      /* Latin small letter u with grave */
        tm[250] =    L"uacute";      /* Latin small letter u with acute */
        tm[251] =    L"ucirc";       /* Latin small letter u with circumflex */
        tm[252] =    L"uuml";        /* Latin small letter u with diaeresis */
        tm[253] =    L"yacute";      /* Latin small letter y with acute */
        tm[254] =    L"thorn";       /* Latin small letter thorn */
        tm[255] =    L"yuml";        /* Latin small letter y with diaeresis */
        tm[338] =    L"OElig";       /* Latin capital ligature oe */
        tm[339] =    L"oelig";       /* Latin small ligature oe */
        tm[352] =    L"Scaron";      /* Latin capital letter s with caron */
        tm[353] =    L"scaron";      /* Latin small letter s with caron */
        tm[376] =    L"Yuml";        /* Latin capital letter y with diaeresis */
        tm[402] =    L"fnof";        /* Latin small letter f with hook */
        tm[710] =    L"circ";        /* modifier letter circumflex accent */
        tm[732] =    L"tilde";       /* small tilde */
        tm[913] =    L"Alpha";       /* Greek capital letter alpha */
        tm[914] =    L"Beta";        /* Greek capital letter beta */
        tm[915] =    L"Gamma";       /* Greek capital letter gamma */
        tm[916] =    L"Delta";       /* Greek capital letter delta */
        tm[917] =    L"Epsilon";     /* Greek capital letter epsilon */
        tm[918] =    L"Zeta";        /* Greek capital letter zeta */
        tm[919] =    L"Eta";         /* Greek capital letter eta */
        tm[920] =    L"Theta";       /* Greek capital letter theta */
        tm[921] =    L"Iota";        /* Greek capital letter iota */
        tm[922] =    L"Kappa";       /* Greek capital letter kappa */
        tm[923] =    L"Lambda";      /* Greek capital letter lambda */
        tm[924] =    L"Mu";          /* Greek capital letter mu */
        tm[925] =    L"Nu";          /* Greek capital letter nu */
        tm[926] =    L"Xi";          /* Greek capital letter xi */
        tm[927] =    L"Omicron";     /* Greek capital letter omicron */
        tm[928] =    L"Pi";          /* Greek capital letter pi */
        tm[929] =    L"Rho";         /* Greek capital letter rho */
        tm[931] =    L"Sigma";       /* Greek capital letter sigma */
        tm[932] =    L"Tau";         /* Greek capital letter tau */
        tm[933] =    L"Upsilon";     /* Greek capital letter upsilon */
        tm[934] =    L"Phi";         /* Greek capital letter phi */
        tm[935] =    L"Chi";         /* Greek capital letter chi */
        tm[936] =    L"Psi";         /* Greek capital letter psi */
        tm[937] =    L"Omega";       /* Greek capital letter omega */
        tm[945] =    L"alpha";       /* Greek small letter alpha */
        tm[946] =    L"beta";        /* Greek small letter beta */
        tm[947] =    L"gamma";       /* Greek small letter gamma */
        tm[948] =    L"delta";       /* Greek small letter delta */
        tm[949] =    L"epsilon";     /* Greek small letter epsilon */
        tm[950] =    L"zeta";        /* Greek small letter zeta */
        tm[951] =    L"eta";         /* Greek small letter eta */
        tm[952] =    L"theta";       /* Greek small letter theta */
        tm[953] =    L"iota";        /* Greek small letter iota */
        tm[954] =    L"kappa";       /* Greek small letter kappa */
        tm[955] =    L"lambda";      /* Greek small letter lambda */
        tm[956] =    L"mu";          /* Greek small letter mu */
        tm[957] =    L"nu";          /* Greek small letter nu */
        tm[958] =    L"xi";          /* Greek small letter xi */
        tm[959] =    L"omicron";     /* Greek small letter omicron */
        tm[960] =    L"pi";          /* Greek small letter pi */
        tm[961] =    L"rho";         /* Greek small letter rho */
        tm[962] =    L"sigmaf";      /* Greek small letter final sigma */
        tm[963] =    L"sigma";       /* Greek small letter sigma */
        tm[964] =    L"tau";         /* Greek small letter tau */
        tm[965] =    L"upsilon";     /* Greek small letter upsilon */
        tm[966] =    L"phi";         /* Greek small letter phi */
        tm[967] =    L"chi";         /* Greek small letter chi */
        tm[968] =    L"psi";         /* Greek small letter psi */
        tm[969] =    L"omega";       /* Greek small letter omega */
        tm[977] =    L"thetasym";    /* Greek theta symbol */
        tm[978] =    L"upsih";       /* Greek upsilon with hook symbol */
        tm[982] =    L"piv";         /* Greek pi symbol */
        tm[8194] =   L"ensp";        /* en space */
        tm[8195] =   L"emsp";        /* em space */
        tm[8201] =   L"thinsp";      /* thin space */
        tm[8204] =   L"zwnj";        /* zero width non-joiner */
        tm[8205] =   L"zwj";         /* zero width joiner */
        tm[8206] =   L"lrm";         /* left-to-right mark */
        tm[8207] =   L"rlm";         /* right-to-left mark */
        tm[8211] =   L"ndash";       /* en dash */
        tm[8212] =   L"mdash";       /* em dash */
        tm[8216] =   L"lsquo";       /* left single quotation mark */
        tm[8217] =   L"rsquo";       /* right single quotation mark */
        tm[8218] =   L"sbquo";       /* single low-9 quotation mark */
        tm[8220] =   L"ldquo";       /* left double quotation mark */
        tm[8221] =   L"rdquo";       /* right double quotation mark */
        tm[8222] =   L"bdquo";       /* double low-9 quotation mark */
        tm[8224] =   L"dagger";      /* dagger */
        tm[8225] =   L"Dagger";      /* double dagger */
        tm[8226] =   L"bull";        /* bullet */
        tm[8230] =   L"hellip";      /* horizontal ellipsis */
        tm[8240] =   L"permil";      /* per mille sign */
        tm[8242] =   L"prime";       /* prime */
        tm[8243] =   L"Prime";       /* double prime */
        tm[8249] =   L"lsaquo";      /* single left-pointing angle quotation mark */
        tm[8250] =   L"rsaquo";      /* single right-pointing angle quotation mark */
        tm[8254] =   L"oline";       /* overline */
        tm[8260] =   L"frasl";       /* fraction slash */
        tm[8364] =   L"euro";        /* euro sign */
        tm[8465] =   L"image";       /* black-letter capital i */
        tm[8472] =   L"weierp";      /* script capital pXCOMMAX Weierstrass p */
        tm[8476] =   L"real";        /* black-letter capital r */
        tm[8482] =   L"trade";       /* trademark sign */
        tm[8501] =   L"alefsym";     /* alef symbol */
        tm[8592] =   L"larr";        /* leftwards arrow */
        tm[8593] =   L"uarr";        /* upwards arrow */
        tm[8594] =   L"rarr";        /* rightwards arrow */
        tm[8595] =   L"darr";        /* downwards arrow */
        tm[8596] =   L"harr";        /* left right arrow */
        tm[8629] =   L"crarr";       /* downwards arrow with corner leftwards */
        tm[8656] =   L"lArr";        /* leftwards double arrow */
        tm[8657] =   L"uArr";        /* upwards double arrow */
        tm[8658] =   L"rArr";        /* rightwards double arrow */
        tm[8659] =   L"dArr";        /* downwards double arrow */
        tm[8660] =   L"hArr";        /* left right double arrow */
        tm[8704] =   L"forall";      /* for all */
        tm[8706] =   L"part";        /* partial differential */
        tm[8707] =   L"exist";       /* there exists */
        tm[8709] =   L"empty";       /* empty set */
        tm[8711] =   L"nabla";       /* nabla */
        tm[8712] =   L"isin";        /* element of */
        tm[8713] =   L"notin";       /* not an element of */
        tm[8715] =   L"ni";          /* contains as member */
        tm[8719] =   L"prod";        /* n-ary product */
        tm[8721] =   L"sum";         /* n-ary summation */
        tm[8722] =   L"minus";       /* minus sign */
        tm[8727] =   L"lowast";      /* asterisk operator */
        tm[8730] =   L"radic";       /* square root */
        tm[8733] =   L"prop";        /* proportional to */
        tm[8734] =   L"infin";       /* infinity */
        tm[8736] =   L"ang";         /* angle */
        tm[8743] =   L"and";         /* logical and */
        tm[8744] =   L"or";          /* logical or */
        tm[8745] =   L"cap";         /* intersection */
        tm[8746] =   L"cup";         /* union */
        tm[8747] =   L"int";         /* integral */
        tm[8756] =   L"there4";      /* therefore */
        tm[8764] =   L"sim";         /* tilde operator */
        tm[8773] =   L"cong";        /* congruent to */
        tm[8776] =   L"asymp";       /* almost equal to */
        tm[8800] =   L"ne";          /* not equal to */
        tm[8801] =   L"equiv";       /* identical toXCOMMAX equivalent to */
        tm[8804] =   L"le";          /* less-than or equal to */
        tm[8805] =   L"ge";          /* greater-than or equal to */
        tm[8834] =   L"sub";         /* subset of */
        tm[8835] =   L"sup";         /* superset of */
        tm[8836] =   L"nsub";        /* not a subset of */
        tm[8838] =   L"sube";        /* subset of or equal to */
        tm[8839] =   L"supe";        /* superset of or equal to */
        tm[8853] =   L"oplus";       /* circled plus */
        tm[8855] =   L"otimes";      /* circled times */
        tm[8869] =   L"perp";        /* up tack */
        tm[8901] =   L"sdot";        /* dot operator */
        tm[8968] =   L"lceil";       /* left ceiling */
        tm[8969] =   L"rceil";       /* right ceiling */
        tm[8970] =   L"lfloor";      /* left floor */
        tm[8971] =   L"rfloor";      /* right floor */
        tm[9001] =   L"lang";        /* left-pointing angle bracket */
        tm[9002] =   L"rang";        /* right-pointing angle bracket */
        tm[9674] =   L"loz";         /* lozenge */
        tm[9824] =   L"spades";      /* black spade suit */
        tm[9827] =   L"clubs";       /* black club suit */
        tm[9829] =   L"hearts";      /* black heart suit */
        tm[9830] =   L"diams";       /* black diamond suit */

        map.swap(temp);
        init = true;

        MEMORY_BARRIER();

      } // !init

    return *map.get();
  }

  String HTMLEntityCodec::encodeCharacter( const Char* immune, size_t length, Char c) const
  {
    ASSERT(immune);
    ASSERT(length);

    // check for immune characters
    String str(immune ? String(immune, length) : String());
    if (containsCharacter(c, str)) {
      return String(1,c);
    }

    // check for alphanumeric characters
    ASSERT(0);
    //String hex = Codec.getHexForNonAlphanumeric(c);
    //if ( hex == null ) {
    //return L"L"+c;
    //}

    // check for illegal characters
    ASSERT(0);
    //if ( ( c <= 0x1f && c != L'\t' && c != L'\n' && c != L'\r' ) || ( c >= 0x7f && c <= 0x9f ) )
    //{
    //  hex = REPLACEMENT_HEX();  // Let's entity encode this instead of returning it
    //  c = REPLACEMENT_CHAR();
    //}

    // check if there's a defined entity
    const EntityMap& map = getCharacterToEntityMap();
    if(0 != map.count(c))
    {
      EntityMapIterator it = map.find(c);
      return String(L"&") + it->second + String(L";");
    }

    // Hack ahead!!! Need to cut in ESAPI logic
    if(c < 256 && ::isalnum(c))
      return String(1, c);

    // return the hex entity as suggested in the spec
    StringStream oss;
    oss << HEX(4) << int(0xFFFF & c);
    return String(L"&#x") + oss.str() + String(L";");

    // return String(1, c);
  }

  Char HTMLEntityCodec::decodeCharacter(PushbackString& /*input*/) const {
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
