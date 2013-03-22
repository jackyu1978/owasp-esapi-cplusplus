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

#include "EsapiCommon.h"
#include "codecs/PushbackString.h"

namespace esapi
{
  PushbackString::PushbackString(const NarrowString& input)
    : input(input), varPushback(0), varTemp(0), varIndex(0), varMark(0) {
    ASSERT(!input.empty());
  }

  void PushbackString::pushback( Char c ){
    ASSERT(c != 0);
    this->varPushback = c;
  }

  size_t PushbackString::index() const{
    ASSERT(varIndex < input.length());
    return this->varIndex;
  }

  bool PushbackString::hasNext() const{
    if ( this->varPushback != 0 ) return true;
    if ( this->input.compare("") == 0 ) return false;
    if ( this->input.length() == 0 ) return false;
    if ( this->varIndex >= this->input.length() ) return false;
    return true;
  }

  Char PushbackString::next() {
    if ( this->varPushback != 0 ) {
      Char save = this->varPushback;
      this->varPushback = 0;
      return save;
    }
    if ( this->input.compare("") == 0) return 0;
    if ( this->input.length() == 0 ) return 0;
    if ( this->varIndex >= this->input.length() ) return 0;

    ASSERT(varIndex < input.length());
    return this->input[this->varIndex++];
  }

  Char PushbackString::nextHex() {
    Char c = next();
    if ( c == 0 ) return 0;
    if ( isHexDigit( c ) ) return c;
    return 0;
  }

  Char PushbackString::nextOctal() {
    Char c = next();
    if ( c == 0 ) return 0;
    if ( isOctalDigit( c ) ) return c;
    return 0;
  }

  bool PushbackString::isHexDigit( Char c ) {
    ASSERT(c != 0);

    if ( c == 0 ) return false;
    int ch = c;
    return (ch >= L'0' && ch <= L'9' ) || (ch >= L'a' && ch <= L'f' ) || (ch >= L'A' && ch <= L'F' );
  }

  bool PushbackString::isOctalDigit( Char c ) {
    ASSERT(c != 0);

    if ( c == 0 ) return false;
    int ch = c;
    return ch >= L'0' && ch <= L'7';
  }

  Char PushbackString::peek() const{
    if ( this->varPushback != 0 ) return this->varPushback;
    if ( this->input.compare("") == 0) return 0;
    if ( this->input.length() == 0 ) return 0;
    if ( this->varIndex >= this->input.length() ) return 0;

    ASSERT(varIndex < input.length());
    return this->input[this->varIndex];
  }

  bool PushbackString::peek( Char c ) const{
    ASSERT(c != 0);

    if ( this->varPushback != 0 && this->varPushback == c ) return true;
    if ( this->input.compare("") == 0) return false;
    if ( this->input.length() == 0 ) return false;
    if ( this->varIndex >= this->input.length() ) return false;

    ASSERT(varIndex < input.length());
    return this->input[this->varIndex] == c;
  }

  void PushbackString::mark() const{
    ASSERT(!input.empty());

    this->varTemp = this->varPushback;
    this->varMark = this->varIndex;
  }

  void PushbackString::reset()  {
    ASSERT(!input.empty());

    this->varPushback = this->varTemp;
    this->varIndex = this->varMark;
  }

  String PushbackString::remainder() {
    ASSERT(!input.empty());
    ASSERT(varIndex < input.length());

    String output = this->input.substr( this->varIndex );
    if ( this->varPushback != 0 ) {
      output = this->varPushback + output;
    }
    return output;
  }
} //espai
