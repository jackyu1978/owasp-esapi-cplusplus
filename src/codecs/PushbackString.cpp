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

esapi::PushbackString::PushbackString(const std::string& input)
  : input(input), varPushback(0), varTemp(0), varIndex(0), varMark(0) {
  ASSERT(!input.empty());
}

void esapi::PushbackString::pushback( char c ){
  ASSERT(c != 0);
  this->varPushback = c;
}

size_t esapi::PushbackString::index() const{
  ASSERT(varIndex < input.length());
  return this->varIndex;
}

bool esapi::PushbackString::hasNext() const{
  if ( this->varPushback != 0 ) return true;
  if ( this->input.compare("") == 0 ) return false;
  if ( this->input.length() == 0 ) return false;
  if ( this->varIndex >= this->input.length() ) return false;
  return true;
}

char esapi::PushbackString::next() {
  if ( this->varPushback != 0 ) {
    char save = this->varPushback;
    this->varPushback = 0;
    return save;
  }
  if ( this->input.compare("") == 0) return 0;
  if ( this->input.length() == 0 ) return 0;
  if ( this->varIndex >= this->input.length() ) return 0;

  ASSERT(varIndex < input.length());
  return this->input[this->varIndex++];
}

char esapi::PushbackString::nextHex() {
  char c = next();
  if ( c == 0 ) return 0;
  if ( isHexDigit( c ) ) return c;
  return 0;
}

char esapi::PushbackString::nextOctal() {
  char c = next();
  if ( c == 0 ) return 0;
  if ( isOctalDigit( c ) ) return c;
  return 0;
}

bool esapi::PushbackString::isHexDigit( char c ) {
  ASSERT(c != 0);

  if ( c == 0 ) return false;
  int ch = c;
  return (ch >= '0' && ch <= '9' ) || (ch >= 'a' && ch <= 'f' ) || (ch >= 'A' && ch <= 'F' );
}

bool esapi::PushbackString::isOctalDigit( char c ) {
  ASSERT(c != 0);

  if ( c == 0 ) return false;
  int ch = c;
  return ch >= '0' && ch <= '7';
}

char esapi::PushbackString::peek() const{
  if ( this->varPushback != 0 ) return this->varPushback;
  if ( this->input.compare("") == 0) return 0;
  if ( this->input.length() == 0 ) return 0;
  if ( this->varIndex >= this->input.length() ) return 0;

  ASSERT(varIndex < input.length());
  return this->input[this->varIndex];
}

bool esapi::PushbackString::peek( char c ) const{
  ASSERT(c != 0);

  if ( this->varPushback != 0 && this->varPushback == c ) return true;
  if ( this->input.compare("") == 0) return false;
  if ( this->input.length() == 0 ) return false;
  if ( this->varIndex >= this->input.length() ) return false;

  ASSERT(varIndex < input.length());
  return this->input[this->varIndex] == c;
}

void esapi::PushbackString::mark() const{
  ASSERT(!input.empty());

  this->varTemp = this->varPushback;
  this->varMark = this->varIndex;
}

void esapi::PushbackString::reset()  {
  ASSERT(!input.empty());

  this->varPushback = this->varTemp;
  this->varIndex = this->varMark;
}

std::string esapi::PushbackString::remainder() {
  ASSERT(!input.empty());
  ASSERT(varIndex < input.length());

  std::string output = this->input.substr( this->varIndex );
  if ( this->varPushback != 0 ) {
    output = this->varPushback + output;
  }
  return output;
}
