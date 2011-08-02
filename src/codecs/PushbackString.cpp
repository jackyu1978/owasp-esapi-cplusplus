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

#include "codecs/PushbackString.h"

esapi::PushbackString::PushbackString( std::string input) {
	this->input = input;
	this->varIndex = 0;
	this->varMark = 0;
}

void esapi::PushbackString::pushback( char c ){
	this->varPushback = c;
}

int esapi::PushbackString::index(){
	return this->varIndex;
}

bool esapi::PushbackString::hasNext(){
	if ( this->varPushback != 0 ) return true;
	if ( this->input.compare("") ) return false;
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
	if ( this->input.compare("") ) return 0;
	if ( this->input.length() == 0 ) return 0;
	if ( this->varIndex >= this->input.length() ) return 0;
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
	if ( c == 0 ) return false;
	int ch = c;
	return (ch >= '0' && ch <= '9' ) || (ch >= 'a' && ch <= 'f' ) || (ch >= 'A' && ch <= 'F' );
}

bool esapi::PushbackString::isOctalDigit( char c ) {
	if ( c == 0 ) return false;
	int ch = c;
	return ch >= '0' && ch <= '7';
}

char esapi::PushbackString::peek() {
	if ( this->varPushback != 0 ) return this->varPushback;
	if ( this->input.compare("") ) return 0;
	if ( this->input.length() == 0 ) return 0;
	if ( this->varIndex >= this->input.length() ) return 0;
	return this->input[this->varIndex];
}

bool esapi::PushbackString::peek( char c ) {
	if ( this->varPushback != 0 && this->varPushback == c ) return true;
	if ( this->input.compare("") ) return false;
	if ( this->input.length() == 0 ) return false;
	if ( this->varIndex >= this->input.length() ) return false;
	return this->input[this->varIndex] == c;
}

void esapi::PushbackString::mark() {
	this->temp = this->varPushback;
	this->varMark = this->varIndex;
}

void esapi::PushbackString::reset()  {
	this->varPushback = this->temp;
	this->varIndex = this->varMark;
}

std::string esapi::PushbackString::remainder() {
	std::string output = this->input.substr( this->varIndex );
	if ( this->varPushback != 0 ) {
		output = this->varPushback + output;
	}
	return output;
}
