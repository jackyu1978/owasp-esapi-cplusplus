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

#include "esapi/codecs/Codec.h"
#include <sstream>

std::string* esapi::Codec::hexArray (){
	std::string *arrHex[256];

	for ( int c = 0; c < 0xFF; c++ ) {
		if ( c >= 0x30 && c <= 0x39 || c >= 0x41 && c <= 0x5A || c >= 0x61 && c <= 0x7A ) {
			*arrHex[c] = "";
		} else {
			std::stringstream str;
			str << std::hex << c;
			*arrHex[c] = str.str();
		}
	}

	return *arrHex;
}

const std::string * esapi::Codec::hex = hexArray();

std::string esapi::Codec::encode(char immune[], std::string input){
	std::string sb = "";

	for (unsigned int i = 0; i < input.length(); i++) {
				char c = input[i];
				sb.append(encodeCharacter(immune, c));
			}

	return sb;
}

std::string esapi::Codec::encodeCharacter( char immune[], char c){
	return ""+c;
}

std::string esapi::Codec::decode(std::string input){
	std::string sb = "";

	esapi::PushbackString pbs(input);
			while (pbs.hasNext()) {
				char c = decodeCharacter(pbs);
				if (c != 0) {
					sb+=c;
				} else {
					sb+=pbs.next();
				}
			}
	return sb;
}

char esapi::Codec::decodeCharacter( PushbackString input ) {
	return input.next();
}

std::string esapi::Codec::getHexForNonAlphanumeric(char c){
	int i = c;
	if(i<0xFF)
		return this->hex[i];
	return toHex(i);
}

std::string esapi::Codec::toOctal(char c){
	std::stringstream str;
	str << std::oct << c;
	return str.str();
}

std::string esapi::Codec::toHex(char c){
	std::stringstream str;
	str << std::hex << c;
	return str.str();
}

bool esapi::Codec::containsCharacter( char c, char array[]){
	int arrSize = sizeof(array)/sizeof(char);

	for (int ch=0; ch < arrSize; ch++) {
		if (c == array[ch]) return true;
	}
	return false;
}
