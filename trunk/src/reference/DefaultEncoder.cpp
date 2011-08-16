/**
* OWASP Enterprise Security API (ESAPI)
*
* This file is part of the Open Web Application Security Project (OWASP)
* Enterprise Security API (ESAPI) project. For details, please see
* http://www.owasp.org/index.php/ESAPI.
*
* Copyright (c) 2011 - The OWASP Foundation
*/

#include "EncoderConstants.h"
#include "reference/DefaultEncoder.h"

esapi::Encoder* esapi::DefaultEncoder::singletonInstance = NULL;
//esapi::Logger* esapi::DefaultEncoder::logger = NULL;

// Codecs
//std::list<esapi::Codec*> esapi::DefaultEncoder::codecs = NULL;
//esapi::HTMLEntityCodec esapi::DefaultEncoder::htmlCodec;
//esapi::XMLEntityCodec esapi::DefaultEncoder::xmlCodec;
//esapi::PercentCodec esapi::DefaultEncoder::percentCodec;
//esapi::JavaScriptCodec esapi::DefaultEncoder::javaScriptCodec;
//esapi::VBScriptCodec esapi::DefaultEncoder::vbScriptCodec;
//esapi::CSSCodec esapi::DefaultEncoder::cssCodec;

const char esapi::DefaultEncoder::IMMUNE_HTML [] = {' ',' '};
const char esapi::DefaultEncoder::IMMUNE_HTMLATTR [] = {' ',' '};
const char esapi::DefaultEncoder::IMMUNE_CSS [] = {' ',' '};
const char esapi::DefaultEncoder::IMMUNE_JAVASCRIPT [] = {' ',' '};
const char esapi::DefaultEncoder::IMMUNE_VBSCRIPT [] = {' ',' '};
const char esapi::DefaultEncoder::IMMUNE_XML [] = {' ',' '};
const char esapi::DefaultEncoder::IMMUNE_SQL [] = {' ',' '};
const char esapi::DefaultEncoder::IMMUNE_OS [] = {' ',' '};
const char esapi::DefaultEncoder::IMMUNE_XMLATTR [] = {' ',' '};
const char esapi::DefaultEncoder::IMMUNE_XPATH [] = {' ',' '};

esapi::DefaultEncoder::DefaultEncoder() {

}

esapi::Encoder* esapi::DefaultEncoder::getInstance() {
	Encoder* enc;
	return enc;
}

esapi::DefaultEncoder::DefaultEncoder( std::list<std::string> ) {

}

std::string esapi::DefaultEncoder::canonicalize( const std::string & ) {
	return "";
}

std::string esapi::DefaultEncoder::canonicalize( const std::string & , bool) {
	return "";
}

std::string esapi::DefaultEncoder::canonicalize( const std::string & , bool, bool ) {
	return "";
}

std::string esapi::DefaultEncoder::encodeForHTML(const std::string &) {
	return "";
}

std::string esapi::DefaultEncoder::decodeForHTML(const std::string &) {
	return "";
}

std::string esapi::DefaultEncoder::encodeForHTMLAttribute(const std::string &) {
	return "";
}

std::string esapi::DefaultEncoder::encodeForCSS(const std::string &) {
	return "";
}

std::string esapi::DefaultEncoder::encodeForJavaScript(const std::string &) {
	return "";
}

std::string esapi::DefaultEncoder::encodeForVBScript(const std::string &) {
	return "";
}

std::string esapi::DefaultEncoder::encodeForSQL(const Codec &codec, const std::string &) {
	return "";
}

std::string esapi::DefaultEncoder::encodeForOS(const Codec &codec, const std::string &) {
	return "";
}

std::string esapi::DefaultEncoder::encodeForLDAP(const std::string &) {
	return "";
}

std::string esapi::DefaultEncoder::encodeForDN(const std::string &) {
	return "";
}

std::string esapi::DefaultEncoder::encodeForXPath(const std::string &) {
	return "";
}

std::string esapi::DefaultEncoder::encodeForXML(const std::string &) {
	return "";
}

std::string esapi::DefaultEncoder::encodeForXMLAttribute(const std::string &) {
	return "";
}

std::string esapi::DefaultEncoder::encodeForURL(const std::string &) throw (EncodingException) {
	return "";
}

std::string esapi::DefaultEncoder::decodeFromURL(const std::string &) throw (EncodingException) {
	return "";
}

std::string esapi::DefaultEncoder::encodeForBase64(const std::string &, bool) {
	return "";
}

std::string esapi::DefaultEncoder::decodeFromBase64(const std::string &) {
	return "";
}
