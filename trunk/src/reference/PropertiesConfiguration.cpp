/*
 * PropertiesConfiguration.cpp
 *
 *  Created on: Mar 21, 2012
 */

#include <fstream>
#include <ios>
#include <iostream>

#include "errors/FileNotFoundException.h"
#include "reference/Configuration.h"
#include "reference/PropertiesConfiguration.h"
#include "util/TextConvert.h"

namespace esapi {

const String PropertiesConfiguration::DEFAULT_PROPERTIES_FILENAME = L"ESAPI.properties";

PropertiesConfiguration::PropertiesConfiguration(const String &file /* = DEFAULT_PROPERTIES_FILENAME */) {
	load(file);
}

PropertiesConfiguration::PropertiesConfiguration(const hash_map<String, String> &map)
		: Configuration(map) {
}

PropertiesConfiguration::~PropertiesConfiguration() {
}


inline void PropertiesConfiguration::ltrim(std::string &s) {
	std::string::size_type pos = s.find_first_not_of(" \t\n\r\v");
	if (pos != std::string::npos)
		s.erase(0, pos);
}

inline void PropertiesConfiguration::rtrim(std::string &s) {
	std::string::size_type pos = s.find_last_not_of(" \t\n\r\v");
	if (pos != std::string::npos)
		s.erase(pos + 1);
}

inline void PropertiesConfiguration::trim(std::string &s) {

	ltrim(s);
	rtrim(s);
}

inline void PropertiesConfiguration::ltrim(std::wstring &s) {
	std::wstring::size_type pos = s.find_first_not_of(L" \t\n\r\v");
	if (pos != std::wstring::npos)
		s.erase(0, pos);
}

inline void PropertiesConfiguration::rtrim(std::wstring &s) {
	std::wstring::size_type pos = s.find_last_not_of(L" \t\n\r\v");
	if (pos != std::wstring::npos)
		s.erase(pos + 1);
}

inline void PropertiesConfiguration::trim(std::wstring &s) {

	ltrim(s);
	rtrim(s);
}

/**
 *
 * This function will throw an IllegalArgumentException if the file contents cannot be multibyte decoded.
 */
void PropertiesConfiguration::load(const String &file) {
	std::string nFile = TextConvert::WideToNarrow(file);
	std::cout << "Loading properties file: " << nFile << std::endl;
	std::ifstream input(nFile.c_str(), std::ios::in);
	if (input.fail())
		throw FileNotFoundException("Could not open file for read: " + nFile);
	while (input) {
		parseLine(input);
	}
}

void PropertiesConfiguration::parseLine(std::ifstream &input) {
	if (input.is_open()) {
		std::string line;
		if (getline(input, line)) {
			trim(line);
			if (line.size() > 0 && line[0] != '#') {
				char delimiter = '=';
				size_t delimiter_pos = line.find(delimiter, 0);
				std::string nKey = line.substr(0, delimiter_pos);
				std::string nValue = line.substr(delimiter_pos + 1, line.size());
				trim(nKey);
				trim(nValue);
				// Convert to wstring key and value
				String key = TextConvert::NarrowToWide(nKey);
				String value = TextConvert::NarrowToWide(nValue);
				map_[key] = value;
			}
		}
	}
}

}
