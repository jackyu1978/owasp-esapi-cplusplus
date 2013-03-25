/*
 * PropertiesConfiguration.cpp
 *
 *  Created on: Mar 21, 2012
 */

#include <fstream>
#include <istream>
#include <iostream>

#include "errors/FileNotFoundException.h"
#include "reference/Configuration.h"
#include "reference/PropertiesConfiguration.h"
#include "util/TextConvert.h"

namespace esapi {

  const String PropertiesConfiguration::DEFAULT_PROPERTIES_FILENAME = "ESAPI.properties";

  PropertiesConfiguration::PropertiesConfiguration(const String &file /* = DEFAULT_PROPERTIES_FILENAME */) {
    load(file);
  }

  PropertiesConfiguration::PropertiesConfiguration(const ConfigurationMap& map)
    : Configuration(map) {
  }

  PropertiesConfiguration::PropertiesConfiguration(std::istream& in)
    : Configuration() {

    ASSERT(!in.bad());
    while (in.good() && !in.eof()) {
      parseLine(in);
    }
  }

  PropertiesConfiguration::~PropertiesConfiguration() {
  }

  /**
   *
   * This function will throw an IllegalArgumentException if the file contents cannot be multibyte decoded.
   */
  void PropertiesConfiguration::load(const String &file) {
    std::cout << "Loading properties file: " << file << std::endl;
    std::ifstream input(file.c_str(), std::ifstream::in);

    // Need to check whether we should be using bad() or fail(). I believe its bad().
    // http://www.cplusplus.com/reference/ios/ios/fail/
    ASSERT(!input.bad());
    if (input.bad())
      throw FileNotFoundException("Could not open file for read: " + file);

    while (input.good() && !input.eof()) {
      parseLine(input);
    }
  }

  void PropertiesConfiguration::parseLine(std::istream &input) {
    ASSERT(!input.bad());
    if(input.bad())
      throw std::runtime_error("Should I shit or go blind???");

    std::string line;
    if (getline(input, line))
      {
	// This trim is needed to properly catch comments
	trimWhitespace(line);
	if(line.empty() || line[0] == '#')
	  return;

	static const char delim = '=';
	const size_t pos = line.find(delim, 0);
	std::string key = line.substr(0, pos);
	std::string value = line.substr(pos + 1, line.size());

	trimWhitespace(key);
	trimWhitespace(value);
	ASSERT(!key.empty());
	ASSERT(!value.empty());

	m_map[key] = value;
      }
  }
}
