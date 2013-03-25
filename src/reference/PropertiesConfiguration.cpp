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

  PropertiesConfiguration::PropertiesConfiguration(const String &file)
    : Configuration() {

    if(!file.empty())
      load(file);
  }

  PropertiesConfiguration::PropertiesConfiguration(const ConfigurationMap& map)
    : Configuration(map) {
  }

  PropertiesConfiguration::PropertiesConfiguration(std::istream& in)
    : Configuration() {

    parseStream(in);
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

    // fail() catches File Not Found, bad() does not.
    ASSERT(!input.fail());
    if (input.fail())
      throw FileNotFoundException("Failed to open file for read: " + file);

    parseStream(input);
  }

  void PropertiesConfiguration::parseStream(std::istream &input) {
    ASSERT(!input.fail());
    if(input.fail())
      throw std::runtime_error("Should I shit or go blind???");

    size_t lineno = 0;	
    while (input.good() && !input.eof()) {
      try
	{
	  lineno++;
	  parseLine(input);
	}
      catch(std::exception& ex)
	{
	  std::clog << ex.what() << " (line " << lineno << ")" << std::endl;
	}
    }
  }

  void PropertiesConfiguration::parseLine(std::istream &input) {
    ASSERT(!input.fail());
    if(input.fail())
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

        ASSERT(pos != String::npos);
        if(pos == String::npos)
          std::clog << "delimiter not found" << std::endl;

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

