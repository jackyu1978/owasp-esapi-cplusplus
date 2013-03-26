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
    // std::clog << "Loading properties file: " << file << std::endl;
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

    // Clear the existing map if there are any elements
    if(!empty())
      clear();

    size_t lineno = 0;	
    while (input.good() && !input.eof()) {
      lineno++;
      parseLine(input, lineno);
    }
  }

  // http://docs.oracle.com/javase/6/docs/api/java/util/Properties.html
  // Nothing fancy here. We parse name/value pairs based on the '=' delimiter
  // The Java parser is much more versatile.
  void PropertiesConfiguration::parseLine(std::istream &input, size_t lineno) {
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
        if(pos == String::npos) {
          std::ostringstream ss;
          ss << "parseLine: delimiter not found (line: " << lineno << ")";
          // std::clog << ss.str() << std::endl;
          throw IllegalArgumentException(ss.str());
        }

	std::string key = line.substr(0, pos);
	std::string value = line.substr(pos + 1, line.size());

        // Keys must be present
	trimWhitespace(key);
        ASSERT(!key.empty());
        if(key.empty()) {                    
          std::ostringstream ss;
          ss << "parseLine: property key is not valid (line: " << lineno << ")";
          // std::clog << ss.str() << std::endl;
          throw IllegalArgumentException(ss.str());
        }

        // Value is optional, but will likely result in an exception during retrieval.
        // String *will not* throw on getString(...); but Bool and Int *will*
        // throw when using getBool(...) or getInt(...).
	trimWhitespace(value);	
	ASSERT(!value.empty());

        setString(key, value);
      }
  }
}

