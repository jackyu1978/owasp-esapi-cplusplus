/*
* Configuration.cpp
*
*  Created on: Mar 21, 2012
*/

#include "EsapiCommon.h"
#include "errors/IllegalArgumentException.h"
#include "errors/NoSuchPropertyException.h"
#include "errors/ParseException.h"
#include "reference/Configuration.h"
#include "util/TextConvert.h"

#include <sstream>
#include <iomanip>

namespace esapi {

  Configuration::Configuration() {
  }

  Configuration::Configuration(const ConfigurationMap map) : m_map(map) {
  }

  Configuration::~Configuration() {
  }

  bool Configuration::hasProperty(const String &key) const {
    ASSERT(!key.empty());
    if(key.empty())
      throw IllegalArgumentException("Key is not valid");

    return m_map.count(key) > 0;
  }

  bool Configuration::getUnparsedString(const String &key, String &value) const {
    ASSERT(!key.empty());
    if(key.empty())
      throw IllegalArgumentException("Key is not valid");

    ConfigurationMap::const_iterator iterator = m_map.find(key);
    if (iterator != m_map.end()) {
      value = iterator->second;
      return true;
    }
    
    value = "";
    return false;
  }

  String Configuration::getString(const String &key) const {
    ASSERT(!key.empty());
    if(key.empty())
      throw IllegalArgumentException("Key is not valid");

    String value;
    if (!getUnparsedString(key, value))
      throw NoSuchPropertyException("Property not found: " + key);

    return value;
  }

  String Configuration::getString(const String &key, const String &defaultValue) const {
    ASSERT(!key.empty());
    if(key.empty())
      throw IllegalArgumentException("Key is not valid");

    String value;
    if (getUnparsedString(key, value))
      return value;

    return defaultValue;
  }

  int Configuration::getInt(const String &key) const {
    ASSERT(!key.empty());
    if(key.empty())
      throw IllegalArgumentException("Key is not valid");

    String value;
    if (getUnparsedString(key, value))
      return parseInt(value);

    throw NoSuchPropertyException("Property not found: " + key);
  }

  int Configuration::getInt(const String &key, int defaultValue) const {
    ASSERT(!key.empty());
    if(key.empty())
      throw IllegalArgumentException("Key is not valid");

    String value;
    if (getUnparsedString(key, value))
      return parseInt(value);

    return defaultValue;
  }

  bool Configuration::getBool(const String &key) const {
    ASSERT(!key.empty());
    if(key.empty())
      throw IllegalArgumentException("Key is not valid");

    String value;
    if (getUnparsedString(key, value))
      return parseBool(value);

    throw NoSuchPropertyException("Property not found: " + key);
  }

  bool Configuration::getBool(const String &key, const bool defaultValue) const {
    ASSERT(!key.empty());
    if(key.empty())
      throw IllegalArgumentException("Key is not valid");

    String value;
    if (getUnparsedString(key, value))
      return parseBool(value);

    return defaultValue;
  }

  bool Configuration::parseBool(const String &str) const
  {
    ASSERT(!str.empty());
    if(str.empty())
      throw ParseException("Boolean value is empty");

    String lower(str);
    trimWhitespace(lower);
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

    if (lower == String(1, (char)0x00) || lower == "0" || lower == "false" || lower == "off" || lower == "no")
      return false;
    else if (lower == String(1, (char)0x01)  || lower == "1" || lower == "true" || lower == "on" || lower == "yes")
      return true;
    else
      throw ParseException("Cannot parse as boolean: " + str);
  }

  int Configuration::parseInt(const String &s) const
  {
    ASSERT(!s.empty());

    String temp(s);
    trimWhitespace(temp);

    StringStream ss(temp);
    int n = 0;

    const String& prefix = temp.substr(0,2);
    if(prefix == "0x" || prefix == "0X")
      ss >> std::setbase(16);

    ss >> n;
    ASSERT(!(ss.fail()));
    if (ss.fail())
        throw ParseException("Cannot parse as int: " + s);

    return n;
  }

  StringList Configuration::getStringList(const String &key) const
  {
    ASSERT(!key.empty());
    if(key.empty())
      throw IllegalArgumentException("Key is not valid");

    StringList value;
    String unparsed;

    if (getUnparsedString(key, unparsed))
    {
      splitString(unparsed, value, ", ", true);
    }
    else
      throw NoSuchPropertyException("Property not found: " + key);

    return value;
  }

  StringList Configuration::getStringList(const String &key, const StringList &defaultValue) const
  {
    ASSERT(!key.empty());
    if(key.empty())
      throw IllegalArgumentException("Key is not valid");

    StringList value;
    String unparsed;

    if (getUnparsedString(key, unparsed))
    {
      splitString(unparsed, value, ",", true);
    }
    else
      value = defaultValue;

    return value;
  }

  void Configuration::trimWhitespace(String& str) const
  {
    std::string::size_type pos1 = str.find_first_not_of(" \t\n\v\f\r");
    if (pos1 != std::string::npos)
      str.erase(0, pos1);

    std::string::size_type pos2 = str.find_last_not_of(" \t\n\v\f\r");
    if (pos2 != std::string::npos)
      str.erase(pos2 + 1);
  }

  void Configuration::splitString(String &input, StringList &output, const String &delimiters = " ", const bool trimEmpty = false) const
  {
    if (delimiters.empty())
      throw IllegalArgumentException("Cannot split using empty set of delimiters");

    String::size_type offset = 0;
    while (true)
    {
      String::size_type pos = input.find_first_of(delimiters, offset);
      if (pos == String::npos)
      {
        pos = input.length();

        if (pos != offset || !trimEmpty)
          output.push_back(input.substr(offset));
        break;
      }
      else
      {
        if (pos != offset || !trimEmpty)
          output.push_back(input.substr(offset, pos - offset));
        offset = pos + 1;
      }
    }
  }
}
