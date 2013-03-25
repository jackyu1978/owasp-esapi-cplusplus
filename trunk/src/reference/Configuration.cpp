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

namespace esapi {

  Configuration::Configuration() {
  }

  //Configuration::Configuration(const hash_map<String, String> map): m_map(map) {
  //}

  Configuration::Configuration(const ConfigurationMap map): m_map(map) {
  }

  Configuration::~Configuration() {
  }

  bool Configuration::hasProperty(const String &key) const {
    return m_map.count(key) > 0;
  }

  bool Configuration::getUnparsedString(const String &key, String &value) const {
    // hash_map<String, String>::const_iterator iterator = m_map.find(key);
    ConfigurationMap::const_iterator iterator = m_map.find(key);
    if (iterator != m_map.end()) {
      value = iterator->second;
      return true;
    }
    else
      return false;
  }

  String Configuration::getString(const String &key) const {
    String value;
    if (!getUnparsedString(key, value))
      throw NoSuchPropertyException("Property not found: " + key);

    return value;
  }

  String Configuration::getString(const String &key, const String &defaultValue) const {
    String value;
    if (getUnparsedString(key, value))
      return value;

    return defaultValue;
  }

  int Configuration::getInt(const String &key) const {
    String value;
    if (getUnparsedString(key, value))
      return parseInt(value);

    throw NoSuchPropertyException("Property not found: " + key);
  }

  int Configuration::getInt(const String &key, int defaultValue) const {
    String value;
    if (getUnparsedString(key, value))
      return parseInt(value);

    return defaultValue;
  }

  bool Configuration::getBool(const String &key) const {
    String value;
    if (getUnparsedString(key, value))
      return parseBool(value);

    throw NoSuchPropertyException("Property not found: " + key);
  }

  bool Configuration::getBool(const String &key, const bool defaultValue) const {
    String value;
    if (getUnparsedString(key, value))
      return parseBool(value);

    return defaultValue;
  }


  bool Configuration::parseBool(const String &s) const {
    String lower(s);
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

    if (s == "\x00" || s == "0" || s == "false" || s == "off" || s == "no")
      return false;
    else if (s == "\x01" || s == "1" || s == "true" || s == "on" || s == "yes")
      return true;
    else
      throw ParseException("Cannot parse as boolean: " + s);
  }

  int Configuration::parseInt(const String &s) const {

    StringStream ss(s);
    int n = 0;

    ss >> n;
    ASSERT(!(ss.fail()));
    if (ss.fail())
        throw ParseException("Cannot parse as int: " + s);

    return n;
  }

  StringList Configuration::getStringList(const String &key) const
  {
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
