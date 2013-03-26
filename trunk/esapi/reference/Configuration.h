/*
 * Configuration.h
 *
 *  Created on: Mar 21, 2012
 */

#pragma once

#include "EsapiCommon.h"
#include "EsapiTypes.h"

namespace esapi {

  typedef unordered_map<String, String> ConfigurationMap;

  class ESAPI_EXPORT Configuration
  {  

  public:

    bool hasProperty(const String &key) const;

    String getString(const String &key) const;
    String getString(const String &key, const String &defaultValue) const;
    StringList getStringList(const String &key) const;
    StringList getStringList(const String &key, const StringList &defaultValue) const;
    
    int getInt(const String &key) const;
    int getInt(const String &key, int defaultValue) const;
    
    bool getBool(const String &key) const;
    bool getBool(const String &key, const bool defaultValue) const;

    // void setBool(const String &key, const bool &value);
    // void setInt(const String &key, const int &value);
    // void setInt(const String &key, const int &value);

    Configuration();
    Configuration(const ConfigurationMap& map);

    virtual ~Configuration();

  protected:
    void trimWhitespace(String& str) const;
    bool getUnparsedString(const String &, String &) const;
    bool parseBool(const String &) const;
    int parseInt(const String &) const;
    void splitString(String &, StringList &, const String &, const bool trimEmpty) const;

  private:
    ConfigurationMap m_map;

  private:
    Configuration(const Configuration &);
    Configuration& operator= (const Configuration &);
  };

} // NAMESPACE
