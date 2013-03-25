/*
 * PropertiesConfiguration.h
 *
 *  Created on: Mar 21, 2012
 */

#pragma once

#include "EsapiCommon.h"
#include "Configuration.h"

namespace esapi {

  class ESAPI_EXPORT PropertiesConfiguration: protected Configuration {
  public:
    void load(const String &file);

    PropertiesConfiguration(const String &file = DEFAULT_PROPERTIES_FILENAME);
    PropertiesConfiguration(const ConfigurationMap &);
    PropertiesConfiguration(std::istream &);
    virtual ~PropertiesConfiguration();

  protected:
    static const String DEFAULT_PROPERTIES_FILENAME;

  protected:
    void parseStream(std::istream &input);
    void parseLine(std::istream &input, size_t lineno);
  };

} // NAMESPACE

