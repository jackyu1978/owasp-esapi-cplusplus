/*
 * PropertiesConfiguration.h
 *
 *  Created on: Mar 21, 2012
 */

#pragma once

#include "EsapiCommon.h"
#include "Configuration.h"

namespace esapi {

  class ESAPI_EXPORT PropertiesConfiguration: public Configuration {
  public:

    /**
     * Constructs a property store backed by disk storage.
     *
     * @param filename the disk file to load. If the file does not exist, a
     *        FileNotFoundException is thrown. If the file exists, the file
     *        is parsed and used for name/value pair lookups.
     */
    PropertiesConfiguration(const String &filename = DEFAULT_PROPERTIES_FILENAME);

    /**
     * Constructs a property store from an existing store.
     */
    PropertiesConfiguration(const ConfigurationMap &);

    /**
     * Constructs a property store from an input stream such as
     *        an ifstream or istringstream.
     *
     * @param istream the stream to parse.
     */
    PropertiesConfiguration(std::istream &);

    /**
     * Standard destructor.
     */
    virtual ~PropertiesConfiguration();

    /**
     * Loads a property store from disk storage.
     *
     * @param filename the disk file to load. If the file does not exist, a
     *        FileNotFoundException is thrown. If the file exists, the file
     *        is parsed and used for name/value pair lookups. Any existing
     *        data will be removed before reading the new configuration.
     */
    void load(const String &filename);

  protected:

    /**
     * The default filename of the property store.
     *
     * @param DEFAULT_PROPERTIES_FILENAME is defined as 'ESAPI.properties'.
     */
    static const String DEFAULT_PROPERTIES_FILENAME;

  protected:

    /**
     * Parses an input stream to construct the property store. parseStream
     *        repeatedly calls parseLine with line number information to
     *        produce meaningful exceptions on error.
     *
     * @param istream the stream to parse.
     */
    void parseStream(std::istream &input);

    /**
     * Parses one line from the input stream. The data format is a simple
     *        name/value pair scheme with the equal sign ('=') as a 
     *        delimiter. Leading and trailing whitespace is ignored for
     *        both the key and value. An empty key (after trimming whitespace)
     *        will cause an exception. An empty value (after trimming
     *        whitespace) is allowed, but could cause an exception if the
     *        value is *not* retrieved as a String (for example, Boolean
     *        or Integer).
     *
     * @param input the stream to parse.
     * @param lineno the current line number.
     */
    void parseLine(std::istream &input, size_t lineno);
  };

} // NAMESPACE

