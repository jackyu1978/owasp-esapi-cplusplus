/*
 * Configuration.h
 *
 *  Created on: Mar 21, 2012
 */

#pragma once

#include "EsapiCommon.h"
#include "EsapiTypes.h"

namespace esapi {

class ESAPI_EXPORT Configuration {
public:
	//	class KeyValuePair {
	//	public:
	//		KeyValuePair(const String &key, String &value): key_(key), value_(value) {
	//
	//		}
	//
	//		const String &key() const {
	//			return key_;
	//		}
	//
	//		const String &value() const {
	//			return value_;
	//		}
	//
	//	private:
	//		const String &key_;
	//		String &value_;
	//	};

	bool hasProperty(const String &key) const;
	//	void setString(const String &key, const String &value);
	String getString(const String &key) const;
	String getString(const String &key, const String &defaultValue) const;
	StringList getStringList(const String &key) const;
	StringList getStringList(const String &key, const StringList &defaultValue) const;
	//	void setInt(const String &key, const int &value);
	int getInt(const String &key) const;
	int getInt(const String &key, int defaultValue) const;
	//	void setBool(const String &key, const bool &value);
	bool getBool(const String &key) const;
	bool getBool(const String &key, const bool defaultValue) const;

	Configuration();
	// Configuration(const hash_map<String, String> map);
  Configuration(const unordered_map<String, String> map);
	virtual ~Configuration();

protected:
	bool getUnparsedString(const String &, String &) const;
	bool parseBool(const String &) const;
	int parseInt(const String &) const;
	void splitString(String &, StringList &, const String &, const bool trimEmpty) const;

	// hash_map<String, String> map_;
  unordered_map<String, String> map_;

private:
	Configuration(const Configuration &);
	Configuration& operator= (const Configuration &);
};

} // NAMESPACE
