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
	void load(const String &file);
//	template<class C>
//	static void ltrim(C &s);
//	template<class C>
//	static void rtrim(C &s);
//	template<class C>
//	static void trim(C &s);

	PropertiesConfiguration(const String &file = DEFAULT_PROPERTIES_FILENAME);
	PropertiesConfiguration(const hash_map<String, String> &);
	virtual ~PropertiesConfiguration();

protected:
	void ltrim(std::string &);
	void rtrim(std::string &);
	void trim(std::string &);
	void ltrim(std::wstring &);
	void rtrim(std::wstring &);
	void trim(std::wstring &);

	static const String DEFAULT_PROPERTIES_FILENAME;

private:
	void parseLine(std::ifstream &input);
};

//template <class C>
//inline void ltrim(std::basic_string<C> &s) {
//	typename std::basic_string<C>::size_type pos = s.find_first_not_of(" \t\n\v");
//	if (pos != std::basic_string<C>::npos)
//		s.erase(0, pos);
//}
//
//template <class C>
//inline void rtrim(std::basic_string<C> &s) {
//	typename std::basic_string<C>::size_type pos = s.find_last_not_of(" \t\n\v");
//	if (pos != std::basic_string<C>::npos)
//		s.erase(pos + 1);
//}
//
//template <class C>
//inline void trim(std::basic_string<C> &s) {
//
//	ltrim(s);
//	rtrim(s);
//}

}
