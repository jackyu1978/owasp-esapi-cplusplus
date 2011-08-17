/**
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2007 - The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 *
 * @author Jeff Williams <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @created 2007
 */

#pragma once

#include <map>
#include <string>
#include <set>

namespace esapi {
/*
 * Trie implementation
 *
 * @author Jeff Williams <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @author Dan Amodio (dan.amodio@aspectsecurity.com)
 */
template <typename T>
class Trie {
private:
	std::map<std::string,T> map;
public:
	std::pair<std::string,T> getLongestMatch(std::string);
	//pair<std::string,T> getLongestMatch(PushbackReader) =0;
	int getMaxKeyLength();

	template <typename Y>
	class TrieProxy : Trie<Y> {
		private:
			Trie<Y> wrapped;

			TrieProxy(Trie<Y>);

		protected:
			Trie<Y> getWrapped();

		public:
			std::pair<std::string,Y> getLongestMatch (std::string);

			int getMaxKeyLength();

			int size();

			bool isEmpty();

			bool containsKey(std::string);

			bool containsValue(Y);

			Y get(std::string);

			Y put (std::string, Y);

			Y remove(std::string);

			void putAll(std::map<std::string, Y>);

			void clear();

			std::set<std::string> keySet();

			std::set<Y> values();

			std::set< std::pair<std::string,Y> > entrySet();

			int hashCode();
	};

	template <typename U>
	class Unmodifiable : TrieProxy<U> {
	public:
		Unmodifiable(Trie<U> toWrap);

		U put(std::string, U);
		U remove(std::string);
		void putAll(std::map<std::string,U>);
		void clear();
		std::set<std::string> keySet();
		std::set<U> values();
		std::set< std::pair<std::string,U> > entrySet();
	};

	template <typename V>
	class Util {
	private:
		Util() {};
	public:
		static Trie<V> unmodifiable(Trie<V>);
	};

};
}; // esapi namespace
