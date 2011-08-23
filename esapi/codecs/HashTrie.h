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

#include "codecs/Trie.h"
#include "errors/NullPointerException.h"
#include "errors/UnsupportedOperationException.h"

#include <map>
#include <set>
#include <string>

namespace esapi {
/**
 * Trie implementation for CharSequence keys. This uses HashMaps for each
 * level instead of the traditional array. This is done as with unicode,
 * each level's array would be 64k entries.
 *
 * <b>NOTE:</b><br>
 * <ul>
 *	<li>{@link Map.remove(Object)} is not supported.</li>
 *	<li>
 *		If deletion support is added the max key length will
 *		need work or removal.
 *	</li>
 *	<li>Null values are not supported.</li>
 * </ul>
 *
 * @author Ed Schaller
 * @author Dan Amodio (dan.amodio@aspectsecurity.com)
 */
template <typename T>
class HashTrie : esapi::Trie<T>
{
private:

	template <typename Y>
	class Entry
	{
	private:
		std::pair<std::string,Y> pair;
		std::string key;
		Y value;

	public:
		Entry(std::string, Y);

		/**
		 * Convinence instantiator.
		 * @param key The key for the new instance
		 * @param keyLength The length of the key to use
		 * @param value The value for the new instance
		 * @return null if key or value is null
		 *	new Entry(key,value) if {@link CharSequence#length()} == keyLength
		 *	new Entry(key.subSequence(0,keyLength),value) otherwise
		 */
		static Entry<T> newInstanceIfNeeded(std::string, int, T);

		/**
		 * Convinence instantiator.
		 * @param key The key for the new instance
		 * @param value The value for the new instance
		 * @return null if key or value is null
		 *	new Entry(key,value) otherwise
		 */
		static Entry<T> newInstanceIfNeeded(std::string, T);

                /*************/
                /* std::pair */
                /*************/

		std::string getKey();

		T getValue();

		T setValue(T);

                /********************/
                /* java.lang.Object */
                /********************/

		bool equals(std::pair<std::string,Y>); // TODO overload equals operator?

		int hashCode();

		std::string toString();
	};

	/**
	 * Node inside the trie.
	 */
	template <typename U>
	class Node
	{
	private:
		U value;
		std::map<char,Node<U> > nextMap;

		/**
		 * Create a new Map for a node level. This is here so
		 * that if the underlying * Map implementation needs to
		 * be switched it is easily done.
		 * @return A new Map for use.
		 */
		static std::map<char,Node<U> > newNodeMap();

		/**
		 * Create a new Map for a node level. This is here so
		 * that if the underlying * Map implementation needs to
		 * be switched it is easily done.
		 * @param prev Previous map to use to populate the
		 * new map.
		 * @return A new Map for use.
		 */
		static std::map<char,Node<U> > newNodeMap(std::map<char,Node<U> >);

		/**
		 * Set the value for the key terminated at this node.
		 * @param value The value for this key.
		 */
		void setValue(U);

		/**
		 * Get the node for the specified character.
		 * @param ch The next character to look for.
		 * @return The node requested or null if it is not
		 *	present.
		 */
		Node<U> getNextNode(char);

		/**
		 * Recursively add a key.
		 * @param key The key being added.
		 * @param pos The position in key that is being handled
		 *	at this level.
		 */
		U put(std::string, int, U);

		/**
		 * Recursively lookup a key's value.
		 * @param key The key being looked up.
		 * @param pos The position in the key that is being
		 *	looked up at this level.
		 * @return The value assocatied with the key or null if
		 *	none exists.
		 */
		U get(std::string, int);

		/**
		 * Recursively lookup the longest key match.
		 * @param key The key being looked up.
		 * @param pos The position in the key that is being
		 *	looked up at this level.
		 * @return The Entry assocatied with the longest key
		 *	match or null if none exists.
		 */
		Entry<U> getLongestMatch(std::string, int);

		/**
		 * Recursively lookup the longest key match.
		 * @param keyIn Where to read the key from
		 * @param pos The position in the key that is being
		 *	looked up at this level.
		 * @return The Entry assocatied with the longest key
		 *	match or null if none exists.
		 */
		Entry<U> getLongestMatch(std::string, std::string);

		/**
		 * Recursively rebuild the internal maps.
		 */
		void remap();

		/**
		 * Recursively search for a value.
		 * @param toFind The value to search for
		 * @return true if the value was found
		 *	false otherwise
		 */
		bool containsValue(U);

		/**
		 * Recursively build values.
		 * @param values List being built.
		 * @return true if the value was found
		 *	false otherwise
		 */
		std::set<U> values(std::set<U>);

		/**
		 * Recursively build a key set.
		 * @param key StringBuilder with our key.
		 * @param keys Set to add to
		 * @return keys with additions
		 */
		std::set<std::string> keySet(std::string, std::set<std::string>);

		/**
		 * Recursively build a entry set.
		 * @param key StringBuilder with our key.
		 * @param entries Set to add to
		 * @return entries with additions
		 */
		std::set<std::pair<std::string,U> > entrySet(std::string, std::set<std::pair<std::string,U> >);
	};

	Node<T> root;
	int maxKeyLen;
	int trieSize;

public:
	HashTrie();

	/**
	 * Get the key value entry who's key is the longest prefix match.
	 * @param key The key to lookup
	 * @return Entry with the longest matching key.
	 */
	std::pair<std::string, T> getLongestMatch(std::string);

	/**
	 * Get the maximum key length.
	 * @return max key length.
	 */
	int getMaxKeyLength();


	/**
	 * Clear all entries.
	 */
	void clear();

	/** {@inheritDoc} */
	bool containsKey(std::string);

	/** {@inheritDoc} */
	bool containsValue(T);

	/**
	 * Add mapping.
	 * @param key The mapping's key.
	 * @value value The mapping's value
	 * @throws NullPointerException if key or value is null.
	 */
	T put(std::string, T) throw (NullPointerException);

	/**
	 * Remove a entry.
	 * @return previous value
	 * @throws UnsupportedOperationException always.
	 */
	T remove(std::string) throw (UnsupportedOperationException);

	/** {@inheritDoc} */
	void putAll(std::map<std::string, T>);

	/** {@inheritDoc} */
	std::set<std::string> keySet();

	/** {@inheritDoc} */
	std::set<T> values();

	/** {@inheritDoc} */
	std::set< std::pair<std::string,T> > entrySet();

	/**
	 * Get the value for a key.
	 * @param key The key to look up.
	 * @return The value for key or null if the key is not found.
	 */
	T get(std::string);

	/**
	 * Get the number of entries.
	 * @return the number or entries.
	 */
	int size();

	/** {@inheritDoc} */
	//bool equals(Object); TODO is this necessary?

	/** {@inheritDoc} */
	//int hashCode(); TODO necessary?

	/** {@inheritDoc} */
	std::string toString();

	/** {@inheritDoc} */
	bool isEmpty();
};
}; // esapi namespace
