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
#include "EsapiCommon.h"
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

	public:
		Entry(const std::string&, const Y&);

		/**
		 * Convinence instantiator.
		 * @param key The key for the new instance
		 * @param keyLength The length of the key to use
		 * @param value The value for the new instance
		 * @return null if key or value is null
		 *	new Entry(key,value) if {@link CharSequence#length()} == keyLength
		 *	new Entry(key.subSequence(0,keyLength),value) otherwise
		 */
		static Entry<Y> newInstanceIfNeeded(const std::string&, size_t, const Y&);

		/**
		 * Convinence instantiator.
		 * @param key The key for the new instance
		 * @param value The value for the new instance
		 * @return null if key or value is null
		 *	new Entry(key,value) otherwise
		 */
		static Entry<Y> newInstanceIfNeeded(const std::string&, const Y&);

                /*************/
                /* std::pair */
                /*************/

		std::string getKey();

		Y getValue();

		Y setValue(const Y&);

                /********************/
                /* java.lang.Object */
                /********************/

		bool equals(const std::pair<std::string, Y>&) const;

		int hashCode() const;

		std::string toString() const;
	};

	/**
	 * Node inside the trie.
	 */
	template <typename U>
	class Node
	{
	private:
		U value;
		std::map<char, Node<U> > *nextMap;

		Node();

		/**
		 * Create a new Map for a node level. This is here so
		 * that if the underlying * Map implementation needs to
		 * be switched it is easily done.
		 * @return A new Map for use.
		 */
		static std::map<char, Node<U> > newNodeMap();

		/**
		 * Create a new Map for a node level. This is here so
		 * that if the underlying * Map implementation needs to
		 * be switched it is easily done.
		 * @param prev Previous map to use to populate the
		 * new map.
		 * @return A new Map for use.
		 */
		static std::map<char,Node<U> > newNodeMap(const std::map<char,Node<U> >&);

		/**
		 * Set the value for the key terminated at this node.
		 * @param value The value for this key.
		 */
		void setValue(const U&);

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
		U put(const std::string&, size_t, const U&);

		/**
		 * Recursively lookup a key's value.
		 * @param key The key being looked up.
		 * @param pos The position in the key that is being
		 *	looked up at this level.
		 * @return The value assocatied with the key or null if
		 *	none exists.
		 */
		U get(const std::string&, size_t);

		/**
		 * Recursively lookup the longest key match.
		 * @param key The key being looked up.
		 * @param pos The position in the key that is being
		 *	looked up at this level.
		 * @return The Entry assocatied with the longest key
		 *	match or null if none exists.
		 */
		Entry<U> getLongestMatch(const std::string&, size_t) const;

		/**
		 * Recursively lookup the longest key match.
		 * @param keyIn Where to read the key from
		 * @param pos The position in the key that is being
		 *	looked up at this level.
		 * @return The Entry assocatied with the longest key
		 *	match or null if none exists.
		 */
		Entry<U> getLongestMatch(const std::string&, const std::string&) const;

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
		bool containsValue(const U&) const;

		/**
		 * Recursively build values.
		 * @param values List being built.
		 * @return true if the value was found
		 *	false otherwise
		 */
		std::set<U> values(const std::set<U>&);

		/**
		 * Recursively build a key set.
		 * @param key StringBuilder with our key.
		 * @param keys Set to add to
		 * @return keys with additions
		 */
		std::set<std::string> keySet(const std::string&, const std::set<std::string>&);

		/**
		 * Recursively build a entry set.
		 * @param key StringBuilder with our key.
		 * @param entries Set to add to
		 * @return entries with additions
		 */
		std::map<std::string,U> entrySet(const std::string&, const std::set<std::pair<std::string,U> >&);
	};

	Node<T> root;
	size_t maxKeyLen;
	size_t trieSize;

public:
	HashTrie();

	/**
	 * Get the key value entry who's key is the longest prefix match.
	 * @param key The key to lookup
	 * @return Entry with the longest matching key.
	 */
	std::pair<std::string, T> getLongestMatch(const std::string&) const;

	/**
	 * Get the maximum key length.
	 * @return max key length.
	 */
	size_t getMaxKeyLength() const;


	/**
	 * Clear all entries.
	 */
	void clear();

	/** {@inheritDoc} */
	bool containsKey(const std::string&);

	/** {@inheritDoc} */
	bool containsValue(const T&) const;

	/**
	 * Add mapping.
	 * @param key The mapping's key.
	 * @value value The mapping's value
	 * @throws NullPointerException if key or value is null.
	 */
	T put(const std::string&, const T&) throw (NullPointerException);

	/**
	 * Remove a entry.
	 * @return previous value
	 * @throws UnsupportedOperationException always.
	 */
	T remove(const std::string&) throw (UnsupportedOperationException);

	/** {@inheritDoc} */
	void putAll(const std::map<std::string, T>&);

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
	size_t size();

	/** {@inheritDoc} */
	//bool equals(Object) const; TODO is this necessary?

	/** {@inheritDoc} */
	//int hashCode() const; TODO necessary?

	/** {@inheritDoc} */
	std::string toString() const;

	/** {@inheritDoc} */
	bool isEmpty() const;
};
}; // esapi namespace


// compiler does not allow template code in seperate cpp file

template <typename T>
template <typename Y>
esapi::HashTrie<T>::Entry<Y>::Entry(const std::string& key, const Y& value) {
	this->pair.first = key;
	this->pair.second = value;
}

template <typename T>
template <typename Y>
esapi::HashTrie<T>::Entry<Y> esapi::HashTrie<T>::Entry<Y>::newInstanceIfNeeded(const std::string& key, size_t keyLength, const Y& value) {
	if(value == NULL || (key.compare("")==0) )
		return NULL;
	if(key.size() > keyLength)
		key = key.substr(0,keyLength);
	return new Entry<Y>(key,value);
}

template <typename T>
template <typename Y>
esapi::HashTrie<T>::Entry<Y> esapi::HashTrie<T>::Entry<Y>::newInstanceIfNeeded(const std::string& key, const Y& value) {
	if(value == NULL || (key.compare("")==0) )
		return NULL;
	return new Entry<Y>(key,value);
}

template <typename T>
template <typename Y>
std::string esapi::HashTrie<T>::Entry<Y>::getKey() {
	return this->pair.first;
}

template <typename T>
template <typename Y>
Y esapi::HashTrie<T>::Entry<Y>::getValue() {
	return this->pair.second;
}

template <typename T>
template <typename Y>
Y esapi::HashTrie<T>::Entry<Y>::setValue(const Y&) {
	throw new UnsupportedOperationException("setValue(..) is not supported for HashTrie.");
}

template <typename T>
template <typename Y>
bool esapi::HashTrie<T>::Entry<Y>::equals(const std::pair<std::string,Y>& other) const {
	// TODO: should use NullSafe, but at this moment, it has not been ported yet.
	// ASSERT(other); // cannot be NULL since its a reference
	ASSERT(!(other.first.empty()));
	ASSERT(other.second);

	return ((this->pair.first.compare(other.first)==0) && (this->pair.second == other.second));
}

template <typename T>
template <typename Y>
int esapi::HashTrie<T>::Entry<Y>::hashCode() const {
	throw new UnsupportedOperationException("hashCode(..) is not supported for HashTrie.");
}

template <typename T>
template <typename Y>
std::string esapi::HashTrie<T>::Entry<Y>::toString() const {
	// TODO: should use NullSafe
	ASSERT(!this->pair.first->empty());
	ASSERT(this->pair.second);

	return this->pair.first << " => " << this->pair.second;
}

template <typename T>
template <typename U>
esapi::HashTrie<T>::Node<U>::Node() {this->nextMap = NULL;}


template <typename T>
template <typename U>
std::map<char, typename esapi::HashTrie<T>::template Node<U> > esapi::HashTrie<T>::Node<U>::newNodeMap() {
	throw new UnsupportedOperationException("working on it..."); //TODO
}


template <typename T>
template <typename U>
std::map<char, typename esapi::HashTrie<T>::template Node<U> > esapi::HashTrie<T>::Node<U>::newNodeMap(const std::map<char,Node<U> >&) {
	throw new UnsupportedOperationException("working on it..."); //TODO
}

template <typename T>
template <typename U>
void esapi::HashTrie<T>::Node<U>::setValue(const U&) {
	throw new UnsupportedOperationException("working on it..."); //TODO
}

template <typename T>
template <typename U>
esapi::HashTrie<T>::Node<U> esapi::HashTrie<T>::Node<U>::getNextNode(char) {
	throw new UnsupportedOperationException("working on it..."); //TODO
}

template <typename T>
template <typename U>
U esapi::HashTrie<T>::Node<U>::put(const std::string&, size_t, const U&) {
	throw new UnsupportedOperationException("working on it..."); //TODO
}

template <typename T>
template <typename U>
U esapi::HashTrie<T>::Node<U>::get(const std::string&, size_t) {
	throw new UnsupportedOperationException("working on it..."); //TODO
}

// TODO does not compile. fix.
/*
template <typename T>
template <typename Y>
template <typename U>
esapi::HashTrie<T>::Entry<Y> esapi::HashTrie<T>::Node<U>::getLongestMatch(std::string, int) {
	throw new UnsupportedOperationException("working on it..."); //TODO
}*/

/*
template <typename T>
template <typename Y>
template <typename U>
esapi::HashTrie<T>::Entry<Y> esapi::HashTrie<T>::Node<U>::getLongestMatch(std::string, std::string) {
	throw new UnsupportedOperationException("working on it..."); //TODO
}*/

template <typename T>
template <typename U>
void esapi::HashTrie<T>::Node<U>::remap() {
	throw new UnsupportedOperationException("working on it..."); //TODO
}

template <typename T>
template <typename U>
bool esapi::HashTrie<T>::Node<U>::containsValue(const U&) const {
	throw new UnsupportedOperationException("working on it..."); //TODO
}

template <typename T>
template <typename U>
std::set<U> esapi::HashTrie<T>::Node<U>::values(const std::set<U>&) {
	throw new UnsupportedOperationException("working on it..."); //TODO
}

template <typename T>
template <typename U>
std::set<std::string> esapi::HashTrie<T>::Node<U>::keySet(const std::string&, const std::set<std::string>&) {
	throw new UnsupportedOperationException("working on it..."); //TODO
}

template <typename T>
template <typename U>
std::map<std::string,U> esapi::HashTrie<T>::Node<U>::entrySet(const std::string&, const std::set<std::pair<std::string,U> >&) {
	throw new UnsupportedOperationException("working on it..."); //TODO
}
