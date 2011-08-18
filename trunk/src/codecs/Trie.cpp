/**
* OWASP Enterprise Security API (ESAPI)
*
* This file is part of the Open Web Application Security Project (OWASP)
* Enterprise Security API (ESAPI) project. For details, please see
* http://www.owasp.org/index.php/ESAPI.
*
* Copyright (c) 2011 - The OWASP Foundation
*/

#include "codecs/Trie.h"
#include <map>

template <typename T>
template <typename Y>
esapi::Trie<T>::TrieProxy<Y>::TrieProxy(const Trie<Y> & toWrap) {
	this->wrapped = toWrap;
}

template <typename T>
template <typename Y>
const esapi::Trie<Y>& esapi::Trie<T>::TrieProxy<Y>::getWrapped() {
	return this->wrapped;
}

template <typename T>
template <typename Y>
std::pair<std::string,Y> esapi::Trie<T>::TrieProxy<Y>::getLongestMatch (std::string) {

}

template <typename T>
template <typename Y>
int esapi::Trie<T>::TrieProxy<Y>::getMaxKeyLength() {
	return this->wrapped.getMaxKeyLength();
}

template <typename T>
template <typename Y>
int esapi::Trie<T>::TrieProxy<Y>::size() {
	return this->wrapped.size();
}

template <typename T>
template <typename Y>
bool esapi::Trie<T>::TrieProxy<Y>::isEmpty() {
	return this->wrapped.empty();
}

template <typename T>
template <typename Y>
bool esapi::Trie<T>::TrieProxy<Y>::containsKey(std::string key) {
	if (this->wrapped.count(key)>0)
		return true;
	else
		return false;
}

template <typename T>
template <typename Y>
bool esapi::Trie<T>::TrieProxy<Y>::containsValue(Y val) {
	typename std::map<std::string,Y>::iterator it;
	for ( it=this->wrapped.begin() ; it != this->wrapped.end(); it++ ) {
		if ( (*it).second == val)
			return true;
	}
	return false;
}

template <typename T>
template <typename Y>
Y esapi::Trie<T>::TrieProxy<Y>::get(std::string key) {
	typename std::map<std::string,Y>::iterator it = this->wrapped.find(key);

	if (it == this->wrapped.end())
		return 0;
	else
		return it.second;
}

template <typename T>
template <typename Y>
Y esapi::Trie<T>::TrieProxy<Y>::put (std::string key, Y value) {
	typename std::pair<std::string,Y> newElement(key,value);
	std::pair< typename std::map<std::string,Y>::iterator,bool > ret;

	ret=this->wrapped.insert(newElement);

	if (ret.second==false) {
		// return previous existing value
		ret.first->second;
	} else {
		return NULL;
	}
}

template <typename T>
template <typename Y>
Y esapi::Trie<T>::TrieProxy<Y>::remove(std::string key) {
	typename std::map<std::string,Y>::iterator it = this->wrapped.find(key);

	if (it == this->wrapped.end()) {
		return NULL;
	} else {
		Y val = it.second;
		this->wrapped.erase(it);
		return val;
	}
}

template <typename T>
template <typename Y>
void esapi::Trie<T>::TrieProxy<Y>::putAll(std::map<std::string, Y> t) {
	this->wrapped.insert(t.begin(),t.end());
}

template <typename T>
template <typename Y>
void esapi::Trie<T>::TrieProxy<Y>::clear() {
	this->wrapped.clear();
}

/*template <typename T>
template <typename Y>
std::set<std::string> esapi::Trie<T>::TrieProxy<Y>::keySet() {

}

template <typename T>
template <typename Y>
std::set<Y> esapi::Trie<T>::TrieProxy<Y>::values() {

}

template <typename T>
template <typename Y>
std::set< std::pair<std::string,Y> > esapi::Trie<T>::TrieProxy<Y>::entrySet() {

}

template <typename T>
template <typename Y>
int esapi::Trie<T>::TrieProxy<Y>::hashCode() {

}*/

template <typename T>
template <typename U>
esapi::Trie<T>::Unmodifiable<U>::Unmodifiable(const Trie<U> & toWrap) : TrieProxy<U>(toWrap){}

template <typename T>
template <typename U>
U esapi::Trie<T>::Unmodifiable<U>::put(std::string, U) throw (esapi::UnsupportedOperationException) {
	throw UnsupportedOperationException("put(..) is unsupported for Unmodifiable Trie.");
}

template <typename T>
template <typename U>
U esapi::Trie<T>::Unmodifiable<U>::remove(std::string) throw (esapi::UnsupportedOperationException) {
	throw UnsupportedOperationException("remove(..) is unsupported for Unmodifiable Trie.");
}

template <typename T>
template <typename U>
void esapi::Trie<T>::Unmodifiable<U>::putAll(std::map<std::string,U>) throw (esapi::UnsupportedOperationException) {
	throw UnsupportedOperationException("putAll(..) is unsupported for Unmodifiable Trie.");
}

template <typename T>
template <typename U>
void esapi::Trie<T>::Unmodifiable<U>::clear() throw (esapi::UnsupportedOperationException) {
	throw UnsupportedOperationException("clear() is unsupported for Unmodifiable Trie.");
}

/*
template <typename T>
template <typename U>
std::set<std::string> esapi::Trie<T>::Unmodifiable<U>::keySet() {

}

template <typename T>
template <typename U>
std::set<U> esapi::Trie<T>::Unmodifiable<U>::values() {

}

template <typename T>
template <typename U>
std::set< std::pair<std::string,U> > esapi::Trie<T>::Unmodifiable<U>::entrySet() {

}*/

template <typename T>
template <typename V>
esapi::Trie<V>* esapi::Trie<T>::Util<V>::unmodifiable(const Trie<V> & toWrap){
	return new Unmodifiable<V>(toWrap);
}
