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

#include "EsapiCommon.h"
#include "errors/UnsupportedOperationException.h"

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
    class Trie : std::map<std::string, T> {
  protected:
    Trie() : map() { }
    std::map<std::string,T> map;
  public:
    virtual std::pair<std::string,T> getLongestMatch(const std::string&) const;
    //pair<std::string,T> getLongestMatch(PushbackReader) =0;
    virtual size_t getMaxKeyLength() const;
    virtual size_t size() const;
    virtual ~Trie() {};

    template <typename Y>
      class TrieProxy : public Trie<Y> {
    private:
      Trie<Y> wrapped;

      TrieProxy(const Trie<Y> &);
      TrieProxy() : Trie<Y>(), wrapped() {};

    protected:
      virtual const Trie<T>& getWrapped();

    public:
      virtual std::pair<std::string,Y> getLongestMatch (const std::string&) const;

      virtual size_t getMaxKeyLength() const;

      virtual size_t size() const;

      virtual bool isEmpty() const;

      virtual bool containsKey(const std::string&) const;

      virtual bool containsValue(const Y&) const;

      virtual Y get(const std::string&);

      virtual Y put (const std::string&, const Y&);

      virtual Y remove(const std::string&);

      virtual void putAll(const std::map<std::string, Y>&);

      virtual void clear();

      virtual std::set<std::string> keySet();

      virtual std::set<Y> values();

      virtual std::map<std::string,Y> entrySet();

      /*virtual int hashCode();*/

      virtual ~TrieProxy() {};
    };

    template <typename U>
      class Unmodifiable : public TrieProxy<U> {
    public:
      Unmodifiable(const Trie<U> &);

      U put(std::string, U) throw (UnsupportedOperationException);
      U remove(std::string) throw (UnsupportedOperationException);
      void putAll(std::map<std::string,U>) throw (UnsupportedOperationException);
      void clear() throw (UnsupportedOperationException);
      std::set<std::string> keySet();
      std::set<U> values();
      std::set< std::pair<std::string,U> > entrySet();
    };

    template <typename V>
      class Util {
    private:
      Util() {};
    public:
      static Trie<T>* unmodifiable(const Trie<V> &);
    };

  };
}; // esapi namespace


// Silly compilers don't like separate files for templates.

template <typename T>
std::pair<std::string,T> esapi::Trie<T>::getLongestMatch(const std::string& key) const {
  return std::pair<std::string,T>(key, this->map.find(key)->second );
}

template <typename T>
size_t esapi::Trie<T>::getMaxKeyLength() const{
  return 0;
}

template <typename T>
size_t esapi::Trie<T>::size() const{
  return this->map.size();
}

template <typename T>
template <typename Y>
esapi::Trie<T>::TrieProxy<Y>::TrieProxy(const esapi::Trie<Y> & toWrap) {
  this->wrapped = toWrap;
}

template <typename T>
template <typename Y>
const esapi::Trie<T>& esapi::Trie<T>::TrieProxy<Y>::getWrapped() {
  return this->wrapped;
}

template <typename T>
template <typename Y>
std::pair<std::string,Y> esapi::Trie<T>::TrieProxy<Y>::getLongestMatch (const std::string& keyIn) const {
  return this->wrapped.getLongestMatch(keyIn);
}

template <typename T>
template <typename Y>
size_t esapi::Trie<T>::TrieProxy<Y>::getMaxKeyLength() const {
  return this->wrapped.getMaxKeyLength();
}

template <typename T>
template <typename Y>
size_t esapi::Trie<T>::TrieProxy<Y>::size() const {
  return this->wrapped.map.size();
}

template <typename T>
template <typename Y>
bool esapi::Trie<T>::TrieProxy<Y>::isEmpty() const {
  return this->wrapped.map.empty();
}

template <typename T>
template <typename Y>
bool esapi::Trie<T>::TrieProxy<Y>::containsKey(const std::string& key) const {
  if (this->wrapped.map.count(key)>0)
    return true;
  else
    return false;
}

template <typename T>
template <typename Y>
bool esapi::Trie<T>::TrieProxy<Y>::containsValue(const Y& val) const {
  typename std::map<std::string,Y>::const_iterator it;
  for ( it=this->wrapped.map.begin() ; it != this->wrapped.map.end(); it++ ) {
    if ( (*it).second == val)
      return true;
  }
  return false;
}

template <typename T>
template <typename Y>
Y esapi::Trie<T>::TrieProxy<Y>::get(const std::string& key) {
  typename std::map<std::string,Y>::iterator it = this->wrapped.map.find(key);

  if (it == this->wrapped.map.end())
    {
      // return NULL;
      // You might try and create a distinguished 'null Y' to return
      ASSERT(0);
      return Y();
    }

  return it->second;
}

template <typename T>
template <typename Y>
Y esapi::Trie<T>::TrieProxy<Y>::put (const std::string& key, const Y& value) {
  typename std::pair<std::string,Y> newElement(key,value);
  std::pair< typename std::map<std::string,Y>::iterator,bool > ret;

  ret=this->wrapped.map.insert(newElement);

  if (ret.second==false) {
    // return previous existing value
    return ret.first->second;
  }

  // return NULL;
  // You might try and create a distinguished 'null Y' to return
  ASSERT(0);
  return Y();
}

template <typename T>
template <typename Y>
Y esapi::Trie<T>::TrieProxy<Y>::remove(const std::string& key) {
  typename std::map<std::string,Y>::iterator it = this->wrapped.map.find(key);

  if (it == this->wrapped.map.end()) {
    // return NULL;
    // You might try and create a distinguished 'null Y' to return
    ASSERT(0);
    return Y();
  }

  Y val = it->second;
  this->wrapped.map.erase(it);
  return val;
}

template <typename T>
template <typename Y>
void esapi::Trie<T>::TrieProxy<Y>::putAll(const std::map<std::string, Y>& t) {
  this->wrapped.map.insert(t.begin(),t.end());
}

template <typename T>
template <typename Y>
void esapi::Trie<T>::TrieProxy<Y>::clear() {
  this->wrapped.map.clear();
}

template <typename T>
template <typename Y>
std::set<std::string> esapi::Trie<T>::TrieProxy<Y>::keySet() {
  std::set<std::string> keys;
  typename std::map<std::string,Y>::iterator it;

  for (it=this->wrapped.map.begin(); it != this->wrapped.map.end(); it++)
    keys.insert(it->first);

  return keys;
}

template <typename T>
template <typename Y>
std::set<Y> esapi::Trie<T>::TrieProxy<Y>::values() {
  std::set<Y> keys;
  typename std::map<std::string,Y>::iterator it;

  for (it=this->wrapped.map.begin(); it != this->wrapped.map.end(); it++)
    keys.insert(it->second);

  return keys;
}

template <typename T>
template <typename Y>
std::map<std::string,Y> esapi::Trie<T>::TrieProxy<Y>::entrySet() {
  return this->wrapped.map;
}

/*
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
esapi::Trie<T>* esapi::Trie<T>::Util<V>::unmodifiable(const Trie<V> & toWrap){
  return new Unmodifiable<V>(toWrap);
}