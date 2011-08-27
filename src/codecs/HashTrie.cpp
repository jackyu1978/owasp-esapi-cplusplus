/**
* OWASP Enterprise Security API (ESAPI)
*
* This file is part of the Open Web Application Security Project (OWASP)
* Enterprise Security API (ESAPI) project. For details, please see
* http://www.owasp.org/index.php/ESAPI.
*
* Copyright (c) 2011 - The OWASP Foundation
*/

#include "codecs/HashTrie.h"

// compiler does not allow template code in seperate cpp file

namespace esapi
{
  template <typename T>
  template <typename Y>
  HashTrie<T>::Entry<Y>::Entry(const std::string& key, const Y& value){
    this->pair.first = key;
    this->pair.second = value;
  }

  template <typename T>
  template <typename Y>
  typename HashTrie<T>::Entry<Y>
    HashTrie<T>::Entry<Y>::newInstanceIfNeeded(const std::string& key, size_t keyLength, const Y& value){
      if(value == NULL || (key.compare("")==0) )
        return NULL;
      if(key.size() > keyLength)
        key = key.substr(0,keyLength);
      return new Entry<Y>(key,value);
  }

  template <typename T>
  template <typename Y>
  typename HashTrie<T>::Entry<Y>
    HashTrie<T>::Entry<Y>::newInstanceIfNeeded(const std::string& key, const Y& value){
      if(value == NULL || (key.compare("")==0) )
        return NULL;
      return new Entry<Y>(key,value);
  }

  template <typename T>
  template <typename Y>
  std::string HashTrie<T>::Entry<Y>::getKey(){
    return this->pair.first;
  }

  template <typename T>
  template <typename Y>
  Y HashTrie<T>::Entry<Y>::getValue(){
    return this->pair.second;
  }

  template <typename T>
  template <typename Y>
  Y HashTrie<T>::Entry<Y>::setValue(const Y&){
    throw new UnsupportedOperationException("setValue(..) is not supported for HashTrie.");
  }

  template <typename T>
  template <typename Y>
  bool HashTrie<T>::Entry<Y>::equals(const std::pair<std::string,Y>& other) const{
    // TODO: should use NullSafe, but at this moment, it has not been ported yet.
    // ASSERT(other); // cannot be NULL since its a reference
    ASSERT(!(other.first.empty()));
    ASSERT(other.second);

    return ((this->pair.first.compare(other.first)==0) && (this->pair.second == other.second));
  }

  template <typename T>
  template <typename Y>
  int HashTrie<T>::Entry<Y>::hashCode() const{
    throw new UnsupportedOperationException("hashCode(..) is not supported for HashTrie.");
  }

  template <typename T>
  template <typename Y>
  std::string HashTrie<T>::Entry<Y>::toString() const{
    // TODO: should use NullSafe
    ASSERT(!this->pair.first->empty());
    ASSERT(this->pair.second);

    return this->pair.first << " => " << this->pair.second;
  }

  template <typename T>
  template <typename U>
  HashTrie<T>::Node<U>::Node(){this->nextMap = NULL;}


  template <typename T>
  template <typename U>
  std::map<char, typename HashTrie<T>::Node<U> > HashTrie<T>::Node<U>::newNodeMap(){
    throw new UnsupportedOperationException("working on it..."); //TODO
  }


  template <typename T>
  template <typename U>
  std::map<char, typename HashTrie<T>::Node<U> > HashTrie<T>::Node<U>::newNodeMap(const std::map<char,Node<U> >&){
    throw new UnsupportedOperationException("working on it..."); //TODO
  }

  template <typename T>
  template <typename U>
  void HashTrie<T>::Node<U>::setValue(const U&){
    throw new UnsupportedOperationException("working on it..."); //TODO
  }

  template <typename T>
  template <typename U>
  typename HashTrie<T>::Node<U> HashTrie<T>::Node<U>::getNextNode(char){
    throw new UnsupportedOperationException("working on it..."); //TODO
  }

  template <typename T>
  template <typename U>
  U HashTrie<T>::Node<U>::put(const std::string&, size_t, const U&){
    throw new UnsupportedOperationException("working on it..."); //TODO
  }

  template <typename T>
  template <typename U>
  U HashTrie<T>::Node<U>::get(const std::string&, size_t){
    throw new UnsupportedOperationException("working on it..."); //TODO
  }

  // TODO does not compile. fix.
  /*
  template <typename T>
  template <typename Y>
  template <typename U>
  HashTrie<T>::Entry<Y> HashTrie<T>::Node<U>::getLongestMatch(const std::string&, size_t) {
  throw new UnsupportedOperationException("working on it..."); //TODO
  }*/

  /*
  template <typename T>
  template <typename Y>
  template <typename U>
  HashTrie<T>::Entry<Y> HashTrie<T>::Node<U>::getLongestMatch(const std::string&, const std::string&) {
  throw new UnsupportedOperationException("working on it..."); //TODO
  }*/

  template <typename T>
  template <typename U>
  void HashTrie<T>::Node<U>::remap(){
    throw new UnsupportedOperationException("working on it..."); //TODO
  }

  template <typename T>
  template <typename U>
  bool HashTrie<T>::Node<U>::containsValue(const U&) const{
    throw new UnsupportedOperationException("working on it..."); //TODO
  }

  template <typename T>
  template <typename U>
  std::set<U> HashTrie<T>::Node<U>::values(const std::set<U>&){
    throw new UnsupportedOperationException("working on it..."); //TODO
  }

  template <typename T>
  template <typename U>
  std::set<std::string> HashTrie<T>::Node<U>::keySet(const std::string&, const std::set<std::string>&){
    throw new UnsupportedOperationException("working on it..."); //TODO
  }

  template <typename T>
  template <typename U>
  std::map<std::string,U> HashTrie<T>::Node<U>::entrySet(const std::string&, const std::set<std::pair<std::string,U> >&){
    throw new UnsupportedOperationException("working on it..."); //TODO
  }

}; // esapi namespace