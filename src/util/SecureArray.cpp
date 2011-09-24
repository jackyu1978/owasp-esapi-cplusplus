/**
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * http://www.owasp.org/index.php/ESAPI.
 *
 * Copyright (c) 2011 - The OWASP Foundation
 *
 * @author Kevin Wall, kevin.w.wall@gmail.com
 * @author Jeffrey Walton, noloader@gmail.com
 *
 */

#include "util/SecureArray.h"
#include "errors/EncryptionException.h"
#include "errors/InvalidArgumentException.h"

#include "safeint/SafeInt3.hpp"

namespace esapi
{
  // Construction
  template <typename T>
  SecureArray<T>::SecureArray(size_type n, const T t)
    : m_vector(new SecureVector)
  {
    ESAPI_ASSERT2(n <= max_size(), "Too many elements in the array");
    // Allocator will throw below

    boost::shared_ptr<SecureVector> temp(new SecureVector(n,t));
    ASSERT(temp.get());
    if(!temp.get())
      throw std::bad_alloc();

    m_vector.swap(temp);
    ASSERT(nullptr != m_vector.get());
  }

  template <typename T>
  SecureArray<T>::SecureArray(const T* ptr, size_t cnt)
    : m_vector(new SecureVector)
  {
    ESAPI_ASSERT2(ptr, "Array pointer is not valid");
    if(ptr == nullptr)
      throw InvalidArgumentException("Array pointer is not valid");

    ESAPI_ASSERT2(cnt, "Array size is 0"); // Warning only
    ESAPI_ASSERT2(cnt <= max_size(), "Too many elements in the array");
    // Allocator will throw below

    // Not sure what the conatiner does here...
    ESAPI_ASSERT2((size_t)ptr % sizeof(T) == 0, "Array pointer slices elements");
    //if((size_t)ptr % sizeof(T) != 0)
    //  throw InvalidArgumentException("Pointer slices elements");

    // Check for wrap
    SafeInt<size_t> si(cnt);
    try {
      si *= sizeof(T);
      si += (size_t)ptr;
    }
    catch(SafeIntException&) {
      throw std::bad_alloc();
    }

    const T* last = (const T*)(size_t)si;
    boost::shared_ptr<SecureVector> temp(new SecureVector(ptr /*first*/, last));
    ASSERT(temp.get());
    if(!temp.get())
      throw std::bad_alloc();

    ASSERT(temp->size() == cnt);
    m_vector.swap(temp);
    ASSERT(nullptr != m_vector.get());
  }

  template <typename T>
  template <class InputIterator>
  SecureArray<T>::SecureArray(InputIterator first, InputIterator last)
    : m_vector(new SecureVector)
  {
    ASSERT(first);
    if(!first)
      throw InvalidArgumentException("Bad first input iterator");

    ASSERT(first >= last);
    if(!(first >= last))
      throw InvalidArgumentException("Bad input iterators");

    // Not sure what the conatiner does here....
    ESAPI_ASSERT2(first % sizeof(T) == 0, "InputIterator first slices elements");
    ESAPI_ASSERT2(last % sizeof(T) == 0, "InputIterator last slices elements");
    //if((first % sizeof(T) != 0) || (last % sizeof(T) != 0))
    //  throw InvalidArgumentException("InputIterator slices elements");

    // Check for wrap
    SafeInt<size_t> si((size_t)last);
    try {
      si += sizeof(T);
    }
    catch(SafeIntException&) {
      throw std::length_error("Bad input iterators");
    }

    boost::shared_ptr<SecureVector> temp(new SecureVector(first,last));
    ASSERT(temp.get());
    if(!temp.get())
      throw std::bad_alloc();

    m_vector.swap(temp);
    ASSERT(nullptr != m_vector.get());
  }

  // Iterators
  template <typename T>
  typename SecureArray<T>::iterator
  SecureArray<T>::begin()
  {
    ASSERT(m_vector.get());
    return m_vector->begin();
  }

  template <typename T>
  typename SecureArray<T>::const_iterator
  SecureArray<T>::begin() const
  {
    ASSERT(m_vector.get());
    return m_vector->begin();
  }

  template <typename T>
  typename SecureArray<T>::iterator
  SecureArray<T>::end()
  {
    ASSERT(m_vector.get());
    return m_vector->end();
  }

  template <typename T>
  typename SecureArray<T>::const_iterator
  SecureArray<T>::end() const
  {
    ASSERT(m_vector.get());
    return m_vector->end();
  }

  template <typename T>
  typename SecureArray<T>::reference
  SecureArray<T>::front()
  {
    ASSERT(m_vector.get());
    return m_vector->front();
  }

  template <typename T>
  typename SecureArray<T>::const_reference
  SecureArray<T>::front() const
  {
    ASSERT(m_vector.get());
    return m_vector->front();
  }

  template <typename T>
  typename SecureArray<T>::reference
  SecureArray<T>::back()
  {
    ASSERT(m_vector.get());
    return m_vector->back();
  }

  template <typename T>
  typename SecureArray<T>::const_reference
  SecureArray<T>::back() const
  {
    ASSERT(m_vector.get());
    return m_vector->back();
  }

  template <typename T>
  typename SecureArray<T>::reverse_iterator
  SecureArray<T>::rbegin()
  {
    ASSERT(m_vector.get());
    return m_vector->rbegin();
  }

  template <typename T>
  typename SecureArray<T>::const_reverse_iterator
  SecureArray<T>::rbegin() const
  {
    ASSERT(m_vector.get());
    return m_vector->rbegin();
  }

  template <typename T>
  typename SecureArray<T>::reverse_iterator
  SecureArray<T>::rend()
  {
    ASSERT(m_vector.get());
    return m_vector->rend();
  }

  template <typename T>
  typename SecureArray<T>::const_reverse_iterator
  SecureArray<T>::rend() const
  {
    ASSERT(m_vector.get());
    return m_vector->rend();
  }

  // Copy and assignment
  template <typename T>
  SecureArray<T>::SecureArray(const SecureArray& sa)
    : m_vector(sa.m_vector)
  {
    ASSERT(m_vector.get());
  }

  template <typename T>
  SecureArray<T>& SecureArray<T>::operator=(const SecureArray<T>& sa)
  {
    if(this != &sa)
      {
        m_vector = sa.m_vector;
      }
    ASSERT(m_vector.get());
    return *this;
  }

  // Size and capacity
  template <typename T>
  typename SecureArray<T>::size_type
  SecureArray<T>::max_size() const
  {
    ASSERT(m_vector.get());
    return m_vector->max_size();
  }

  template <typename T>
  size_t SecureArray<T>::capacity() const
  {
    ASSERT(m_vector.get());
    return m_vector->capacity();
  }

  template <typename T>
  void SecureArray<T>::reserve(size_t cnt)
  {
    ASSERT(m_vector.get());
    m_vector->reserve(cnt);
  }

  template <typename T>
  bool SecureArray<T>::empty() const
  {
    ASSERT(m_vector.get());
    return m_vector->empty();
  }

  template <typename T>
  typename SecureArray<T>::size_type
  SecureArray<T>::size() const
  {
    ASSERT(m_vector.get());
    return m_vector->size();
  }

  template <typename T>
  typename SecureArray<T>::size_type
  SecureArray<T>::length() const
  {
    ASSERT(m_vector.get());
    return m_vector->size();
  }

  template <typename T>
  void SecureArray<T>::resize(size_type n, T t)
  {
    ASSERT(m_vector.get());
    m_vector->resize(n, t);
  }

  template <typename T>
  void SecureArray<T>::clear()
  {
    ASSERT(m_vector.get());
    return m_vector->clear();
  }

  // Member functions
  template <typename T>
  const T& SecureArray<T>::operator[](size_t pos) const
  {
    ASSERT(m_vector.get());
    return m_vector->operator[](pos);
  }

  template <typename T>
  T& SecureArray<T>::operator[](size_t pos)
  {
    ASSERT(m_vector.get());
    return m_vector->operator[](pos);
  }

  template <typename T>
  const T& SecureArray<T>::at(size_t pos) const
  {
    ASSERT(m_vector.get());
    return m_vector->at(pos);
  }

  template <typename T>
  T& SecureArray<T>::at(size_t pos)
  {
    ASSERT(m_vector.get());
    return m_vector->at(pos);
  }

  // Value added
  template <typename T>
  T* SecureArray<T>::data()
  {
    return (m_vector->size() ? &(m_vector->operator[](0)) : nullptr);
  }

  // Value added
  template <typename T>
  const T* SecureArray<T>::data() const
  {
    return (m_vector->size() ? &(m_vector->operator[](0)) : nullptr);
  }

  template <typename T>
  void SecureArray<T>::assign(size_type n, const T& u)
  {
    ASSERT(n <= max_size());

    ASSERT(m_vector.get());
    m_vector->assign(n, u);
  }

  template <typename T>
  void SecureArray<T>::assign(const T* ptr, size_t cnt)
  {
    ESAPI_ASSERT2(ptr, "Array pointer is not valid");
    if(ptr == nullptr)
      throw InvalidArgumentException("Array pointer is not valid");

    ESAPI_ASSERT2(cnt, "Array size is 0"); // Warning only
    ESAPI_ASSERT2(cnt <= max_size(), "Too many elements in the array");
    // Allocator will throw below

    // Not sure what the conatiner does here...
    ESAPI_ASSERT2((size_t)ptr % sizeof(T) == 0, "Array pointer slices elements");
    //if((size_t)ptr % sizeof(T) != 0)
    //  throw InvalidArgumentException("Pointer slices elements");

    // Check for wrap
    SafeInt<size_t> si(cnt);
    try {
      si *= sizeof(T);
      si += (size_t)ptr;
    }
    catch(SafeIntException&) {
      throw std::length_error("Too many elements in the array");
    }

    ASSERT(m_vector.get());
    const T* last = (const T*)(size_t)si;
    m_vector->assign(ptr /*first*/, last);
  }

  template <typename T>
  template <class InputIterator>
  void SecureArray<T>::assign(InputIterator first, InputIterator last)
  {
    ESAPI_ASSERT2(first, "Bad first input iterator");
    ESAPI_ASSERT2(first >= last, "Input iterators are not valid");
    if(!(first >= last))
      throw std::length_error(L"Input iterators are not valid");

    // Not sure what the conatiner does here....
    ESAPI_ASSERT2(first % sizeof(T) == 0, "InputIterator first slices elements");
    ESAPI_ASSERT2(last % sizeof(T) == 0, "InputIterator last slices elements");
    
    ASSERT(m_vector.get());
    return m_vector->assign(first, last);
  }

  template <typename T>
  typename SecureArray<T>::iterator
  SecureArray<T>::insert(iterator pos, const T& x)
  {
    ASSERT(m_vector.get());
    return m_vector->insert(pos, x);
  }

  template <typename T>
  void SecureArray<T>::insert(iterator pos, size_type n, const T& x)
  {
    ESAPI_ASSERT2(n, "Insertion size is 0"); // Warning only
    ESAPI_ASSERT2(n <= max_size(), "Too many elements in the array");
    ESAPI_ASSERT2(n <= max_size() - size(), "Too many elements in the resulting array");

    // Test resulting size, throw on overflow
    SafeInt<size_t> si(n);
    try {   
      si += size();
      si *= sizeof(T);
    }
    catch(SafeIntException&) {
      throw std::bad_alloc();
    }

    ASSERT(m_vector.get());
    m_vector->insert(pos, n, x);
  }

  template <typename T>
  void SecureArray<T>::insert(iterator pos, const T* ptr, size_t cnt)
  {
    ESAPI_ASSERT2(ptr, "Array pointer is not valid");
    if(ptr == nullptr)
      throw InvalidArgumentException("Array pointer is not valid");

    ESAPI_ASSERT2(cnt, "Array size is 0"); // Warning only
    ESAPI_ASSERT2(cnt <= max_size(), "Too many elements in the array");
    ESAPI_ASSERT2(cnt <= max_size() - size(), "Too many elements in the resulting array");

    // Not sure what the conatiner does here...
    ESAPI_ASSERT2((size_t)ptr % sizeof(T) == 0, "Array pointer slices elements");
    //if((size_t)ptr % sizeof(T) != 0)
    //  throw InvalidArgumentException("Pointer slices elements");

    // Check for wrap on the pointer
    SafeInt<size_t> si(cnt);
    try {
      si *= sizeof(T);
      si += (size_t)ptr;
    }
    catch(SafeIntException&) {
      throw std::bad_alloc();
    }

    // Check for wrap on the resulting array
    try
    {
      SafeInt<size_t> sj(cnt);
      sj += size();
      sj *= sizeof(T);
    }
    catch(SafeIntException&) {
      throw std::bad_alloc();
    }

    const T* last = (const T*)(size_t)si;
    ASSERT(m_vector.get());
    m_vector->insert(pos, ptr /*first*/, last);
  }

  template <typename T>
  template <class InputIterator>
  void SecureArray<T>::insert(iterator pos, InputIterator first, InputIterator last)
  {
    ESAPI_ASSERT2(first, "Bad first input iterator");
    ESAPI_ASSERT2(first >= last, "Input iterators are not valid");
    if(!(first >= last))
      throw std::length_error(L"Input iterators are not valid");

    // Not sure what the conatiner does here....
    ESAPI_ASSERT2(first % sizeof(T) == 0, "InputIterator first slices elements");
    ESAPI_ASSERT2(last % sizeof(T) == 0, "InputIterator last slices elements");
    //if((size_t)first % sizeof(T) != 0 || (size_t)last % sizeof(T) != 0)
    //  throw InvalidArgumentException("Pointer slices elements");
    
    ASSERT(m_vector.get());
    m_vector->insert(pos, first, last);
  }

  template <typename T>
  typename SecureArray<T>::iterator
  SecureArray<T>::erase(iterator pos)
  {
    ASSERT(m_vector.get());
    return m_vector->erase(pos);
  }

  template <typename T>
  typename SecureArray<T>::iterator
  SecureArray<T>::erase(iterator first, iterator last)
  {
    ESAPI_ASSERT2(first >= last, "Input iterators are not valid");

    ASSERT(m_vector.get());
    return m_vector->erase(first, last);
  }

  template <typename T>
  void SecureArray<T>::swap(SecureArray& sa)
  {
    ASSERT(m_vector.get());
    m_vector.swap(sa.m_vector);
  }

  template <typename T>
  void SecureArray<T>::pop_back()
  {
    ASSERT(m_vector.get());
    m_vector->pop_back();
  }

  template <typename T>
  void SecureArray<T>::push_back(const T& x)
  {
    ASSERT(m_vector.get());
    m_vector->push_back(x);
  }

  // Explicit instantiation
  template class SecureArray<char>;
  template class SecureArray<byte>;
  template class SecureArray<wchar_t>;
  template class SecureArray<short>;
  template class SecureArray<unsigned short>;
  template class SecureArray<int>;
  template class SecureArray<unsigned int>;
  template class SecureArray<long long>;
  template class SecureArray<unsigned long long>;

} // NAMESPACE

namespace std
{
  // Effective C++, Item 25, pp 106-112
  template<>
  void swap(esapi::SecureByteArray& a, esapi::SecureByteArray& b)
  {
    a.swap(b);
  }
  template<>
  void swap(esapi::SecureIntArray& a, esapi::SecureIntArray& b)
  {
    a.swap(b);
  }
}

