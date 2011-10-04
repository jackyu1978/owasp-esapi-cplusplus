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

// GCC is aggressively optimizing the SafeInt checks in this source file
#define SECURE_ARRAY_NO_SAFE_INT 1

namespace esapi
{
  // Construction
  template <typename T>
  SecureArray<T>::SecureArray(size_type n, const T& t)
    : m_vector(create_secure_array(n,t))
  {
    ASSERT(m_vector.get());
  }

  template <typename T>
  SecureArray<T>::SecureArray(const T* ptr, size_t cnt)
    : m_vector(create_secure_array(ptr, cnt))
  {
    ASSERT(m_vector.get());
  }

  template <typename T>
  template <typename InputIterator>
  SecureArray<T>::SecureArray(InputIterator first, InputIterator last)
    : m_vector(create_secure_array(first, last))
  {
    ASSERT(m_vector.get());
  }

  // Private helper
  template <typename T>
  typename SecureArray<T>::SecureVector*
  SecureArray<T>::create_secure_array(size_type cnt, const T& value)
  {
    // Warning only
    ESAPI_ASSERT2(cnt != 0, "Array size is 0");
    ESAPI_ASSERT2(cnt <= max_size(), "Too many elements in the array");
    if(!(cnt <= max_size()))
      throw InvalidArgumentException("Too many elements in the array");

    return new SecureVector(cnt, value);
  }

  // Private helper
  template <typename T>
  typename SecureArray<T>::SecureVector*
  SecureArray<T>::create_secure_array(const T* ptr, size_t cnt)
  {
    ESAPI_ASSERT2(ptr, "Array pointer is not valid");
    if(ptr == nullptr)
      throw InvalidArgumentException("Array pointer is not valid");

    // Warning only
    ESAPI_ASSERT2(cnt != 0, "Array size is 0");
    // Allocator will throw below
    ESAPI_ASSERT2(cnt <= max_size(), "Too many elements in the array");

    try
    {
      const T* base = ptr;
      base += SafeInt<size_t>(cnt);
    }
    catch(const SafeIntException&)
    {
      throw InvalidArgumentException("Array pointer wrap");
    }

    return new SecureVector(ptr /*first*/, ptr+cnt /*last*/);
  }

  // Private helper
  template <typename T>
  template <typename InputIterator>
  typename SecureArray<T>::SecureVector*
  SecureArray<T>::create_secure_array(InputIterator first, InputIterator last)
  {
    ESAPI_ASSERT2(first, "Bad first input iterator");
    ESAPI_ASSERT2(last >= first, "Input iterators are not valid");
    if(!(last >= first))
      throw InvalidArgumentException("Bad input iterators");

    return new SecureVector(first, last);
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
    ASSERT(m_vector->size() == sa.m_vector->size());
  }

  template <typename T>
  SecureArray<T>& SecureArray<T>::operator=(const SecureArray<T>& sa)
  {
    if(this != &sa)
      {
        m_vector = sa.m_vector;
      }    
    ASSERT(m_vector.get());
    ASSERT(m_vector->size() == sa.m_vector->size());

    return *this;
  }

  // Size and capacity
  template <typename T>
  typename SecureArray<T>::size_type
  SecureArray<T>::max_size() const
  {
    // Can't use m_vector->max_size() here. It might be called
    // before the m_vector is constructed (ie, create_secure_array).
    return std::numeric_limits<T>::max()/sizeof(T);
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
    return (m_vector->size() != 0 ? &(m_vector->operator[](0)) : nullptr);
  }

  // Value added
  template <typename T>
  const T* SecureArray<T>::data() const
  {
    return (m_vector->size() != 0 ? &(m_vector->operator[](0)) : nullptr);
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

    // Warning only
    ESAPI_ASSERT2(cnt != 0, "Array size is 0");
    ESAPI_ASSERT2(cnt <= max_size(), "Too many elements in the array");
    if(!(cnt <= max_size()))
      throw InvalidArgumentException("Too many elements in the array");

    try
    {
      const T* base = ptr;
      base += SafeInt<size_t>(cnt);
    }
    catch(const SafeIntException&)
    {
      throw InvalidArgumentException("Array pointer wrap");
    }

    ASSERT(m_vector.get());
    m_vector->assign(ptr /*first*/, ptr+cnt /*last*/);
  }

  template <typename T>
  template <typename InputIterator>
  void SecureArray<T>::assign(InputIterator first, InputIterator last)
  {
    ESAPI_ASSERT2(first, "Bad first input iterator");
    ESAPI_ASSERT2(last >= first, "Input iterators are not valid");
    if(!(last >= first))
      throw InvalidArgumentException("Bad input iterators");
    
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
    if(!(n <= max_size() - size()))
      throw InvalidArgumentException("Too many elements in the resulting array");

    ASSERT(m_vector.get());
    m_vector->insert(pos, n, x);
  }

  template <typename T>
  void SecureArray<T>::insert(iterator pos, const T* ptr, size_t cnt)
  {
    ESAPI_ASSERT2(ptr, "Array pointer is not valid");
    if(ptr == nullptr)
      throw InvalidArgumentException("Array pointer is not valid");

    // Warning only
    ESAPI_ASSERT2(cnt != 0, "Array size is 0");
    ESAPI_ASSERT2(cnt <= max_size(), "Too many elements in the array");
    ESAPI_ASSERT2(cnt <= max_size() - size(), "Too many elements in the resulting array");
    if(!(cnt <= max_size() - size()))
      throw InvalidArgumentException("Too many elements in the array");

    try
    {
      const T* base = ptr;
      base += SafeInt<size_t>(cnt);
    }
    catch(const SafeIntException&)
    {
      throw InvalidArgumentException("Array pointer wrap");
    }

    ASSERT(m_vector.get());
    m_vector->insert(pos, ptr /*first*/, ptr+cnt /*last*/);
  }

  template <typename T>
  template <typename InputIterator>
  void SecureArray<T>::insert(iterator pos, InputIterator first, InputIterator last)
  {
    ESAPI_ASSERT2(first, "Bad first input iterator");
    ESAPI_ASSERT2(last >= first, "Input iterators are not valid");
    if(!(last >= first))
      throw InvalidArgumentException("Bad input iterators");
    
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

  template <typename T>
  void swap(SecureArray<T>& a, SecureArray<T>& b)
  {
    a.swap(b);
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

