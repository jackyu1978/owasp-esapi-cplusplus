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

#pragma once

#include "EsapiCommon.h"
#include "util/zAllocator.h"
#include "errors/IllegalArgumentException.h"
#include "safeint/SafeInt3.hpp"

#include <new>
#include <vector>
#include <boost/shared_ptr.hpp>

namespace esapi
{
  template <typename T>
  class ESAPI_EXPORT SecureArray
  {
  public:

    typedef typename std::vector< T, zallocator<T> > SecureVector;
    typedef typename zallocator<T>::size_type size_type;

    typedef typename SecureVector::value_type value_type;
    typedef typename SecureVector::pointer pointer;
    typedef typename SecureVector::const_pointer const_pointer;

    typedef typename SecureVector::iterator iterator;
    typedef typename SecureVector::const_iterator const_iterator;
    typedef typename SecureVector::reverse_iterator reverse_iterator;
    typedef typename SecureVector::const_reverse_iterator const_reverse_iterator;

    typedef typename SecureVector::reference reference;
    typedef typename SecureVector::const_reference const_reference;

  public:

    // Construction
    explicit SecureArray(size_type cnt = 0, const T& value = T())
      : m_vector(create_secure_array(cnt,value))
    {
      // Parameters are validated in create_secure_array
      ASSERT(m_vector.get());
      ASSERT(m_vector->size() == cnt);
    }

    explicit SecureArray(const T* ptr, size_t cnt)
      : m_vector(create_secure_array(ptr, cnt))
    {
      // Parameters are validated in create_secure_array
      ASSERT(m_vector.get());
      ASSERT(m_vector->size() == cnt);
    }

    template <typename InputIterator>
    SecureArray(InputIterator first, InputIterator last)
      : m_vector(create_secure_array(first, last))
    {
      // Parameters are validated in create_secure_array
      ASSERT(m_vector.get());
    }

    // Destruction
    ~SecureArray() { }

    // Iterators
    iterator begin()
    {
      ASSERT(m_vector.get());
      return m_vector->begin();
    }

    const_iterator begin() const
    {
      ASSERT(m_vector.get());
      return m_vector->begin();
    }

    iterator end()
    {
      ASSERT(m_vector.get());
      return m_vector->end();
    }

    const_iterator end() const
    {
      ASSERT(m_vector.get());
      return m_vector->end();
    }

    reference front()
    {
      ASSERT(m_vector.get());
      return m_vector->front();
    }

    const_reference front() const
    {
      ASSERT(m_vector.get());
      return m_vector->front();
    }

    reference back()
    {
      ASSERT(m_vector.get());
      return m_vector->back();
    }

    const_reference back() const
    {
      ASSERT(m_vector.get());
      return m_vector->back();
    }

    reverse_iterator rbegin()
    {
      ASSERT(m_vector.get());
      return m_vector->rbegin();
    }

    const_reverse_iterator rbegin() const
    {
      ASSERT(m_vector.get());
      return m_vector->rbegin();
    }

    reverse_iterator rend()
    {
      ASSERT(m_vector.get());
      return m_vector->rend();
    }

    const_reverse_iterator rend() const
    {
      ASSERT(m_vector.get());
      return m_vector->rend();
    }

    // Copy and assignment
    SecureArray(const SecureArray& sa)
      : m_vector(sa.m_vector)
    {
      ASSERT(m_vector.get());
      ASSERT(m_vector->size() == sa.m_vector->size());
    }

    SecureArray& operator=(const SecureArray& sa)
    {
      if(this != &sa)
      {
        m_vector = sa.m_vector;
      }    
      ASSERT(m_vector.get());
      ASSERT(m_vector->size() == sa.m_vector->size());

      return *this;
    }

    // Clone
    SecureArray clone() const
    {
      ASSERT(m_vector.get());
      if( !size() )
        return SecureArray<T>();

      return SecureArray<T>(data(), size());
    }

    // Size and capacity
    size_t max_size() const
    {
      // Can't use m_vector->max_size() here. It might be called before
      // the m_vector is constructed (eg, in create_secure_array).
      return std::numeric_limits<size_t>::max() / sizeof(T);
    }

    size_t capacity() const
    {
      ASSERT(m_vector.get());
      return m_vector->capacity();
    }

    void reserve(size_t cnt)
    {
      ASSERT(!(cnt > max_size()));
      if(cnt > max_size())
        throw std::bad_alloc();

      ASSERT(m_vector.get());
      m_vector->reserve(cnt);
    }

    bool empty() const
    {
      ASSERT(m_vector.get());
      return m_vector->empty();
    }

    size_type size() const
    {
      ASSERT(m_vector.get());
      return m_vector->size();
    }

    size_type length() const
    {
      ASSERT(m_vector.get());
      return m_vector->size();
    }

    void resize(size_type cnt, T t)
    {
      ASSERT(!(cnt > max_size()));
      if(cnt > max_size)
        throw std::bad_alloc();

      ASSERT(m_vector.get());
      m_vector->resize(cnt, t);
    }

    void clear()
    {
      ASSERT(m_vector.get());
      return m_vector->clear();
    }

    // Member functions
    const T& operator[](size_t pos) const
    {
      ASSERT(m_vector.get());
      return m_vector->operator[](pos);
    }

    T& operator[](size_t pos)
    {
      ASSERT(m_vector.get());
      return m_vector->operator[](pos);
    }

    const T& at(size_t pos) const
    {
      ASSERT(m_vector.get());
      return m_vector->at(pos);
    }

    T& at(size_t pos)
    {
      ASSERT(m_vector.get());
      return m_vector->at(pos);
    }

    // Value added
    T* data()
    {
      ASSERT(m_vector.get());
      return (m_vector->size() != 0 ? &(m_vector->operator[](0)) : nullptr);
    }

    const T* data() const
    {
      ASSERT(m_vector.get());
      return (m_vector->size() != 0 ? &(m_vector->operator[](0)) : nullptr);
    }

    void assign(size_type n, const T& u)
    {
      ASSERT(n <= max_size());

      ASSERT(m_vector.get());
      m_vector->assign(n, u);
    }

    void assign(const T* ptr, size_t cnt)
    {
      ESAPI_ASSERT2(ptr, "Array pointer is not valid");
      if(ptr == nullptr)
        throw IllegalArgumentException("Array pointer is not valid");

      // Warning only
      ESAPI_ASSERT2(cnt != 0, "Array size is 0");
      ESAPI_ASSERT2(cnt <= max_size(), "Too many elements in the array");
      if(!(cnt <= max_size()))
        throw IllegalArgumentException("Too many elements in the array");

      try
      {
        const T* base = ptr;
        base += SafeInt<size_t>(cnt);
      }
      catch(const SafeIntException&)
      {
        throw IllegalArgumentException("Array pointer wrap");
      }

      ASSERT(m_vector.get());
      m_vector->assign(ptr /*first*/, ptr+cnt /*last*/);
    }

    template <typename InputIterator>
    void assign(InputIterator first, InputIterator last)
    {
      // We're walking a tight rope here. There's nothing that says InputIterators need
      // to compare. However, our use of them are as pointers, which will compare.
      // The ASSERTs and tests might have to be yanked in the future if a non-pointer
      // InputIterator is used. (Thanks to Jonathan Wakely for the clarification).
      ESAPI_ASSERT2(first, "Bad first input iterator");
      ESAPI_ASSERT2(last >= first, "Input iterators are not valid");
      if(!(last >= first))
        throw IllegalArgumentException("Bad input iterators");

      ASSERT(m_vector.get());
      return m_vector->assign(first, last);
    }

    iterator insert(iterator pos, const T& x)
    {
      ASSERT(m_vector.get());
      return m_vector->insert(pos, x);
    }

    void insert(iterator pos, size_type n, const T& x)
    {
      ESAPI_ASSERT2(n, "Insertion size is 0"); // Warning only
      ESAPI_ASSERT2(n <= max_size(), "Too many elements in the array");
      ESAPI_ASSERT2(n <= max_size() - size(), "Too many elements in the resulting array");
      if(!(n <= max_size() - size()))
        throw IllegalArgumentException("Too many elements in the resulting array");

      ASSERT(m_vector.get());
      m_vector->insert(pos, n, x);
    }

    void insert(iterator pos, const T* ptr, size_t cnt)
    {
      ESAPI_ASSERT2(ptr, "Array pointer is not valid");
      if(ptr == nullptr)
        throw IllegalArgumentException("Array pointer is not valid");

      // Warning only
      ESAPI_ASSERT2(cnt != 0, "Array size is 0");
      ESAPI_ASSERT2(cnt <= max_size(), "Too many elements in the array");
      ESAPI_ASSERT2(cnt <= max_size() - size(), "Too many elements in the resulting array");
      if(!(cnt <= max_size() - size()))
        throw IllegalArgumentException("Too many elements in the array");

      try
      {
        const T* base = ptr;
        base += SafeInt<size_t>(cnt);
      }
      catch(const SafeIntException&)
      {
        throw IllegalArgumentException("Array pointer wrap");
      }

      ASSERT(m_vector.get());
      m_vector->insert(pos, ptr /*first*/, ptr+cnt /*last*/);
    }

    template <typename InputIterator>
    void insert(iterator pos, InputIterator first, InputIterator last)
    {
      // We're walking a tight rope here. There's nothing that says InputIterators need
      // to compare. However, our use of them are as pointers, which will compare.
      // The ASSERTs and tests might have to be yanked in the future if a non-pointer
      // InputIterator is used. (Thanks to Jonathan Wakely for the clarification).
      ESAPI_ASSERT2(first, "Bad first input iterator");
      ESAPI_ASSERT2(last >= first, "Input iterators are not valid");
      if(!(last >= first))
        throw IllegalArgumentException("Bad input iterators");

      ASSERT(m_vector.get());
      m_vector->insert(pos, first, last);
    }

    iterator erase(iterator pos)
    {
      ASSERT(m_vector.get());
      return m_vector->erase(pos);
    }

    iterator erase(iterator first, iterator last)
    {
      // We're walking a tight rope here. There's nothing that says InputIterators need
      // to compare. However, our use of them are as pointers, which will compare.
      // The ASSERTs and tests might have to be yanked in the future if a non-pointer
      // InputIterator is used. (Thanks to Jonathan Wakely for the clarification).
      // ESAPI_ASSERT2(first != nullptr, "Bad first input iterator");
      ESAPI_ASSERT2(last >= first, "Input iterators are not valid");
      if(!(last >= first))
        throw IllegalArgumentException("Bad input iterators");

      ASSERT(m_vector.get());
      return m_vector->erase(first, last);
    }

    void swap(SecureArray& sa)
    {
      ASSERT(m_vector.get());
      m_vector.swap(sa.m_vector);
    }

    void pop_back()
    {
      ASSERT(m_vector.get());
      m_vector->pop_back();
    }

    void push_back(const T& x)
    {
      ASSERT(m_vector.get());
      m_vector->push_back(x);
    }

  private:

    // Helpers to validate parameters in constructors
    SecureVector* create_secure_array(size_type cnt, const T& value)
    {
      // Array size 0 is OK.
      // ESAPI_ASSERT2(cnt != 0, "Array size is 0");
      ESAPI_ASSERT2(cnt <= max_size(), "Too many elements in the array");
      if(!(cnt <= max_size()))
        throw IllegalArgumentException("Too many elements in the array");

      return new SecureVector(cnt, value);
    }

    // Helpers to validate parameters in constructors
    SecureVector* create_secure_array(const T* ptr, size_t cnt)
    {
      ESAPI_ASSERT2(ptr, "Array pointer is not valid");
      if(ptr == nullptr)
        throw IllegalArgumentException("Array pointer is not valid");

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
        throw IllegalArgumentException("Array pointer wrap");
      }

      return new SecureVector(ptr /*first*/, ptr+cnt /*last*/);
    }

    // Helpers to validate parameters in constructors
    template <typename InputIterator>
    SecureVector* create_secure_array(InputIterator first, InputIterator last)
    {
      // We're walking a tight rope here. There's nothing that says InputIterators need
      // to compare. However, our use of them are as pointers, which will compare.
      // The ASSERTs and tests might have to be yanked in the future if a non-pointer
      // InputIterator is used. (Thanks to Jonathan Wakely for the clarification).
      ESAPI_ASSERT2(first, "Bad first input iterator");
      ESAPI_ASSERT2(last >= first, "Input iterators are not valid");
      if(!(last >= first))
        throw IllegalArgumentException("Bad input iterators");

      return new SecureVector(first, last);
    }

  private:

    boost::shared_ptr<SecureVector> m_vector;
  };

  // Non-member swap
  template <typename T>
  void swap(SecureArray<T>& a, SecureArray<T>& b)
  {
    a.swap(b);
  }

  // Convenience
  typedef SecureArray<byte> SecureByteArray;
  typedef SecureArray<int> SecureIntArray;

} // NAMESPACE

// Causes duplicate symbols under MSVC and GCC
#if 0
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
#endif