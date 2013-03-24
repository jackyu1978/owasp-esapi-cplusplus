/**
* OWASP Enterprise Security API (ESAPI)
*
* This file is part of the Open Web Application Security Project (OWASP)
* Enterprise Security API (ESAPI) project. For details, please see
* <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
*
* Copyright (c) 2011 - The OWASP Foundation
*
* The ESAPI is published by OWASP under the BSD license. You should read and accept the
* LICENSE before you use, modify, and/or redistribute this software.
*
* @author Jeff Williams <a href="http://www.aspectsecurity.com">Aspect Security</a>
* @created 2011
*/

#include "EsapiCommon.h"
#include "codecs/Codec.h"
#include "errors/IllegalArgumentException.h"

#include <sstream>
#include <iomanip>

#include "safeint/SafeInt3.hpp"

/**
* Precomputed size of the internal hex array.
* Private to this compilation unit.
*/
static const size_t ARR_SIZE = 256;

//
// Thread safe, multiprocessor initialization
// http://www.aristeia.com/Papers/DDJ_Jul_Aug_2004_revised.pdf
//

namespace esapi
{
  const StringArray& Codec::getHexArray ()
  {
    MutexLock lock(getClassMutex());

    static volatile bool init = false;
    static shared_ptr<StringArray> hexArr;

    MEMORY_BARRIER();
    if(!init)
    {
      shared_ptr<StringArray> temp(new StringArray);
      ASSERT(temp);
      if(nullptr == temp.get())
        throw std::bad_alloc();

      // Convenience
      StringArray& ta = *temp.get();

      // Save on reallocations
      ta.resize(ARR_SIZE);

      for ( unsigned int c = 0; c < ARR_SIZE; c++ ) {
        if ( (c >= 0x30 && c <= 0x39) || (c >= 0x41 && c <= 0x5A) || (c >= 0x61 && c <= 0x7A) ) {
          ta[c] = String();
        } else {
          StringStream str;
          // str << HEX(2) << int(0xFF & c);
          str << std::hex << c;
          ta[c] = str.str();
        }
      }

      hexArr.swap(temp);
      init = true;

      MEMORY_BARRIER();

    } // !init

    return *hexArr.get();
  }

  /**
  * Retrieve the class wide intialization lock.
  *
  * @return the mutex used to lock the class.
  */
  Mutex& Codec::getClassMutex ()
  {
    static Mutex s_mutex;
    return s_mutex;
  }

  NarrowString Codec::encode(const StringArray& immune, const NarrowString& input) const
  {
    // ASSERT(!immune.empty());
    ASSERT(!input.empty());

    if(immune.empty() || input.empty())
      return input;

    String sb;
    sb.reserve(input.length());

    /*
    PushbackString pbs(input);
    while(pbs.hasNext())
    {
    sb.append(encodeCharacter(immune, pbs.nextCharacter()));
    }
    */

    return sb;
  }

  NarrowString Codec::encodeCharacter(const StringArray& immune, const NarrowString& ch) const {
    // ASSERT(!immune.empty());
    ASSERT(!ch.empty());

    return ch;
  }

  NarrowString Codec::decode(const NarrowString& input) const {
    ASSERT(!input.empty());

    if(input.empty())
      return NarrowString();

    NarrowString sb;
    sb.reserve(input.size());

    PushbackString pbs(input);
    while (pbs.hasNext()) {
      NarrowString ch = decodeCharacter(pbs);
      ASSERT(!ch.empty());

      if (!ch.empty()) {
        sb+=ch;
      } else {
        sb+=pbs.next();
      }
    }
    return sb;
  }

  NarrowString Codec::decodeCharacter(PushbackString& input) const {
    // This method needs to reset input under certain conditions,
    // which it is not doing. See the comments in the header file.
    ASSERT(0);
    ASSERT(input.hasNext());

    return NarrowString(1, input.next());
  }

  NarrowString Codec::getHexForNonAlphanumeric(const NarrowString& ch) {
    ASSERT(!ch.empty());

    const StringArray& hex = getHexArray();

    /*
    int i = (int)ch;
    if(i < (int)ARR_SIZE)
    return hex.at(i);

    return toHex((Char)i);
    */
    return NarrowString();
  }

  NarrowString Codec::toBase(const NarrowString& ch, unsigned int base) {

    ASSERT(!ch.empty());
    ASSERT(base == 8 || base == 10 || base == 16);

    if(ch.empty())
      return NarrowString();

    if(!(base == 8 || base == 10 || base == 16))
      throw IllegalArgumentException("Codec::toBase: Invalid base");

    SafeInt<unsigned long> n(static_cast<unsigned char>(ch[0]));
    for(size_t i = 1; i < ch.length(); ++i)
    {
      n <<= static_cast<unsigned int>(8);
      n |= static_cast<unsigned char>(ch[i]);
    }

    StringStream str;
    str.setf(str.flags() | StringStream::uppercase);

    switch(base)
    {
    case 8:
      str << "0" << std::oct << static_cast<unsigned long>(n);
      break;
    case 10:
      str << std::dec << static_cast<unsigned long>(n);
      break;
    case 16:
      str << "0" << std::hex << static_cast<unsigned long>(n);
      if(1 == (str.str().length() % 2))
        str = StringStream(str.str().erase(0,1));
      break;
    default: ;
    }

    return str.str();
  }

  NarrowString Codec::toOctal(const NarrowString& ch) {
    ASSERT(!ch.empty());

    return Codec::toBase(ch, 8);
  }

  NarrowString Codec::toDec(const NarrowString& ch) {
    ASSERT(!ch.empty());

    return Codec::toBase(ch, 10);
  }

  NarrowString Codec::toHex(const NarrowString& ch) {
    ASSERT(!ch.empty());

    return Codec::toBase(ch, 16);
  }

  bool Codec::containsCharacter(const NarrowString& ch, const NarrowString& str) const {
    ASSERT(!ch.empty());
    ASSERT(!str.empty());

    return str.find(ch, 0) != String::npos;
  }
} //espai
