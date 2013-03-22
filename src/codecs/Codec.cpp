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

#include <sstream>
#include <iomanip>

#define HEX(x) std::hex << std::setw(x) << std::setfill(L'0')
#define OCT(x) std::octal << std::setw(x) << std::setfill(L'0')

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

  NarrowString Codec::encode(const Char immune[], size_t length, const NarrowString& input) const
  {
    ASSERT(immune);
    ASSERT(length);
    ASSERT(!input.empty());

    if(!immune)
      return String();

    String sb;
    sb.reserve(input.size());

    for (size_t i = 0; i < input.length(); i++) {
      Char c = input[i];
      sb.append(encodeCharacter(immune, length, c));
    }

    return sb;
  }

  NarrowString Codec::encodeCharacter(const Char immune[], size_t length, Char c) const{
    ASSERT(immune);
    ASSERT(length);
    ASSERT(c != 0);

    return String(1, c);
  }

  NarrowString Codec::decode(const NarrowString& input) const{
    ASSERT(!input.empty());

    NarrowString sb;
    sb.reserve(input.size());

    PushbackString pbs(input);
    while (pbs.hasNext()) {
      NarrowString c = decodeCharacter(pbs);
      ASSERT(!c.empty());

      if (!c.empty()) {
        sb+=c;
      } else {
        sb+=pbs.next();
      }
    }
    return sb;
  }

  NarrowString Codec::decodeCharacter(PushbackString& input) const{
    // This method needs to reset input under certain conditions,
    // which it is not doing. See the comments in the header file.
    ASSERT(0);
    ASSERT(input.hasNext());

    return NarrowString(1, input.next());
  }

  NarrowString Codec::getHexForNonAlphanumeric(Char c) {
    ASSERT(c != 0);

    const StringArray& hex = getHexArray();

    int i = (int)c;
    if(i < (int)ARR_SIZE)
      return hex.at(i);

    return toHex((Char)i);
  }

  NarrowString Codec::toOctal(Char c) {
    ASSERT(c != 0);

    StringStream str;
    // str << OCT(3) << int(0xFF & c);
    str << std::oct << c;
    return str.str();
  }

  NarrowString Codec::toHex(Char c) {
    ASSERT(c != 0);

    StringStream str;
    // str << HEX(2) << int(0xFF & c);
    str << std::hex << c;
    return str.str();
  }

  bool Codec::containsCharacter(Char c, const NarrowString& s) const{
    ASSERT(c != 0);
    ASSERT(!s.empty());

    return s.find(c, 0) != String::npos;
  }

  bool Codec::containsCharacter(Char c, const Char array[], size_t length) const{
    ASSERT(c != 0);
    ASSERT(array);
    ASSERT(length);

    if(!array)
      return false;

    for (size_t ch=0; ch < length; ch++) {
      if (c == array[ch]) return true;
    }

    return false;
  }
} //espai
