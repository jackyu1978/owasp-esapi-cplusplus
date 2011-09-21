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

#include <boost/shared_ptr.hpp>

#include <sstream>
#include <iomanip>

#define HEX(x) std::hex << std::setw(x) << std::setfill('0')
#define OCT(x) std::octal << std::setw(x) << std::setfill('0')

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
    static boost::shared_ptr<StringArray> hexArr;

    MEMORY_BARRIER();
    if(!init)
    {
      boost::shared_ptr<StringArray> temp(new StringArray);
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
          std::ostringstream str;
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

  String Codec::encode(const Char immune[], size_t length, const String& input) const
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

  String Codec::encodeCharacter(const Char immune[], size_t length, Char c) const{
    ASSERT(immune);
    ASSERT(length);
    ASSERT(c != 0);

    return String(1, c);
  }

  String Codec::decode(const String& input) const{
    ASSERT(!input.empty());

    String sb;
    sb.reserve(input.size());

    PushbackString pbs(input);
    while (pbs.hasNext()) {
      Char c = decodeCharacter(pbs);
      if (c != 0) {
        sb+=c;
      } else {
        sb+=pbs.next();
      }
    }
    return sb;
  }

  Char Codec::decodeCharacter(PushbackString& input) const{
    // This method needs to reset input under certain conditions,
    // which it is not doing. See the comments in the header file.
    ASSERT(0);
    ASSERT(input.hasNext());

    return input.next();
  }

  String Codec::getHexForNonAlphanumeric(Char c) {
    ASSERT(c != 0);

    const StringArray& hex = getHexArray();

    int i = (int)c;
    if(i < (int)ARR_SIZE)
      return hex.at(i);

    return toHex((Char)i);
  }

  String Codec::toOctal(Char c) {
    ASSERT(c != 0);

    std::ostringstream str;
    // str << OCT(3) << int(0xFF & c);
    str << std::oct << c;
    return str.str();
  }

  String Codec::toHex(Char c) {
    ASSERT(c != 0);

    std::ostringstream str;
    // str << HEX(2) << int(0xFF & c);
    str << std::hex << c;
    return str.str();
  }

  bool Codec::containsCharacter(Char c, const String& s) const{
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
