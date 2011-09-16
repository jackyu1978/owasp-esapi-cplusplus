/*-----------------------------------------------------------------------------------------------------------
  This software is licensed under the Microsoft Public License (Ms-PL).
  For more information about Microsoft open source licenses, refer to
  http://www.microsoft.com/opensource/licenses.mspx

  This license governs use of the accompanying software. If you use the software, you accept this license.
  If you do not accept the license, do not use the software.

  Definitions
  The terms "reproduce," "reproduction," "derivative works," and "distribution" have the same meaning here
  as under U.S. copyright law. A "contribution" is the original software, or any additions or changes to
  the software. A "contributor" is any person that distributes its contribution under this license.
  "Licensed patents" are a contributor's patent claims that read directly on its contribution.

  Grant of Rights
  (A) Copyright Grant- Subject to the terms of this license, including the license conditions and limitations
  in section 3, each contributor grants you a non-exclusive, worldwide, royalty-free copyright license to
  reproduce its contribution, prepare derivative works of its contribution, and distribute its contribution
  or any derivative works that you create.

  (B) Patent Grant- Subject to the terms of this license, including the license conditions and limitations in
  section 3, each contributor grants you a non-exclusive, worldwide, royalty-free license under its licensed
  patents to make, have made, use, sell, offer for sale, import, and/or otherwise dispose of its contribution
  in the software or derivative works of the contribution in the software.

  Conditions and Limitations
  (A) No Trademark License- This license does not grant you rights to use any contributors' name, logo,
  or trademarks.
  (B) If you bring a patent claim against any contributor over patents that you claim are infringed by the
  software, your patent license from such contributor to the software ends automatically.
  (C) If you distribute any portion of the software, you must retain all copyright, patent, trademark, and
  attribution notices that are present in the software.
  (D) If you distribute any portion of the software in source code form, you may do so only under this license
  by including a complete copy of this license with your distribution. If you distribute any portion of the
  software in compiled or object code form, you may only do so under a license that complies with this license.
  (E) The software is licensed "as-is." You bear the risk of using it. The contributors give no express warranties,
  guarantees, or conditions. You may have additional consumer rights under your local laws which this license
  cannot change. To the extent permitted under your local laws, the contributors exclude the implied warranties
  of merchantability, fitness for a particular purpose and non-infringement.


  Copyright (c) OWASP Project (https://www.owasp.org), 2011. All rights reserved.
*/

#include "TestMain.h"

namespace neg_verify
{

  template <typename T>
  struct UnsignedTest
  {
    T x;
    T y;
    bool fExpected;
  };

  template <typename T>
  struct SignedTest
  {
    T x;
    T y;
    bool fExpected;
  };

  static const SignedTest< __int8 > neg_int8[] =
    {
      { 0x00, 0x00, true},
      { 0x01, 0xff, true},
      { 0x02, 0xfe, true},
      { 0x7e, 0x82, true},
      { 0x7f, 0x81, true},
      { 0x80, 0x80, false},
      { 0x81, 0x7f, true},
      { 0xfe, 0x02, true},
      { 0xff, 0x01, true},
    };

  void NegVerifyInt8()
  {
    size_t i;

    for( i = 0; i < COUNTOF(neg_int8); ++i )
      {
        // Now test throwing version
        bool fSuccess = true;
        try
          {
            SafeInt<__int8> x(neg_int8[i].x);
            SafeInt<__int8> y(-x);

            if(y != (__int8)neg_int8[i].y)
              {
                cerr << "Error in case neg_int8 (1): ";
                cerr << "x = " << HEX(2) << (int)(0xFF & neg_int8[i].x) << ", ";
                cerr << "y = " << HEX(2) << (int)(0xFF & neg_int8[i].y) << endl;
              }
          }
        catch(...)
          {
            fSuccess = false;
          }

        if( fSuccess != neg_int8[i].fExpected )
          {
            cerr << "Error in case neg_int8 throw (2): ";
            cerr << HEX(2) << (int)(0xFF & neg_int8[i].x) << ", ";
            cerr << HEX(2) << (int)(0xFF & neg_int8[i].y) << ", ";
            cerr << "expected = " << neg_int8[i].fExpected << endl;
          }      
      }
  }

  static const SignedTest< __int16 > neg_int16[] =
    {
      { 0x0000, 0x0000, true},
      { 0x0001, 0xffff, true},
      { 0x0002, 0xfffe, true},
      { 0x7ffe, 0x8002, true},
      { 0x7fff, 0x8001, true},
      { 0x8000, 0x8000, false},
      { 0x8001, 0x7fff, true},
      { 0xfffe, 0x0002, true},
      { 0xffff, 0x0001, true},
    };

  void NegVerifyInt16()
  {
    size_t i;

    for( i = 0; i < COUNTOF(neg_int16); ++i )
      {
        // Now test throwing version
        bool fSuccess = true;
        try
          {
            SafeInt<__int16> x(neg_int16[i].x);
            SafeInt<__int16> y(-x);

            if(y != (__int16)neg_int16[i].y)
              {
                cerr << "Error in case neg_int16 (1): ";
                cerr << "x = " << HEX(4) << neg_int16[i].x << ", ";
                cerr << "y = " << HEX(4) << neg_int16[i].y << endl;
              }
          }
        catch(...)
          {
            fSuccess = false;
          }

        if( fSuccess != neg_int16[i].fExpected )
          {
            cerr << "Error in case neg_int16 throw (2): ";
            cerr << HEX(4) << neg_int16[i].x << ", ";
            cerr << HEX(4) << neg_int16[i].y << ", ";
            cerr << "expected = " << neg_int16[i].fExpected << endl;
          }      
      }
  }

  static const SignedTest< __int32 > neg_int32[] =
    {
      { 0x00000000, 0x00000000, true},
      { 0x00000001, 0xffffffff, true},
      { 0x00000002, 0xfffffffe, true},
      { 0x7ffffffe, 0x80000002, true},
      { 0x7fffffff, 0x80000001, true},
      { 0x80000000, 0x80000000, false},
      { 0x80000001, 0x7fffffff, true},
      { 0xfffffffe, 0x00000002, true},
      { 0xffffffff, 0x00000001, true},
    };

  void NegVerifyInt32()
  {
    size_t i;

    for( i = 0; i < COUNTOF(neg_int32); ++i )
      {
        // Now test throwing version
        bool fSuccess = true;
        try
          {
            SafeInt<__int32> x(neg_int32[i].x);
            SafeInt<__int32> y(-x);

            if(y != (__int32)neg_int32[i].y)
              {
                cerr << "Error in case neg_int32 (1): ";
                cerr << "x = " << HEX(8) << neg_int32[i].x << ", ";
                cerr << "y = " << HEX(8) << neg_int32[i].y << endl;
              }
          }
        catch(...)
          {
            fSuccess = false;
          }

        if( fSuccess != neg_int32[i].fExpected )
          {
            cerr << "Error in case neg_int32 throw (2): ";
            cerr << HEX(8) << neg_int32[i].x << ", ";
            cerr << HEX(8) << neg_int32[i].y << ", ";
            cerr << "expected = " << neg_int32[i].fExpected << endl;
          }      
      }
  }

  static const SignedTest< __int64 > neg_int64[] =
    {
      { 0x0000000000000000LL, 0x0000000000000000LL, true},
      { 0x0000000000000001LL, 0xffffffffffffffffLL, true},
      { 0x0000000000000002LL, 0xfffffffffffffffeLL, true},
      { 0x000000007ffffffeLL, 0xffffffff80000002LL, true},
      { 0x000000007fffffffLL, 0xffffffff80000001LL, true},
      { 0x0000000080000000LL, 0xffffffff80000000LL, true},
      { 0x0000000080000001LL, 0xffffffff7fffffffLL, true},
      { 0x00000000fffffffeLL, 0xffffffff00000002LL, true},
      { 0x00000000ffffffffLL, 0xffffffff00000001LL, true},
      { 0x0000000100000000LL, 0xffffffff00000000LL, true},
      { 0x0000000200000000LL, 0xfffffffe00000000LL, true},
      { 0x7ffffffffffffffeLL, 0x8000000000000002LL, true},
      { 0x7fffffffffffffffLL, 0x8000000000000001LL, true},
      { 0x8000000000000000LL, 0x8000000000000000LL, false},
      { 0x8000000000000001LL, 0x7fffffffffffffffLL, true},
      { 0xfffffffffffffffeLL, 0x0000000000000002LL, true},
      { 0xffffffffffffffffLL, 0x0000000000000001LL, true},
    };

  void NegVerifyInt64()
  {
    size_t i;

    for( i = 0; i < COUNTOF(neg_int64); ++i )
      {
        // Now test throwing version
        bool fSuccess = true;
        try
          {
            SafeInt<__int64> x(neg_int64[i].x);
            SafeInt<__int64> y(-x);

            if(y != (__int64)neg_int64[i].y)
              {
                cerr << "Error in case neg_int64 (1): ";
                cerr << "x = " << HEX(16) << neg_int64[i].x << ", ";
                cerr << "y = " << HEX(16) << neg_int64[i].y << endl;
              }
          }
        catch(...)
          {
            fSuccess = false;
          }

        if( fSuccess != neg_int64[i].fExpected )
          {
            cerr << "Error in case neg_int64 throw (2): ";
            cerr << HEX(16) << neg_int64[i].x << ", ";
            cerr << HEX(16) << neg_int64[i].y << ", ";
            cerr << "expected = " << neg_int64[i].fExpected << endl;
          }      
      }
  }

  void NegVerify()
  {
    cout << "Verifying Negation:" << endl;

#if !defined(SAFEINT_DISALLOW_UNSIGNED_NEGATION)
    cout << "Unsigned negation is allowed, but unsigned negation tests ";
    cout << "will not be performed. Please consider defining ";
    cout << "SAFEINT_DISALLOW_UNSIGNED_NEGATION." << endl;
    cout << "An unsigned negation results in an unsigned, so negating ";
    cout << "positive 0x01 results in positive 0xFF, and not a signed ";
    cout << "integer with value -1. " << endl;
#endif

    NegVerifyInt8();
    NegVerifyInt16();
    NegVerifyInt32();
    NegVerifyInt64();
  }

} // NAMESPACE
