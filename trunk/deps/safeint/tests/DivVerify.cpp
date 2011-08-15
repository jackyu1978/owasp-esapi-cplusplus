/*-----------------------------------------------------------------------------------------------------------This software is licensed under the Microsoft Public License (Ms-PL).For more information about Microsoft open source licenses, refer to http://www.microsoft.com/opensource/licenses.mspxThis license governs use of the accompanying software. If you use the software, you accept this license. If you do not accept the license, do not use the software.DefinitionsThe terms "reproduce," "reproduction," "derivative works," and "distribution" have the same meaning here as under U.S. copyright law. A "contribution" is the original software, or any additions or changes to the software. A "contributor" is any person that distributes its contribution under this license. "Licensed patents" are a contributor's patent claims that read directly on its contribution.Grant of Rights(A) Copyright Grant- Subject to the terms of this license, including the license conditions and limitations in section 3, each contributor grants you a non-exclusive, worldwide, royalty-free copyright license to reproduce its contribution, prepare derivative works of its contribution, and distribute its contribution or any derivative works that you create.(B) Patent Grant- Subject to the terms of this license, including the license conditions and limitations in section 3, each contributor grants you a non-exclusive, worldwide, royalty-free license under its licensed patents to make, have made, use, sell, offer for sale, import, and/or otherwise dispose of its contribution in the software or derivative works of the contribution in the software.Conditions and Limitations(A) No Trademark License- This license does not grant you rights to use any contributors' name, logo,     or trademarks. (B) If you bring a patent claim against any contributor over patents that you claim are infringed by the     software, your patent license from such contributor to the software ends automatically. (C) If you distribute any portion of the software, you must retain all copyright, patent, trademark, and     attribution notices that are present in the software. (D) If you distribute any portion of the software in source code form, you may do so only under this license     by including a complete copy of this license with your distribution. If you distribute any portion of the    software in compiled or object code form, you may only do so under a license that complies with this license. (E) The software is licensed "as-is." You bear the risk of using it. The contributors give no express warranties,     guarantees, or conditions. You may have additional consumer rights under your local laws which this license    cannot change. To the extent permitted under your local laws, the contributors exclude the implied warranties    of merchantability, fitness for a particular purpose and non-infringement.Copyright (c) Microsoft Corporation.  All rights reserved.*/#include "TestMain.h"namespace div_verify{/** Interesting numbers:**  unsigned __int64*  0, 1, 2, 0x7fffffff, 0x80000000, 0xffffffff, 0x100000000, 0x200000000, 0x7fffffffffffffff, 0x8000000000000000, 0xffffffffffffffff*  unsigned __int32*  0, 1, 2, 0x7fffffff, 0x80000000, 0xffffffff*  signed __int64*  0, 1, 2, 0x7fffffff, 0x80000000, 0xffffffff, 0x100000000, 0x200000000, 0x7fffffffffffffff, 0x8000000000000000, 0xffffffffffffffff*/template <typename T, typename U>struct DivTest{   T x;   U y;   bool fExpected;};// For the most part, unsigned-unsigned combinations are not going to give us any problems// Only thing to verify is that 0/0 still throwsDivTest< unsigned __int64, unsigned __int64 > uint64_uint64[] = 
{   { 0,                     0, false },   { 1,                     0, false },   { 2,                     0, false },   { 0x7fffffffULL,            0ULL, false },
   { 0x80000000ULL,            0ULL, false },
   { 0xffffffffULL,            0ULL, false },
   { 0x100000000ULL,           0ULL, false },
   { 0x200000000ULL,           0ULL, false },
   { 0x7fffffffffffffffULL,    0ULL, false },
   { 0x8000000000000000ULL,    0ULL, false },
   { 0xffffffffffffffffULL,    0ULL, false },
   { 0,                     1, true },   { 1,                     1, true },   { 2,                     1, true },   { 0x7fffffffULL,            1ULL, true },
   { 0x80000000ULL,            1ULL, true },
   { 0xffffffffULL,            1ULL, true },
   { 0x100000000ULL,           1ULL, true },
   { 0x200000000ULL,           1ULL, true },
   { 0x7fffffffffffffffULL,    1ULL, true },
   { 0x8000000000000000ULL,    1ULL, true },
   { 0xffffffffffffffffULL,    1ULL, true },
   { 0,                     2, true },   { 1,                     2, true },   { 2,                     2, true },   { 0x7fffffffULL,            2ULL, true },
   { 0x80000000ULL,            2ULL, true },
   { 0xffffffffULL,            2ULL, true },
   { 0x100000000ULL,           2ULL, true },
   { 0x200000000ULL,           2ULL, true },
   { 0x7fffffffffffffffULL,    2ULL, true },
   { 0x8000000000000000ULL,    2ULL, true },
   { 0xffffffffffffffffULL,    2ULL, true },
   { 0ULL,                     0x7fffffffULL, true },
   { 1ULL,                     0x7fffffffULL, true },
   { 2ULL,                     0x7fffffffULL, true },
   { 0x7fffffffULL,            0x7fffffffULL, true },
   { 0x80000000ULL,            0x7fffffffULL, true },
   { 0xffffffffULL,            0x7fffffffULL, true },
   { 0x100000000ULL,           0x7fffffffULL, true },
   { 0x200000000ULL,           0x7fffffffULL, true },
   { 0x7fffffffffffffffULL,    0x7fffffffULL, true },
   { 0x8000000000000000ULL,    0x7fffffffULL, true },
   { 0xffffffffffffffffULL,    0x7fffffffULL, true },
   { 0ULL,                     0x80000000ULL, true },
   { 1ULL,                     0x80000000ULL, true },
   { 2ULL,                     0x80000000ULL, true },
   { 0x7fffffffULL,            0x80000000ULL, true },
   { 0x80000000ULL,            0x80000000ULL, true },
   { 0xffffffffULL,            0x80000000ULL, true },
   { 0x100000000ULL,           0x80000000ULL, true },
   { 0x200000000ULL,           0x80000000ULL, true },
   { 0x7fffffffffffffffULL,    0x80000000ULL, true },
   { 0x8000000000000000ULL,    0x80000000ULL, true },
   { 0xffffffffffffffffULL,    0x80000000ULL, true },
   { 0ULL,                     0xffffffffULL, true },
   { 1ULL,                     0xffffffffULL, true },
   { 2ULL,                     0xffffffffULL, true },
   { 0x7fffffffULL,            0xffffffffULL, true },
   { 0x80000000ULL,            0xffffffffULL, true },
   { 0xffffffffULL,            0xffffffffULL, true },
   { 0x100000000ULL,           0xffffffffULL, true },
   { 0x200000000ULL,           0xffffffffULL, true },
   { 0x7fffffffffffffffULL,    0xffffffffULL, true },
   { 0x8000000000000000ULL,    0xffffffffULL, true },
   { 0xffffffffffffffffULL,    0xffffffffULL, true },
   { 0ULL,                     0x100000000ULL, true },
   { 1ULL,                     0x100000000ULL, true },
   { 2ULL,                     0x100000000ULL, true },
   { 0x7fffffffULL,            0x100000000ULL, true },
   { 0x80000000ULL,            0x100000000ULL, true },
   { 0xffffffffULL,            0x100000000ULL, true },
   { 0x100000000ULL,           0x100000000ULL, true },
   { 0x200000000ULL,           0x100000000ULL, true },
   { 0x7fffffffffffffffULL,    0x100000000ULL, true },
   { 0x8000000000000000ULL,    0x100000000ULL, true },
   { 0xffffffffffffffffULL,    0x100000000ULL, true },
   { 0ULL,                     0x200000000ULL, true },
   { 1ULL,                     0x200000000ULL, true },
   { 2ULL,                     0x200000000ULL, true },
   { 0x7fffffffULL,            0x200000000ULL, true },
   { 0x80000000ULL,            0x200000000ULL, true },
   { 0xffffffffULL,            0x200000000ULL, true },
   { 0x100000000ULL,           0x200000000ULL, true },
   { 0x200000000ULL,           0x200000000ULL, true },
   { 0x7fffffffffffffffULL,    0x200000000ULL, true },
   { 0x8000000000000000ULL,    0x200000000ULL, true },
   { 0xffffffffffffffffULL,    0x200000000ULL, true },
   { 0ULL,                     0x7fffffffffffffffULL, true },
   { 1ULL,                     0x7fffffffffffffffULL, true },
   { 2ULL,                     0x7fffffffffffffffULL, true },
   { 0x7fffffffULL,            0x7fffffffffffffffULL, true },
   { 0x80000000ULL,            0x7fffffffffffffffULL, true },
   { 0xffffffffULL,            0x7fffffffffffffffULL, true },
   { 0x100000000ULL,           0x7fffffffffffffffULL, true },
   { 0x200000000ULL,           0x7fffffffffffffffULL, true },
   { 0x7fffffffffffffffULL,    0x7fffffffffffffffULL, true },
   { 0x8000000000000000ULL,    0x7fffffffffffffffULL, true },
   { 0xffffffffffffffffULL,    0x7fffffffffffffffULL, true },
   { 0ULL,                     0x8000000000000000ULL, true },
   { 1ULL,                     0x8000000000000000ULL, true },
   { 2ULL,                     0x8000000000000000ULL, true },
   { 0x7fffffffULL,            0x8000000000000000ULL, true },
   { 0x80000000ULL,            0x8000000000000000ULL, true },
   { 0xffffffffULL,            0x8000000000000000ULL, true },
   { 0x100000000ULL,           0x8000000000000000ULL, true },
   { 0x200000000ULL,           0x8000000000000000ULL, true },
   { 0x7fffffffffffffffULL,    0x8000000000000000ULL, true },
   { 0x8000000000000000ULL,    0x8000000000000000ULL, true },
   { 0xffffffffffffffffULL,    0x8000000000000000ULL, true },
   { 0ULL,                     0xffffffffffffffffULL, true },
   { 1ULL,                     0xffffffffffffffffULL, true },
   { 2ULL,                     0xffffffffffffffffULL, true },
   { 0x7fffffffULL,            0xffffffffffffffffULL, true },
   { 0x80000000ULL,            0xffffffffffffffffULL, true },
   { 0xffffffffULL,            0xffffffffffffffffULL, true },
   { 0x100000000ULL,           0xffffffffffffffffULL, true },
   { 0x200000000ULL,           0xffffffffffffffffULL, true },
   { 0x7fffffffffffffffULL,    0xffffffffffffffffULL, true },
   { 0x8000000000000000ULL,    0xffffffffffffffffULL, true },
   { 0xffffffffffffffffULL,    0xffffffffffffffffULL, true },
};void DivVerifyUint64Uint64(){   size_t i;   for( i = 0; i < sizeof(uint64_uint64)/sizeof(uint64_uint64[0]); ++i )   {      unsigned __int64 ret;      if( SafeDivide(uint64_uint64[i].x, uint64_uint64[i].y, ret) != uint64_uint64[i].fExpected )      {         //assert(false);         cerr << "Error in case uint64_uint64: " << uint64_uint64[i].x << ", " << uint64_uint64[i].y;         cerr << ", expected = " << (uint64_uint64[i].fExpected ? "true" : "false") << endl;      }      // Now test throwing version      bool fSuccess = true;      try      {         SafeInt<unsigned __int64> si(uint64_uint64[i].x);         si /= uint64_uint64[i].y;      }      catch(...)      {         fSuccess = false;      }      if( fSuccess != uint64_uint64[i].fExpected )      {         cerr << "Error in case uint64_uint64: " << uint64_uint64[i].x << ", " << uint64_uint64[i].y;         cerr << ", expected = " << (uint64_uint64[i].fExpected ? "true" : "false") << endl;      }      // Also need to test the version that assigns back out      // to a plain int, as it has different logic      fSuccess = true;      try      {         unsigned __int64 x(uint64_uint64[i].x);         x /= SafeInt<unsigned __int64>(uint64_uint64[i].y);      }      catch(...)      {         fSuccess = false;      }      if( fSuccess != uint64_uint64[i].fExpected )      {         cerr << "Error in case uint64_uint64: " << uint64_uint64[i].x << ", " << uint64_uint64[i].y;         cerr << ", expected = " << (uint64_uint64[i].fExpected ? "true" : "false") << endl;      }   }}DivTest< unsigned __int64, unsigned __int32 > uint64_uint32[] = 
{   { 0,                     0, false },   { 1,                     0, false },   { 2,                     0, false },   { 0x7fffffffULL,            0, false },
   { 0x80000000ULL,            0, false },
   { 0xffffffffULL,            0, false },
   { 0x100000000ULL,           0, false },
   { 0x200000000ULL,           0, false },
   { 0x7fffffffffffffffULL,    0, false },
   { 0x8000000000000000ULL,    0, false },
   { 0xffffffffffffffffULL,    0, false },
   { 0,                     1, true },   { 1,                     1, true },   { 2,                     1, true },   { 0x7fffffffULL,            1, true },
   { 0x80000000ULL,            1, true },
   { 0xffffffffULL,            1, true },
   { 0x100000000ULL,           1, true },
   { 0x200000000ULL,           1, true },
   { 0x7fffffffffffffffULL,    1, true },
   { 0x8000000000000000ULL,    1, true },
   { 0xffffffffffffffffULL,    1, true },
   { 0,                     2, true },   { 1,                     2, true },   { 2,                     2, true },   { 0x7fffffffULL,            2, true },
   { 0x80000000ULL,            2, true },
   { 0xffffffffULL,            2, true },
   { 0x100000000ULL,           2, true },
   { 0x200000000ULL,           2, true },
   { 0x7fffffffffffffffULL,    2, true },
   { 0x8000000000000000ULL,    2, true },
   { 0xffffffffffffffffULL,    2, true },
   { 0ULL,                     0x7fffffff, true },
   { 1ULL,                     0x7fffffff, true },
   { 2ULL,                     0x7fffffff, true },
   { 0x7fffffffULL,            0x7fffffff, true },
   { 0x80000000ULL,            0x7fffffff, true },
   { 0xffffffffULL,            0x7fffffff, true },
   { 0x100000000ULL,           0x7fffffff, true },
   { 0x200000000ULL,           0x7fffffff, true },
   { 0x7fffffffffffffffULL,    0x7fffffff, true },
   { 0x8000000000000000ULL,    0x7fffffff, true },
   { 0xffffffffffffffffULL,    0x7fffffff, true },
   { 0ULL,                     0x80000000, true },
   { 1ULL,                     0x80000000, true },
   { 2ULL,                     0x80000000, true },
   { 0x7fffffffULL,            0x80000000, true },
   { 0x80000000ULL,            0x80000000, true },
   { 0xffffffffULL,            0x80000000, true },
   { 0x100000000ULL,           0x80000000, true },
   { 0x200000000ULL,           0x80000000, true },
   { 0x7fffffffffffffffULL,    0x80000000, true },
   { 0x8000000000000000ULL,    0x80000000, true },
   { 0xffffffffffffffffULL,    0x80000000, true },
   { 0ULL,                     0xffffffff, true },
   { 1ULL,                     0xffffffff, true },
   { 2ULL,                     0xffffffff, true },
   { 0x7fffffffULL,            0xffffffff, true },
   { 0x80000000ULL,            0xffffffff, true },
   { 0xffffffffULL,            0xffffffff, true },
   { 0x100000000ULL,           0xffffffff, true },
   { 0x200000000ULL,           0xffffffff, true },
   { 0x7fffffffffffffffULL,    0xffffffff, true },
   { 0x8000000000000000ULL,    0xffffffff, true },
   { 0xffffffffffffffffULL,    0xffffffff, true },
};void DivVerifyUint64Uint32(){   size_t i;   for( i = 0; i < sizeof(uint64_uint32)/sizeof(uint64_uint32[0]); ++i )   {      unsigned __int64 ret;      if( SafeDivide(uint64_uint32[i].x, uint64_uint32[i].y, ret) != uint64_uint32[i].fExpected )      {         //assert(false);         cerr << "Error in case uint64_uint32: " << uint64_uint32[i].x << ", " << uint64_uint32[i].y;         cerr << ", expected = " << (uint64_uint32[i].fExpected ? "true" : "false") << endl;      }      // Now test throwing version      bool fSuccess = true;      try      {         SafeInt<unsigned __int64> si(uint64_uint32[i].x);         si /= uint64_uint32[i].y;      }      catch(...)      {         fSuccess = false;      }      if( fSuccess != uint64_uint32[i].fExpected )      {         cerr << "Error in case uint64_uint32: " << uint64_uint32[i].x << ", " << uint64_uint32[i].y;         cerr << ", expected = " << (uint64_uint32[i].fExpected ? "true" : "false") << endl;      }      // Also need to test the version that assigns back out      // to a plain int, as it has different logic      fSuccess = true;      try      {         unsigned __int64 x(uint64_uint32[i].x);         x /= SafeInt<unsigned __int32>(uint64_uint32[i].y);      }      catch(...)      {         fSuccess = false;      }      if( fSuccess != uint64_uint32[i].fExpected )      {         cerr << "Error in case uint64_uint32: " << uint64_uint32[i].x << ", " << uint64_uint32[i].y;         cerr << ", expected = " << (uint64_uint32[i].fExpected ? "true" : "false") << endl;      }   }}DivTest< unsigned __int64, unsigned __int16 > uint64_uint16[] = 
{   { 0,                     0, false },   { 1,                     0, false },   { 2,                     0, false },   { 0x7fffffffULL,            0, false },
   { 0x80000000ULL,            0, false },
   { 0xffffffffULL,            0, false },
   { 0x100000000ULL,           0, false },
   { 0x200000000ULL,           0, false },
   { 0x7fffffffffffffffULL,    0, false },
   { 0x8000000000000000ULL,    0, false },
   { 0xffffffffffffffffULL,    0, false },
   { 0,                     1, true },   { 1,                     1, true },   { 2,                     1, true },   { 0x7fffffffULL,            1, true },
   { 0x80000000ULL,            1, true },
   { 0xffffffffULL,            1, true },
   { 0x100000000ULL,           1, true },
   { 0x200000000ULL,           1, true },
   { 0x7fffffffffffffffULL,    1, true },
   { 0x8000000000000000ULL,    1, true },
   { 0xffffffffffffffffULL,    1, true },
   { 0,                     2, true },   { 1,                     2, true },   { 2,                     2, true },   { 0x7fffffffULL,            2, true },
   { 0x80000000ULL,            2, true },
   { 0xffffffffULL,            2, true },
   { 0x100000000ULL,           2, true },
   { 0x200000000ULL,           2, true },
   { 0x7fffffffffffffffULL,    2, true },
   { 0x8000000000000000ULL,    2, true },
   { 0xffffffffffffffffULL,    2, true },
};void DivVerifyUint64Uint16(){   size_t i;   for( i = 0; i < sizeof(uint64_uint16)/sizeof(uint64_uint16[0]); ++i )   {      unsigned __int64 ret;      if( SafeDivide(uint64_uint16[i].x, uint64_uint16[i].y, ret) != uint64_uint16[i].fExpected )      {         //assert(false);         cerr << "Error in case uint64_uint16: " << uint64_uint16[i].x << ", " << uint64_uint16[i].y;         cerr << ", expected = " << (uint64_uint16[i].fExpected ? "true" : "false") << endl;      }      // Now test throwing version      bool fSuccess = true;      try      {         SafeInt<unsigned __int64> si(uint64_uint16[i].x);         si /= uint64_uint16[i].y;      }      catch(...)      {         fSuccess = false;      }      if( fSuccess != uint64_uint16[i].fExpected )      {         cerr << "Error in case uint64_uint16: " << uint64_uint16[i].x << ", " << uint64_uint16[i].y;         cerr << ", expected = " << (uint64_uint16[i].fExpected ? "true" : "false") << endl;      }      // Also need to test the version that assigns back out      // to a plain int, as it has different logic      fSuccess = true;      try      {         unsigned __int64 x(uint64_uint16[i].x);         x /= SafeInt<unsigned __int16>(uint64_uint16[i].y);      }      catch(...)      {         fSuccess = false;      }      if( fSuccess != uint64_uint16[i].fExpected )      {         cerr << "Error in case uint64_uint16: " << uint64_uint16[i].x << ", " << uint64_uint16[i].y;         cerr << ", expected = " << (uint64_uint16[i].fExpected ? "true" : "false") << endl;      }   }}DivTest< unsigned __int64, unsigned __int8 > uint64_uint8[] = 
{   { 0,                     0, false },   { 1,                     0, false },   { 2,                     0, false },   { 0x7fffffffULL,            0, false },
   { 0x80000000ULL,            0, false },
   { 0xffffffffULL,            0, false },
   { 0x100000000ULL,           0, false },
   { 0x200000000ULL,           0, false },
   { 0x7fffffffffffffffULL,    0, false },
   { 0x8000000000000000ULL,    0, false },
   { 0xffffffffffffffffULL,    0, false },
   { 0,                     1, true },   { 1,                     1, true },   { 2,                     1, true },   { 0x7fffffffULL,            1, true },
   { 0x80000000ULL,            1, true },
   { 0xffffffffULL,            1, true },
   { 0x100000000ULL,           1, true },
   { 0x200000000ULL,           1, true },
   { 0x7fffffffffffffffULL,    1, true },
   { 0x8000000000000000ULL,    1, true },
   { 0xffffffffffffffffULL,    1, true },
   { 0,                     2, true },   { 1,                     2, true },   { 2,                     2, true },   { 0x7fffffffULL,            2, true },
   { 0x80000000ULL,            2, true },
   { 0xffffffffULL,            2, true },
   { 0x100000000ULL,           2, true },
   { 0x200000000ULL,           2, true },
   { 0x7fffffffffffffffULL,    2, true },
   { 0x8000000000000000ULL,    2, true },
   { 0xffffffffffffffffULL,    2, true },
};void DivVerifyUint64Uint8(){   size_t i;   for( i = 0; i < sizeof(uint64_uint8)/sizeof(uint64_uint8[0]); ++i )   {      unsigned __int64 ret;      if( SafeDivide(uint64_uint8[i].x, uint64_uint8[i].y, ret) != uint64_uint8[i].fExpected )      {         cerr << "Error in case uint64_uint8: " << uint64_uint8[i].x << ", " << uint64_uint8[i].y;         cerr << ", expected = " << (uint64_uint8[i].fExpected ? "true" : "false") << endl;      }      // Now test throwing version      bool fSuccess = true;      try      {         SafeInt<unsigned __int64> si(uint64_uint8[i].x);         si /= uint64_uint8[i].y;      }      catch(...)      {         fSuccess = false;      }      if( fSuccess != uint64_uint8[i].fExpected )      {         cerr << "Error in case uint64_uint8: " << uint64_uint8[i].x << ", " << uint64_uint8[i].y;         cerr << ", expected = " << (uint64_uint8[i].fExpected ? "true" : "false") << endl;      }      // Also need to test the version that assigns back out      // to a plain int, as it has different logic      fSuccess = true;      try      {         unsigned __int64 x(uint64_uint8[i].x);         x /= SafeInt<unsigned __int8>(uint64_uint8[i].y);      }      catch(...)      {         fSuccess = false;      }      if( fSuccess != uint64_uint8[i].fExpected )      {         cerr << "Error in case uint64_uint8: " << uint64_uint8[i].x << ", " << uint64_uint8[i].y;         cerr << ", expected = " << (uint64_uint8[i].fExpected ? "true" : "false") << endl;      }   }}// Same problem as unsigned-signed, but anything negative should now fail// There are corner cases in the U op SafeInt<T> path, which has to be tested// individuallyDivTest< unsigned __int64, __int64 > uint64_int64[] = 
{   { 0,                     0, false },   { 1,                     0, false },   { 2,                     0, false },   { 0x7fffffffULL,            0LL, false },
   { 0x80000000ULL,            0LL, false },
   { 0xffffffffULL,            0LL, false },
   { 0x100000000ULL,           0LL, false },
   { 0x200000000ULL,           0LL, false },
   { 0x7fffffffffffffffULL,    0LL, false },
   { 0x8000000000000000ULL,    0LL, false },
   { 0xffffffffffffffffULL,    0LL, false },
   { 0,                     1, true },   { 1,                     1, true },   { 2,                     1, true },   { 0x7fffffffULL,            1LL, true },
   { 0x80000000ULL,            1LL, true },
   { 0xffffffffULL,            1LL, true },
   { 0x100000000ULL,           1LL, true },
   { 0x200000000ULL,           1LL, true },
   { 0x7fffffffffffffffULL,    1LL, true },
   { 0x8000000000000000ULL,    1LL, true },
   { 0xffffffffffffffffULL,    1LL, true },
   { 0,                     2, true },   { 1,                     2, true },   { 2,                     2, true },   { 0x7fffffffULL,            2LL, true },
   { 0x80000000ULL,            2LL, true },
   { 0xffffffffULL,            2LL, true },
   { 0x100000000ULL,           2LL, true },
   { 0x200000000ULL,           2LL, true },
   { 0x7fffffffffffffffULL,    2LL, true },
   { 0x8000000000000000ULL,    2LL, true },
   { 0xffffffffffffffffULL,    2LL, true },
   { 0ULL,                     0x7fffffffLL, true },
   { 1ULL,                     0x7fffffffLL, true },
   { 2ULL,                     0x7fffffffLL, true },
   { 0x7fffffffULL,            0x7fffffffLL, true },
   { 0x80000000ULL,            0x7fffffffLL, true },
   { 0xffffffffULL,            0x7fffffffLL, true },
   { 0x100000000ULL,           0x7fffffffLL, true },
   { 0x200000000ULL,           0x7fffffffLL, true },
   { 0x7fffffffffffffffULL,    0x7fffffffLL, true },
   { 0x8000000000000000ULL,    0x7fffffffLL, true },
   { 0xffffffffffffffffULL,    0x7fffffffLL, true },
   { 0ULL,                     0x80000000LL, true },
   { 1ULL,                     0x80000000LL, true },
   { 2ULL,                     0x80000000LL, true },
   { 0x7fffffffULL,            0x80000000LL, true },
   { 0x80000000ULL,            0x80000000LL, true },
   { 0xffffffffULL,            0x80000000LL, true },
   { 0x100000000ULL,           0x80000000LL, true },
   { 0x200000000ULL,           0x80000000LL, true },
   { 0x7fffffffffffffffULL,    0x80000000LL, true },
   { 0x8000000000000000ULL,    0x80000000LL, true },
   { 0xffffffffffffffffULL,    0x80000000LL, true },
   { 0ULL,                     0xffffffffLL, true },
   { 1ULL,                     0xffffffffLL, true },
   { 2ULL,                     0xffffffffLL, true },
   { 0x7fffffffULL,            0xffffffffLL, true },
   { 0x80000000ULL,            0xffffffffLL, true },
   { 0xffffffffULL,            0xffffffffLL, true },
   { 0x100000000ULL,           0xffffffffLL, true },
   { 0x200000000ULL,           0xffffffffLL, true },
   { 0x7fffffffffffffffULL,    0xffffffffLL, true },
   { 0x8000000000000000ULL,    0xffffffffLL, true },
   { 0xffffffffffffffffULL,    0xffffffffLL, true },
   { 0ULL,                     0x100000000LL, true },
   { 1ULL,                     0x100000000LL, true },
   { 2ULL,                     0x100000000LL, true },
   { 0x7fffffffULL,            0x100000000LL, true },
   { 0x80000000ULL,            0x100000000LL, true },
   { 0xffffffffULL,            0x100000000LL, true },
   { 0x100000000ULL,           0x100000000LL, true },
   { 0x200000000ULL,           0x100000000LL, true },
   { 0x7fffffffffffffffULL,    0x100000000LL, true },
   { 0x8000000000000000ULL,    0x100000000LL, true },
   { 0xffffffffffffffffULL,    0x100000000LL, true },
   { 0ULL,                     0x200000000LL, true },
   { 1ULL,                     0x200000000LL, true },
   { 2ULL,                     0x200000000LL, true },
   { 0x7fffffffULL,            0x200000000LL, true },
   { 0x80000000ULL,            0x200000000LL, true },
   { 0xffffffffULL,            0x200000000LL, true },
   { 0x100000000ULL,           0x200000000LL, true },
   { 0x200000000ULL,           0x200000000LL, true },
   { 0x7fffffffffffffffULL,    0x200000000LL, true },
   { 0x8000000000000000ULL,    0x200000000LL, true },
   { 0xffffffffffffffffULL,    0x200000000LL, true },
   { 0ULL,                     0x7fffffffffffffffLL, true },
   { 1ULL,                     0x7fffffffffffffffLL, true },
   { 2ULL,                     0x7fffffffffffffffLL, true },
   { 0x7fffffffULL,            0x7fffffffffffffffLL, true },
   { 0x80000000ULL,            0x7fffffffffffffffLL, true },
   { 0xffffffffULL,            0x7fffffffffffffffLL, true },
   { 0x100000000ULL,           0x7fffffffffffffffLL, true },
   { 0x200000000ULL,           0x7fffffffffffffffLL, true },
   { 0x7fffffffffffffffULL,    0x7fffffffffffffffLL, true },
   { 0x8000000000000000ULL,    0x7fffffffffffffffLL, true },
   { 0xffffffffffffffffULL,    0x7fffffffffffffffLL, true },
   { 0ULL,                     0x8000000000000000LL, true },
   { 1ULL,                     0x8000000000000000LL, true },
   { 2ULL,                     0x8000000000000000LL, true },
   { 0x7fffffffULL,            0x8000000000000000LL, true },
   { 0x80000000ULL,            0x8000000000000000LL, true },
   { 0xffffffffULL,            0x8000000000000000LL, true },
   { 0x100000000ULL,           0x8000000000000000LL, true },
   { 0x200000000ULL,           0x8000000000000000LL, true },
   { 0x7fffffffffffffffULL,    0x8000000000000000LL, true },
   { 0x8000000000000000ULL,    0x8000000000000000LL, false },
   { 0xffffffffffffffffULL,    0x8000000000000000LL, false },
   { 0ULL,                     0xffffffffffffffffLL, true },
   { 1ULL,                     0xffffffffffffffffLL, false },
   { 2ULL,                     0xffffffffffffffffLL, false },
   { 0x7fffffffULL,            0xffffffffffffffffLL, false },
   { 0x80000000ULL,            0xffffffffffffffffLL, false },
   { 0xffffffffULL,            0xffffffffffffffffLL, false },
   { 0x100000000ULL,           0xffffffffffffffffLL, false },
   { 0x200000000ULL,           0xffffffffffffffffLL, false },
   { 0x7fffffffffffffffULL,    0xffffffffffffffffLL, false },
   { 0x8000000000000000ULL,    0xffffffffffffffffLL, false },
   { 0xffffffffffffffffULL,    0xffffffffffffffffLL, false },
};void DivVerifyUint64Int64(){   size_t i;   for( i = 0; i < sizeof(uint64_int64)/sizeof(uint64_int64[0]); ++i )   {      unsigned __int64 ret;      if( SafeDivide(uint64_int64[i].x, uint64_int64[i].y, ret) != uint64_int64[i].fExpected )      {         cerr << "Error in case uint64_int64: " << uint64_int64[i].x << ", " << uint64_int64[i].y;         cerr << ", expected = " << (uint64_int64[i].fExpected ? "true" : "false") << endl;      }      // Now test throwing version      bool fSuccess = true;      try      {         SafeInt<unsigned __int64> si(uint64_int64[i].x);         si /= uint64_int64[i].y;      }      catch(...)      {         fSuccess = false;      }      if( fSuccess != uint64_int64[i].fExpected )      {         cerr << "Error in case uint64_int64: " << uint64_int64[i].x << ", " << uint64_int64[i].y;         cerr << ", expected = " << (uint64_int64[i].fExpected ? "true" : "false") << endl;      }      // Also need to test the version that assigns back out      // to a plain int, as it has different logic      fSuccess = true;      try      {         unsigned __int64 x(uint64_int64[i].x);         x /= SafeInt<__int64>(uint64_int64[i].y);      }      catch(...)      {         fSuccess = false;      }      if( fSuccess != uint64_int64[i].fExpected )      {         cerr << "Error in case uint64_int64: " << uint64_int64[i].x << ", " << uint64_int64[i].y;         cerr << ", expected = " << (uint64_int64[i].fExpected ? "true" : "false") << endl;      }   }}DivTest< __int64, unsigned __int64 > int64_uint64_2[] = 
{   { 0,                     0, false },   { 1,                     0, true },   { 2,                     0, true },   { 0x7fffffffLL,            0ULL, true },
   { 0x80000000LL,            0ULL, true },
   { 0xffffffffLL,            0ULL, true },
   { 0x100000000LL,           0ULL, true },
   { 0x200000000LL,           0ULL, true },
   { 0x7fffffffffffffffLL,    0ULL, true },
   { 0x8000000000000000LL,    0ULL, true },
   { 0xffffffffffffffffLL,    0ULL, true },
   { 0,                     1, false },   { 1,                     1, true },   { 2,                     1, true },   { 0x7fffffffLL,            1ULL, true },
   { 0x80000000LL,            1ULL, true },
   { 0xffffffffLL,            1ULL, true },
   { 0x100000000LL,           1ULL, true },
   { 0x200000000LL,           1ULL, true },
   { 0x7fffffffffffffffLL,    1ULL, true },
   { 0x8000000000000000LL,    1ULL, true },
   { 0xffffffffffffffffLL,    1ULL, true },
   { 0,                     2, false },   { 1,                     2, true },   { 2,                     2, true },   { 0x7fffffffLL,            2ULL, true },
   { 0x80000000LL,            2ULL, true },
   { 0xffffffffLL,            2ULL, true },
   { 0x100000000LL,           2ULL, true },
   { 0x200000000LL,           2ULL, true },
   { 0x7fffffffffffffffLL,    2ULL, true },
   { 0x8000000000000000LL,    2ULL, true },
   { 0xffffffffffffffffLL,    2ULL, true },
   { 0LL,                     0x7fffffffULL, false },
   { 1LL,                     0x7fffffffULL, true },
   { 2LL,                     0x7fffffffULL, true },
   { 0x7fffffffLL,            0x7fffffffULL, true },
   { 0x80000000LL,            0x7fffffffULL, true },
   { 0xffffffffLL,            0x7fffffffULL, true },
   { 0x100000000LL,           0x7fffffffULL, true },
   { 0x200000000LL,           0x7fffffffULL, true },
   { 0x7fffffffffffffffLL,    0x7fffffffULL, true },
   { 0x8000000000000000LL,    0x7fffffffULL, true },
   { 0xffffffffffffffffLL,    0x7fffffffULL, true },
   { 0LL,                     0x80000000ULL, false },
   { 1LL,                     0x80000000ULL, true },
   { 2LL,                     0x80000000ULL, true },
   { 0x7fffffffLL,            0x80000000ULL, true },
   { 0x80000000LL,            0x80000000ULL, true },
   { 0xffffffffLL,            0x80000000ULL, true },
   { 0x100000000LL,           0x80000000ULL, true },
   { 0x200000000LL,           0x80000000ULL, true },
   { 0x7fffffffffffffffLL,    0x80000000ULL, true },
   { 0x8000000000000000LL,    0x80000000ULL, true },
   { 0xffffffffffffffffLL,    0x80000000ULL, true },
   { 0LL,                     0xffffffffULL, false },
   { 1LL,                     0xffffffffULL, true },
   { 2LL,                     0xffffffffULL, true },
   { 0x7fffffffLL,            0xffffffffULL, true },
   { 0x80000000LL,            0xffffffffULL, true },
   { 0xffffffffLL,            0xffffffffULL, true },
   { 0x100000000LL,           0xffffffffULL, true },
   { 0x200000000LL,           0xffffffffULL, true },
   { 0x7fffffffffffffffLL,    0xffffffffULL, true },
   { 0x8000000000000000LL,    0xffffffffULL, true },
   { 0xffffffffffffffffLL,    0xffffffffULL, true },
   { 0LL,                     0x100000000ULL, false },
   { 1LL,                     0x100000000ULL, true },
   { 2LL,                     0x100000000ULL, true },
   { 0x7fffffffLL,            0x100000000ULL, true },
   { 0x80000000LL,            0x100000000ULL, true },
   { 0xffffffffLL,            0x100000000ULL, true },
   { 0x100000000LL,           0x100000000ULL, true },
   { 0x200000000LL,           0x100000000ULL, true },
   { 0x7fffffffffffffffLL,    0x100000000ULL, true },
   { 0x8000000000000000LL,    0x100000000ULL, true },
   { 0xffffffffffffffffLL,    0x100000000ULL, true },
   { 0LL,                     0x200000000ULL, false },
   { 1LL,                     0x200000000ULL, true },
   { 2LL,                     0x200000000ULL, true },
   { 0x7fffffffLL,            0x200000000ULL, true },
   { 0x80000000LL,            0x200000000ULL, true },
   { 0xffffffffLL,            0x200000000ULL, true },
   { 0x100000000LL,           0x200000000ULL, true },
   { 0x200000000LL,           0x200000000ULL, true },
   { 0x7fffffffffffffffLL,    0x200000000ULL, true },
   { 0x8000000000000000LL,    0x200000000ULL, true },
   { 0xffffffffffffffffLL,    0x200000000ULL, true },
   { 0LL,                     0x7fffffffffffffffULL, false },
   { 1LL,                     0x7fffffffffffffffULL, true },
   { 2LL,                     0x7fffffffffffffffULL, true },
   { 0x7fffffffLL,            0x7fffffffffffffffULL, true },
   { 0x80000000LL,            0x7fffffffffffffffULL, true },
   { 0xffffffffLL,            0x7fffffffffffffffULL, true },
   { 0x100000000LL,           0x7fffffffffffffffULL, true },
   { 0x200000000LL,           0x7fffffffffffffffULL, true },
   { 0x7fffffffffffffffLL,    0x7fffffffffffffffULL, true },
   { 0x8000000000000000LL,    0x7fffffffffffffffULL, true },
   { 0xffffffffffffffffLL,    0x7fffffffffffffffULL, true },
   { 0LL,                     0x8000000000000000ULL, false },
   { 1LL,                     0x8000000000000000ULL, false },
   { 2LL,                     0x8000000000000000ULL, true },
   { 0x7fffffffLL,            0x8000000000000000ULL, true },
   { 0x80000000LL,            0x8000000000000000ULL, true },
   { 0xffffffffLL,            0x8000000000000000ULL, true },
   { 0x100000000LL,           0x8000000000000000ULL, true },
   { 0x200000000LL,           0x8000000000000000ULL, true },
   { 0x7fffffffffffffffLL,    0x8000000000000000ULL, true },
   { 0x8000000000000000LL,    0x8000000000000000ULL, true },
   { 0xffffffffffffffffLL,    0x8000000000000000ULL, true },
   { 0LL,                     0xffffffffffffffffULL, false },
   { 1LL,                     0xffffffffffffffffULL, false },
   { 2LL,                     0xffffffffffffffffULL, true },
   { 0x7fffffffLL,            0xffffffffffffffffULL, true },
   { 0x80000000LL,            0xffffffffffffffffULL, true },
   { 0xffffffffLL,            0xffffffffffffffffULL, true },
   { 0x100000000LL,           0xffffffffffffffffULL, true },
   { 0x200000000LL,           0xffffffffffffffffULL, true },
   { 0x7fffffffffffffffLL,    0xffffffffffffffffULL, true },
   { 0x8000000000000000LL,    0xffffffffffffffffULL, true },
   { 0xffffffffffffffffLL,    0xffffffffffffffffULL, false },
};void DivVerifyUint64Int64_2(){   size_t i;   for( i = 0; i < sizeof(int64_uint64_2)/sizeof(int64_uint64_2[0]); ++i )   {      // Now test throwing version      bool fSuccess = true;      try      {         SafeInt<__int64> si(int64_uint64_2[i].x);         SafeInt<__int64> si2;         si2 = int64_uint64_2[i].y / si;      }      catch(...)      {         fSuccess = false;      }      if( fSuccess != int64_uint64_2[i].fExpected )      {         cerr << "Error in case int64_uint64_2: " << int64_uint64_2[i].x << ", " << int64_uint64_2[i].y;         cerr << ", expected = " << (int64_uint64_2[i].fExpected ? "true" : "false") << endl;      }   }}DivTest< unsigned __int64, __int32 > uint64_int32[] = 
{   { 0,                     0, false },   { 1,                     0, false },   { 2,                     0, false },   { 0x7fffffffULL,            0, false },
   { 0x80000000ULL,            0, false },
   { 0xffffffffULL,            0, false },
   { 0x100000000ULL,           0, false },
   { 0x200000000ULL,           0, false },
   { 0x7fffffffffffffffULL,    0, false },
   { 0x8000000000000000ULL,    0, false },
   { 0xffffffffffffffffULL,    0, false },
   { 0,                     1, true },   { 1,                     1, true },   { 2,                     1, true },   { 0x7fffffffULL,            1, true },
   { 0x80000000ULL,            1, true },
   { 0xffffffffULL,            1, true },
   { 0x100000000ULL,           1, true },
   { 0x200000000ULL,           1, true },
   { 0x7fffffffffffffffULL,    1, true },
   { 0x8000000000000000ULL,    1, true },
   { 0xffffffffffffffffULL,    1, true },
   { 0,                     2, true },   { 1,                     2, true },   { 2,                     2, true },   { 0x7fffffffULL,            2, true },
   { 0x80000000ULL,            2, true },
   { 0xffffffffULL,            2, true },
   { 0x100000000ULL,           2, true },
   { 0x200000000ULL,           2, true },
   { 0x7fffffffffffffffULL,    2, true },
   { 0x8000000000000000ULL,    2, true },
   { 0xffffffffffffffffULL,    2, true },
   { 0ULL,                     0x7fffffff, true },
   { 1ULL,                     0x7fffffff, true },
   { 2ULL,                     0x7fffffff, true },
   { 0x7fffffffULL,            0x7fffffff, true },
   { 0x80000000ULL,            0x7fffffff, true },
   { 0xffffffffULL,            0x7fffffff, true },
   { 0x100000000ULL,           0x7fffffff, true },
   { 0x200000000ULL,           0x7fffffff, true },
   { 0x7fffffffffffffffULL,    0x7fffffff, true },
   { 0x8000000000000000ULL,    0x7fffffff, true },
   { 0xffffffffffffffffULL,    0x7fffffff, true },
   { 0ULL,                     0x80000000, true },
   { 1ULL,                     0x80000000, true },
   { 2ULL,                     0x80000000, true },
   { 0x7fffffffULL,            0x80000000, true },
   { 0x80000000ULL,            0x80000000, false },
   { 0xffffffffULL,            0x80000000, false },
   { 0x100000000ULL,           0x80000000, false },
   { 0x200000000ULL,           0x80000000, false },
   { 0x7fffffffffffffffULL,    0x80000000, false },
   { 0x8000000000000000ULL,    0x80000000, false },
   { 0xffffffffffffffffULL,    0x80000000, false },
   { 0ULL,                     0xffffffff, true },
   { 1ULL,                     0xffffffff, false },
   { 2ULL,                     0xffffffff, false },
   { 0x7fffffffULL,            0xffffffff, false },
   { 0x80000000ULL,            0xffffffff, false },
   { 0xffffffffULL,            0xffffffff, false },
   { 0x100000000ULL,           0xffffffff, false },
   { 0x200000000ULL,           0xffffffff, false },
   { 0x7fffffffffffffffULL,    0xffffffff, false },
   { 0x8000000000000000ULL,    0xffffffff, false },
   { 0xffffffffffffffffULL,    0xffffffff, false },
};void DivVerifyUint64Int32(){   size_t i;   for( i = 0; i < sizeof(uint64_int32)/sizeof(uint64_int32[0]); ++i )   {      unsigned __int64 ret;      if( SafeDivide(uint64_int32[i].x, uint64_int32[i].y, ret) != uint64_int32[i].fExpected )      {         cerr << "Error in case uint64_int32: " << uint64_int32[i].x << ", " << uint64_int32[i].y;         cerr << ", expected = " << (uint64_int32[i].fExpected ? "true" : "false") << endl;      }      // Now test throwing version      bool fSuccess = true;      try      {         SafeInt<unsigned __int64> si(uint64_int32[i].x);         si /= uint64_int32[i].y;      }      catch(...)      {         fSuccess = false;      }      if( fSuccess != uint64_int32[i].fExpected )      {         cerr << "Error in case uint64_int32: " << uint64_int32[i].x << ", " << uint64_int32[i].y;         cerr << ", expected = " << (uint64_int32[i].fExpected ? "true" : "false") << endl;      }      // Also need to test the version that assigns back out      // to a plain int, as it has different logic      fSuccess = true;      try      {         unsigned __int64 x(uint64_int32[i].x);         x /= SafeInt<__int64>(uint64_int32[i].y);      }      catch(...)      {         fSuccess = false;      }      if( fSuccess != uint64_int32[i].fExpected )      {         cerr << "Error in case uint64_int32: " << uint64_int32[i].x << ", " << uint64_int32[i].y;         cerr << ", expected = " << (uint64_int32[i].fExpected ? "true" : "false") << endl;      }   }}DivTest< __int32, unsigned __int64 > int32_uint64_2[] = 
{   { 0,                     0, false },   { 1,                     0, true },   { 2,                     0, true },   { 0x7fffffff,            0ULL, true },
   { 0x80000000,            0ULL, true },
   { 0xffffffff,            0ULL, true },
   { 0,                     1, false },   { 1,                     1, true },   { 2,                     1, true },   { 0x7fffffff,            1ULL, true },
   { 0x80000000,            1ULL, true },
   { 0xffffffff,            1ULL, true },
   { 0,                     2, false },   { 1,                     2, true },   { 2,                     2, true },   { 0x7fffffff,            2ULL, true },
   { 0x80000000,            2ULL, true },
   { 0xffffffff,            2ULL, true },
   { 0,                     0x7fffffffULL, false },
   { 1,                     0x7fffffffULL, true },
   { 2,                     0x7fffffffULL, true },
   { 0x7fffffff,            0x7fffffffULL, true },
   { 0x80000000,            0x7fffffffULL, true },
   { 0xffffffff,            0x7fffffffULL, true },
   { 0,                     0x80000000ULL, false },
   { 1,                     0x80000000ULL, false },
   { 2,                     0x80000000ULL, true },
   { 0x7fffffff,            0x80000000ULL, true },
   { 0x80000000,            0x80000000ULL, true },
   { 0xffffffff,            0x80000000ULL, true },
   { 0,                     0xffffffffULL, false },
   { 1,                     0xffffffffULL, false },
   { 2,                     0xffffffffULL, true },
   { 0x7fffffff,            0xffffffffULL, true },
   { 0x80000000,            0xffffffffULL, true },
   { 0xffffffff,            0xffffffffULL, false },
   { 0,                     0x100000000ULL, false },
   { 1,                     0x100000000ULL, false },
   { 2,                     0x100000000ULL, false },
   { 0x7fffffff,            0x100000000ULL, true },
   { 0x80000000,            0x100000000ULL, true },
   { 0xffffffff,            0x100000000ULL, false },
   { 0,                     0x200000000ULL, false },
   { 1,                     0x200000000ULL, false },
   { 2,                     0x200000000ULL, false },
   { 0x7fffffff,            0x200000000ULL, true },
   { 0x80000000,            0x200000000ULL, true },
   { 0xffffffff,            0x200000000ULL, false },
   { 0,                     0x7fffffffffffffffULL, false },
   { 1,                     0x7fffffffffffffffULL, false },
   { 2,                     0x7fffffffffffffffULL, false },
   { 0x7fffffff,            0x7fffffffffffffffULL, false },
   { 0x80000000,            0x7fffffffffffffffULL, false },
   { 0xffffffff,            0x7fffffffffffffffULL, false },
   { 0,                     0x8000000000000000ULL, false },
   { 1,                     0x8000000000000000ULL, false },
   { 2,                     0x8000000000000000ULL, false },
   { 0x7fffffff,            0x8000000000000000ULL, false },
   { 0x80000000,            0x8000000000000000ULL, false },
   { 0xffffffff,            0x8000000000000000ULL, false },
   { 0,                     0xffffffffffffffffULL, false },
   { 1,                     0xffffffffffffffffULL, false },
   { 2,                     0xffffffffffffffffULL, false },
   { 0x7fffffff,            0xffffffffffffffffULL, false },
   { 0x80000000,            0xffffffffffffffffULL, false },
   { 0xffffffff,            0xffffffffffffffffULL, false },
};void DivVerifyUint64Int32_2(){   size_t i;   for( i = 0; i < sizeof(int32_uint64_2)/sizeof(int32_uint64_2[0]); ++i )   {      // Now test throwing version      bool fSuccess = true;      try      {         SafeInt<__int32> si(int32_uint64_2[i].x);         SafeInt<__int32> si2;         si2 = int32_uint64_2[i].y / si;      }      catch(...)      {         fSuccess = false;      }      if( fSuccess != int32_uint64_2[i].fExpected )      {         cerr << "Error in case int32_uint64_2: " << int32_uint64_2[i].x << ", " << int32_uint64_2[i].y;         cerr << ", expected = " << (int32_uint64_2[i].fExpected ? "true" : "false") << endl;      }   }}DivTest< unsigned __int64, __int16 > uint64_int16[] = 
{   { 0,                     0, false },   { 1,                     0, false },   { 2,                     0, false },   { 0x7fffffffULL,            0, false },
   { 0x80000000ULL,            0, false },
   { 0xffffffffULL,            0, false },
   { 0x100000000ULL,           0, false },
   { 0x200000000ULL,           0, false },
   { 0x7fffffffffffffffULL,    0, false },
   { 0x8000000000000000ULL,    0, false },
   { 0xffffffffffffffffULL,    0, false },
   { 0,                     1, true },   { 1,                     1, true },   { 2,                     1, true },   { 0x7fffffffULL,            1, true },
   { 0x80000000ULL,            1, true },
   { 0xffffffffULL,            1, true },
   { 0x100000000ULL,           1, true },
   { 0x200000000ULL,           1, true },
   { 0x7fffffffffffffffULL,    1, true },
   { 0x8000000000000000ULL,    1, true },
   { 0xffffffffffffffffULL,    1, true },
   { 0,                     2, true },   { 1,                     2, true },   { 2,                     2, true },   { 0x7fffffffULL,            2, true },
   { 0x80000000ULL,            2, true },
   { 0xffffffffULL,            2, true },
   { 0x100000000ULL,           2, true },
   { 0x200000000ULL,           2, true },
   { 0x7fffffffffffffffULL,    2, true },
   { 0x8000000000000000ULL,    2, true },
   { 0xffffffffffffffffULL,    2, true },
   { 0,                     -1, true },   { 1,                     -1, false },   { 2,                     -1, false },   { 0x7fffffffULL,            -1, false },
   { 0x80000000ULL,            -1, false },
   { 0xffffffffULL,            -1, false },
   { 0x100000000ULL,           -1, false },
   { 0x200000000ULL,           -1, false },
   { 0x7fffffffffffffffULL,    -1, false },
   { 0x8000000000000000ULL,    -1, false },
   { 0xffffffffffffffffULL,    -1, false },
};void DivVerifyUint64Int16(){   size_t i;   for( i = 0; i < sizeof(uint64_int16)/sizeof(uint64_int16[0]); ++i )   {      unsigned __int64 ret;      if( SafeDivide(uint64_int16[i].x, uint64_int16[i].y, ret) != uint64_int16[i].fExpected )      {         cerr << "Error in case uint64_int16: " << uint64_int16[i].x << ", " << uint64_int16[i].y;         cerr << ", expected = " << (uint64_int16[i].fExpected ? "true" : "false") << endl;      }      // Now test throwing version      bool fSuccess = true;      try      {         SafeInt<unsigned __int64> si(uint64_int16[i].x);         si /= uint64_int16[i].y;      }      catch(...)      {         fSuccess = false;      }      if( fSuccess != uint64_int16[i].fExpected )      {         cerr << "Error in case uint64_int16: " << uint64_int16[i].x << ", " << uint64_int16[i].y;         cerr << ", expected = " << (uint64_int16[i].fExpected ? "true" : "false") << endl;      }      // Also need to test the version that assigns back out      // to a plain int, as it has different logic      fSuccess = true;      try      {         unsigned __int64 x(uint64_int16[i].x);         x /= SafeInt<__int64>(uint64_int16[i].y);      }      catch(...)      {         fSuccess = false;      }      if( fSuccess != uint64_int16[i].fExpected )      {         cerr << "Error in case uint64_int16: " << uint64_int16[i].x << ", " << uint64_int16[i].y;         cerr << ", expected = " << (uint64_int16[i].fExpected ? "true" : "false") << endl;      }   }}DivTest< __int16, unsigned __int64 > int16_uint64_2[] = 
{   { 0,                     0, false },   { 1,                     0, true },   { 2,                     0, true },   { 0x7fff,                0ULL, true },
   { 0x8000,                0ULL, true },
   { 0xffff,                0ULL, true },
   { 0,                     1, false },   { 1,                     1, true },   { 2,                     1, true },   { 0x7fff,                1ULL, true },
   { 0x8000,                1ULL, true },
   { 0xffff,                1ULL, true },
   { 0,                     2, false },   { 1,                     2, true },   { 2,                     2, true },   { 0x7fff,                2ULL, true },
   { 0x8000,                2ULL, true },
   { 0xffff,                2ULL, true },
   { 0,                     0x7fffffffULL, false },
   { 1,                     0x7fffffffULL, true },
   { 2,                     0x7fffffffULL, true },
   { 0x7fff,                0x7fffffffULL, true },
   { 0x8000,                0x7fffffffULL, true },
   { 0xffff,                0x7fffffffULL, true },
   { 0,                     0x80000000ULL, false },
   { 1,                     0x80000000ULL, false },
   { 2,                     0x80000000ULL, true },
   { 0x7fff,                0x80000000ULL, true },
   { 0x8000,                0x80000000ULL, true },
   { 0xffff,                0x80000000ULL, true },
   { 0,                     0xffffffffULL, false },
   { 1,                     0xffffffffULL, false },
   { 2,                     0xffffffffULL, true },
   { 0x7fff,                0xffffffffULL, true },
   { 0x8000,                0xffffffffULL, true },
   { 0xffff,                0xffffffffULL, false },
   { 0,                     0x100000000ULL, false },
   { 1,                     0x100000000ULL, false },
   { 2,                     0x100000000ULL, false },
   { 0x7fff,                0x100000000ULL, true },
   { 0x8000,                0x100000000ULL, true },
   { 0xffff,                0x100000000ULL, false },
   { 0,                     0x200000000ULL, false },
   { 1,                     0x200000000ULL, false },
   { 2,                     0x200000000ULL, false },
   { 0x7fff,                0x200000000ULL, true },
   { 0x8000,                0x200000000ULL, true },
   { 0xffff,                0x200000000ULL, false },
   { 0,                     0x7fffffffffffffffULL, false },
   { 1,                     0x7fffffffffffffffULL, false },
   { 2,                     0x7fffffffffffffffULL, false },
   { 0x7fff,                0x7fffffffffffffffULL, false },
   { 0x8000,                0x7fffffffffffffffULL, false },
   { 0xffff,                0x7fffffffffffffffULL, false },
   { 0,                     0x8000000000000000ULL, false },
   { 1,                     0x8000000000000000ULL, false },
   { 2,                     0x8000000000000000ULL, false },
   { 0x7fff,                0x8000000000000000ULL, false },
   { 0x8000,                0x8000000000000000ULL, false },
   { 0xffff,                0x8000000000000000ULL, false },
   { 0,                     0xffffffffffffffffULL, false },
   { 1,                     0xffffffffffffffffULL, false },
   { 2,                     0xffffffffffffffffULL, false },
   { 0x7fff,                0xffffffffffffffffULL, false },
   { 0x8000,                0xffffffffffffffffULL, false },
   { 0xffff,                0xffffffffffffffffULL, false },
};void DivVerifyUint64Int16_2(){   size_t i;   for( i = 0; i < sizeof(int16_uint64_2)/sizeof(int16_uint64_2[0]); ++i )   {      // Now test throwing version      bool fSuccess = true;      try      {         SafeInt<__int32> si(int16_uint64_2[i].x);         SafeInt<__int32> si2;         si2 = int16_uint64_2[i].y / si;      }      catch(...)      {         fSuccess = false;      }      if( fSuccess != int16_uint64_2[i].fExpected )      {         cerr << "Error in case int16_uint64_2: " << int16_uint64_2[i].x << ", " << int16_uint64_2[i].y;         cerr << ", expected = " << (int16_uint64_2[i].fExpected ? "true" : "false") << endl;      }   }}DivTest< unsigned __int64, __int8 > uint64_int8[] = 
{   { 0,                     0, false },   { 1,                     0, false },   { 2,                     0, false },   { 0x7fffffffULL,            0, false },
   { 0x80000000ULL,            0, false },
   { 0xffffffffULL,            0, false },
   { 0x100000000ULL,           0, false },
   { 0x200000000ULL,           0, false },
   { 0x7fffffffffffffffULL,    0, false },
   { 0x8000000000000000ULL,    0, false },
   { 0xffffffffffffffffULL,    0, false },
   { 0,                     1, true },   { 1,                     1, true },   { 2,                     1, true },   { 0x7fffffffULL,            1, true },
   { 0x80000000ULL,            1, true },
   { 0xffffffffULL,            1, true },
   { 0x100000000ULL,           1, true },
   { 0x200000000ULL,           1, true },
   { 0x7fffffffffffffffULL,    1, true },
   { 0x8000000000000000ULL,    1, true },
   { 0xffffffffffffffffULL,    1, true },
   { 0,                     2, true },   { 1,                     2, true },   { 2,                     2, true },   { 0x7fffffffULL,            2, true },
   { 0x80000000ULL,            2, true },
   { 0xffffffffULL,            2, true },
   { 0x100000000ULL,           2, true },
   { 0x200000000ULL,           2, true },
   { 0x7fffffffffffffffULL,    2, true },
   { 0x8000000000000000ULL,    2, true },
   { 0xffffffffffffffffULL,    2, true },
   { 0,                     -1, true },   { 1,                     -1, false },   { 2,                     -1, false },   { 0x7fffffffULL,            -1, false },
   { 0x80000000ULL,            -1, false },
   { 0xffffffffULL,            -1, false },
   { 0x100000000ULL,           -1, false },
   { 0x200000000ULL,           -1, false },
   { 0x7fffffffffffffffULL,    -1, false },
   { 0x8000000000000000ULL,    -1, false },
   { 0xffffffffffffffffULL,    -1, false },
};void DivVerifyUint64Int8(){   size_t i;   for( i = 0; i < sizeof(uint64_int8)/sizeof(uint64_int8[0]); ++i )   {      unsigned __int64 ret;      if( SafeDivide(uint64_int8[i].x, uint64_int8[i].y, ret) != uint64_int8[i].fExpected )      {         cerr << "Error in case uint64_int8: " << uint64_int8[i].x << ", " << uint64_int8[i].y;         cerr << ", expected = " << (uint64_int8[i].fExpected ? "true" : "false") << endl;      }      // Now test throwing version      bool fSuccess = true;      try      {         SafeInt<unsigned __int64> si(uint64_int8[i].x);         si /= uint64_int8[i].y;      }      catch(...)      {         fSuccess = false;      }      if( fSuccess != uint64_int8[i].fExpected )      {         cerr << "Error in case uint64_int8: " << uint64_int8[i].x << ", " << uint64_int8[i].y;         cerr << ", expected = " << (uint64_int8[i].fExpected ? "true" : "false") << endl;      }      // Also need to test the version that assigns back out      // to a plain int, as it has different logic      fSuccess = true;      try      {         unsigned __int64 x(uint64_int8[i].x);         x /= SafeInt<__int64>(uint64_int8[i].y);      }      catch(...)      {         fSuccess = false;      }      if( fSuccess != uint64_int8[i].fExpected )      {         cerr << "Error in case uint64_int8: " << uint64_int8[i].x << ", " << uint64_int8[i].y;         cerr << ", expected = " << (uint64_int8[i].fExpected ? "true" : "false") << endl;      }   }}DivTest< __int8, unsigned __int64 > int8_uint64_2[] = 
{   { 0,                     0, false },   { 1,                     0, true },   { 2,                     0, true },   { 0x7f,                  0ULL, true },
   { 0x80,                  0ULL, true },
   { 0xff,                  0ULL, true },
   { 0,                     1, false },   { 1,                     1, true },   { 2,                     1, true },   { 0x7f,                  1ULL, true },
   { 0x80,                  1ULL, true },
   { 0xff,                  1ULL, true },
   { 0,                     2, false },   { 1,                     2, true },   { 2,                     2, true },   { 0x7f,                  2ULL, true },
   { 0x80,                  2ULL, true },
   { 0xff,                  2ULL, true },
   { 0,                     0x7fffffffULL, false },
   { 1,                     0x7fffffffULL, true },
   { 2,                     0x7fffffffULL, true },
   { 0x7f,                  0x7fffffffULL, true },
   { 0x80,                  0x7fffffffULL, true },
   { 0xff,                  0x7fffffffULL, true },
   { 0,                     0x80000000ULL, false },
   { 1,                     0x80000000ULL, false },
   { 2,                     0x80000000ULL, true },
   { 0x7f,                  0x80000000ULL, true },
   { 0x80,                  0x80000000ULL, true },
   { 0xff,                  0x80000000ULL, true },
   { 0,                     0xffffffffULL, false },
   { 1,                     0xffffffffULL, false },
   { 2,                     0xffffffffULL, true },
   { 0x7f,                  0xffffffffULL, true },
   { 0x80,                  0xffffffffULL, true },
   { 0xff,                  0xffffffffULL, false },
   { 0,                     0x100000000ULL, false },
   { 1,                     0x100000000ULL, false },
   { 2,                     0x100000000ULL, false },
   { 0x7f,                  0x100000000ULL, true },
   { 0x80,                  0x100000000ULL, true },
   { 0xff,                  0x100000000ULL, false },
   { 0,                     0x200000000ULL, false },
   { 1,                     0x200000000ULL, false },
   { 2,                     0x200000000ULL, false },
   { 0x7f,                  0x200000000ULL, true },
   { 0x80,                  0x200000000ULL, true },
   { 0xff,                  0x200000000ULL, false },
   { 0,                     0x7fffffffffffffffULL, false },
   { 1,                     0x7fffffffffffffffULL, false },
   { 2,                     0x7fffffffffffffffULL, false },
   { 0x7f,                  0x7fffffffffffffffULL, false },
   { 0x80,                  0x7fffffffffffffffULL, false },
   { 0xff,                  0x7fffffffffffffffULL, false },
   { 0,                     0x8000000000000000ULL, false },
   { 1,                     0x8000000000000000ULL, false },
   { 2,                     0x8000000000000000ULL, false },
   { 0x7f,                  0x8000000000000000ULL, false },
   { 0x80,                  0x8000000000000000ULL, false },
   { 0xff,                  0x8000000000000000ULL, false },
   { 0,                     0xffffffffffffffffULL, false },
   { 1,                     0xffffffffffffffffULL, false },
   { 2,                     0xffffffffffffffffULL, false },
   { 0x7f,                  0xffffffffffffffffULL, false },
   { 0x80,                  0xffffffffffffffffULL, false },
   { 0xff,                  0xffffffffffffffffULL, false },
};void DivVerifyUint64Int8_2(){   size_t i;   for( i = 0; i < sizeof(int8_uint64_2)/sizeof(int8_uint64_2[0]); ++i )   {      // Now test throwing version      bool fSuccess = true;      try      {         SafeInt<__int32> si(int8_uint64_2[i].x);         SafeInt<__int32> si2;         si2 = int8_uint64_2[i].y / si;      }      catch(...)      {         fSuccess = false;      }      if( fSuccess != int8_uint64_2[i].fExpected )      {         cerr << "Error in case int8_uint64_2: " << int8_uint64_2[i].x << ", " << int8_uint64_2[i].y;         cerr << ", expected = " << (int8_uint64_2[i].fExpected ? "true" : "false") << endl;      }   }}DivTest< __int64, __int64 > int64_int64[] = 
{   { 0,                     0, false },   { 1,                     0, false },   { 2,                     0, false },   { 0x7fffffffLL,            0LL, false },
   { 0x80000000LL,            0LL, false },
   { 0xffffffffLL,            0LL, false },
   { 0x100000000LL,           0LL, false },
   { 0x200000000LL,           0LL, false },
   { 0x7fffffffffffffffLL,    0LL, false },
   { 0x8000000000000000LL,    0LL, false },
   { 0xffffffffffffffffLL,    0LL, false },
   { 0,                     1, true },   { 1,                     1, true },   { 2,                     1, true },   { 0x7fffffffLL,            1LL, true },
   { 0x80000000LL,            1LL, true },
   { 0xffffffffLL,            1LL, true },
   { 0x100000000LL,           1LL, true },
   { 0x200000000LL,           1LL, true },
   { 0x7fffffffffffffffLL,    1LL, true },
   { 0x8000000000000000LL,    1LL, true },
   { 0xffffffffffffffffLL,    1LL, true },
   { 0,                     2, true },   { 1,                     2, true },   { 2,                     2, true },   { 0x7fffffffLL,            2LL, true },
   { 0x80000000LL,            2LL, true },
   { 0xffffffffLL,            2LL, true },
   { 0x100000000LL,           2LL, true },
   { 0x200000000LL,           2LL, true },
   { 0x7fffffffffffffffLL,    2LL, true },
   { 0x8000000000000000LL,    2LL, true },
   { 0xffffffffffffffffLL,    2LL, true },
   { 0LL,                     0x7fffffffLL, true },
   { 1LL,                     0x7fffffffLL, true },
   { 2LL,                     0x7fffffffLL, true },
   { 0x7fffffffLL,            0x7fffffffLL, true },
   { 0x80000000LL,            0x7fffffffLL, true },
   { 0xffffffffLL,            0x7fffffffLL, true },
   { 0x100000000LL,           0x7fffffffLL, true },
   { 0x200000000LL,           0x7fffffffLL, true },
   { 0x7fffffffffffffffLL,    0x7fffffffLL, true },
   { 0x8000000000000000LL,    0x7fffffffLL, true },
   { 0xffffffffffffffffLL,    0x7fffffffLL, true },
   { 0LL,                     0x80000000LL, true },
   { 1LL,                     0x80000000LL, true },
   { 2LL,                     0x80000000LL, true },
   { 0x7fffffffLL,            0x80000000LL, true },
   { 0x80000000LL,            0x80000000LL, true },
   { 0xffffffffLL,            0x80000000LL, true },
   { 0x100000000LL,           0x80000000LL, true },
   { 0x200000000LL,           0x80000000LL, true },
   { 0x7fffffffffffffffLL,    0x80000000LL, true },
   { 0x8000000000000000LL,    0x80000000LL, true },
   { 0xffffffffffffffffLL,    0x80000000LL, true },
   { 0LL,                     0xffffffffLL, true },
   { 1LL,                     0xffffffffLL, true },
   { 2LL,                     0xffffffffLL, true },
   { 0x7fffffffLL,            0xffffffffLL, true },
   { 0x80000000LL,            0xffffffffLL, true },
   { 0xffffffffLL,            0xffffffffLL, true },
   { 0x100000000LL,           0xffffffffLL, true },
   { 0x200000000LL,           0xffffffffLL, true },
   { 0x7fffffffffffffffLL,    0xffffffffLL, true },
   { 0x8000000000000000LL,    0xffffffffLL, true },
   { 0xffffffffffffffffLL,    0xffffffffLL, true },
   { 0LL,                     0x100000000LL, true },
   { 1LL,                     0x100000000LL, true },
   { 2LL,                     0x100000000LL, true },
   { 0x7fffffffLL,            0x100000000LL, true },
   { 0x80000000LL,            0x100000000LL, true },
   { 0xffffffffLL,            0x100000000LL, true },
   { 0x100000000LL,           0x100000000LL, true },
   { 0x200000000LL,           0x100000000LL, true },
   { 0x7fffffffffffffffLL,    0x100000000LL, true },
   { 0x8000000000000000LL,    0x100000000LL, true },
   { 0xffffffffffffffffLL,    0x100000000LL, true },
   { 0LL,                     0x200000000LL, true },
   { 1LL,                     0x200000000LL, true },
   { 2LL,                     0x200000000LL, true },
   { 0x7fffffffLL,            0x200000000LL, true },
   { 0x80000000LL,            0x200000000LL, true },
   { 0xffffffffLL,            0x200000000LL, true },
   { 0x100000000LL,           0x200000000LL, true },
   { 0x200000000LL,           0x200000000LL, true },
   { 0x7fffffffffffffffLL,    0x200000000LL, true },
   { 0x8000000000000000LL,    0x200000000LL, true },
   { 0xffffffffffffffffLL,    0x200000000LL, true },
   { 0LL,                     0x7fffffffffffffffLL, true },
   { 1LL,                     0x7fffffffffffffffLL, true },
   { 2LL,                     0x7fffffffffffffffLL, true },
   { 0x7fffffffLL,            0x7fffffffffffffffLL, true },
   { 0x80000000LL,            0x7fffffffffffffffLL, true },
   { 0xffffffffLL,            0x7fffffffffffffffLL, true },
   { 0x100000000LL,           0x7fffffffffffffffLL, true },
   { 0x200000000LL,           0x7fffffffffffffffLL, true },
   { 0x7fffffffffffffffLL,    0x7fffffffffffffffLL, true },
   { 0x8000000000000000LL,    0x7fffffffffffffffLL, true },
   { 0xffffffffffffffffLL,    0x7fffffffffffffffLL, true },
   { 0LL,                     0x8000000000000000LL, true },
   { 1LL,                     0x8000000000000000LL, true },
   { 2LL,                     0x8000000000000000LL, true },
   { 0x7fffffffLL,            0x8000000000000000LL, true },
   { 0x80000000LL,            0x8000000000000000LL, true },
   { 0xffffffffLL,            0x8000000000000000LL, true },
   { 0x100000000LL,           0x8000000000000000LL, true },
   { 0x200000000LL,           0x8000000000000000LL, true },
   { 0x7fffffffffffffffLL,    0x8000000000000000LL, true },
   { 0x8000000000000000LL,    0x8000000000000000LL, true },
   { 0xffffffffffffffffLL,    0x8000000000000000LL, true },
   { 0LL,                     0xffffffffffffffffLL, true },
   { 1LL,                     0xffffffffffffffffLL, true },
   { 2LL,                     0xffffffffffffffffLL, true },
   { 0x7fffffffLL,            0xffffffffffffffffLL, true },
   { 0x80000000LL,            0xffffffffffffffffLL, true },
   { 0xffffffffLL,            0xffffffffffffffffLL, true },
   { 0x100000000LL,           0xffffffffffffffffLL, true },
   { 0x200000000LL,           0xffffffffffffffffLL, true },
   { 0x7fffffffffffffffLL,    0xffffffffffffffffLL, true },
   { 0x8000000000000000LL,    0xffffffffffffffffLL, false },
   { 0xffffffffffffffffLL,    0xffffffffffffffffLL, true },
};void DivVerifyInt64Int64(){   size_t i;   for( i = 0; i < sizeof(int64_int64)/sizeof(int64_int64[0]); ++i )   {      __int64 ret;      if( SafeDivide(int64_int64[i].x, int64_int64[i].y, ret) != int64_int64[i].fExpected )      {         cerr << "Error in case int64_int64: " << int64_int64[i].x << ", " << int64_int64[i].y;         cerr << ", expected = " << (int64_int64[i].fExpected ? "true" : "false") << endl;      }      // Now test throwing version      bool fSuccess = true;      try      {         SafeInt<__int64> si(int64_int64[i].x);         si /= int64_int64[i].y;      }      catch(...)      {         fSuccess = false;      }      if( fSuccess != int64_int64[i].fExpected )      {         cerr << "Error in case int64_int64: " << int64_int64[i].x << ", " << int64_int64[i].y;         cerr << ", expected = " << (int64_int64[i].fExpected ? "true" : "false") << endl;      }      // Also need to test the version that assigns back out      // to a plain int, as it has different logic      fSuccess = true;      try      {         __int64 x(int64_int64[i].x);         x /= SafeInt<__int64>(int64_int64[i].y);      }      catch(...)      {         fSuccess = false;      }      if( fSuccess != int64_int64[i].fExpected )      {         cerr << "Error in case int64_int64: " << int64_int64[i].x << ", " << int64_int64[i].y;         cerr << ", expected = " << (int64_int64[i].fExpected ? "true" : "false") << endl;      }   }}void DivVerifyInt64Int64_2(){   size_t i;   for( i = 0; i < sizeof(int64_int64)/sizeof(int64_int64[0]); ++i )   {      // Now test throwing version      bool fSuccess = true;      try      {         SafeInt<__int64> si(int64_int64[i].y);         SafeInt<__int64> si2;         si2 = int64_int64[i].x / si;      }      catch(...)      {         fSuccess = false;      }      if( fSuccess != int64_int64[i].fExpected )      {         cerr << "Error in case int64_int64: " << int64_int64[i].x << ", " << int64_int64[i].y;         cerr << ", expected = " << (int64_int64[i].fExpected ? "true" : "false") << endl;      }   }}DivTest< __int64, __int32 > int64_int32[] = 
{   { 0,                     0, false },   { 1,                     0, false },   { 2,                     0, false },   { 0x7fffffffLL,            0, false },
   { 0x80000000LL,            0, false },
   { 0xffffffffLL,            0, false },
   { 0x100000000LL,           0, false },
   { 0x200000000LL,           0, false },
   { 0x7fffffffffffffffLL,    0, false },
   { 0x8000000000000000LL,    0, false },
   { 0xffffffffffffffffLL,    0, false },
   { 0,                     1, true },   { 1,                     1, true },   { 2,                     1, true },   { 0x7fffffffLL,            1, true },
   { 0x80000000LL,            1, true },
   { 0xffffffffLL,            1, true },
   { 0x100000000LL,           1, true },
   { 0x200000000LL,           1, true },
   { 0x7fffffffffffffffLL,    1, true },
   { 0x8000000000000000LL,    1, true },
   { 0xffffffffffffffffLL,    1, true },
   { 0,                     2, true },   { 1,                     2, true },   { 2,                     2, true },   { 0x7fffffffLL,            2, true },
   { 0x80000000LL,            2, true },
   { 0xffffffffLL,            2, true },
   { 0x100000000LL,           2, true },
   { 0x200000000LL,           2, true },
   { 0x7fffffffffffffffLL,    2, true },
   { 0x8000000000000000LL,    2, true },
   { 0xffffffffffffffffLL,    2, true },
   { 0LL,                     0x7fffffff, true },
   { 1LL,                     0x7fffffff, true },
   { 2LL,                     0x7fffffff, true },
   { 0x7fffffffLL,            0x7fffffff, true },
   { 0x80000000LL,            0x7fffffff, true },
   { 0xffffffffLL,            0x7fffffff, true },
   { 0x100000000LL,           0x7fffffff, true },
   { 0x200000000LL,           0x7fffffff, true },
   { 0x7fffffffffffffffLL,    0x7fffffff, true },
   { 0x8000000000000000LL,    0x7fffffff, true },
   { 0xffffffffffffffffLL,    0x7fffffff, true },
   { 0LL,                     0x80000000, true },
   { 1LL,                     0x80000000, true },
   { 2LL,                     0x80000000, true },
   { 0x7fffffffLL,            0x80000000, true },
   { 0x80000000LL,            0x80000000, true },
   { 0xffffffffLL,            0x80000000, true },
   { 0x100000000LL,           0x80000000, true },
   { 0x200000000LL,           0x80000000, true },
   { 0x7fffffffffffffffLL,    0x80000000, true },
   { 0x8000000000000000LL,    0x80000000, true },
   { 0xffffffffffffffffLL,    0x80000000, true },
   { 0LL,                     0xffffffff, true },
   { 1LL,                     0xffffffff, true },
   { 2LL,                     0xffffffff, true },
   { 0x7fffffffLL,            0xffffffff, true },
   { 0x80000000LL,            0xffffffff, true },
   { 0xffffffffLL,            0xffffffff, true },
   { 0x100000000LL,           0xffffffff, true },
   { 0x200000000LL,           0xffffffff, true },
   { 0x7fffffffffffffffLL,    0xffffffff, true },
   { 0x8000000000000000LL,    0xffffffff, false },
   { 0xffffffffffffffffLL,    0xffffffff, true },
};void DivVerifyInt64Int32(){   size_t i;   for( i = 0; i < sizeof(int64_int32)/sizeof(int64_int32[0]); ++i )   {      __int64 ret;      if( SafeDivide(int64_int32[i].x, int64_int32[i].y, ret) != int64_int32[i].fExpected )      {         cerr << "Error in case int64_int32: " << int64_int32[i].x << ", " << int64_int32[i].y;         cerr << ", expected = " << (int64_int32[i].fExpected ? "true" : "false") << endl;      }      // Now test throwing version      bool fSuccess = true;      try      {         SafeInt<__int64> si(int64_int32[i].x);         si /= int64_int32[i].y;      }      catch(...)      {         fSuccess = false;      }      if( fSuccess != int64_int32[i].fExpected )      {         cerr << "Error in case int64_int32: " << int64_int32[i].x << ", " << int64_int32[i].y;         cerr << ", expected = " << (int64_int32[i].fExpected ? "true" : "false") << endl;      }      // Also need to test the version that assigns back out      // to a plain int, as it has different logic      fSuccess = true;      try      {         __int64 x(int64_int32[i].x);         x /= SafeInt<__int32>(int64_int32[i].y);      }      catch(...)      {         fSuccess = false;      }      if( fSuccess != int64_int32[i].fExpected )      {         cerr << "Error in case int64_int32: " << int64_int32[i].x << ", " << int64_int32[i].y;         cerr << ", expected = " << (int64_int32[i].fExpected ? "true" : "false") << endl;      }   }}DivTest< __int64, __int32 > int64_int32_2[] = 
{   { 0,                     0, false },   { 1,                     0, false },   { 2,                     0, false },   { 0x7fffffffLL,            0, false },
   { 0x80000000LL,            0, false },
   { 0xffffffffLL,            0, false },
   { 0x100000000LL,           0, false },
   { 0x200000000LL,           0, false },
   { 0x7fffffffffffffffLL,    0, false },
   { 0x8000000000000000LL,    0, false },
   { 0xffffffffffffffffLL,    0, false },
   { 0,                     1, true },   { 1,                     1, true },   { 2,                     1, true },   { 0x7fffffffLL,            1, true },
   { 0x80000000LL,            1, false },
   { 0xffffffffLL,            1, false },
   { 0x100000000LL,           1, false },
   { 0x200000000LL,           1, false },
   { 0x7fffffffffffffffLL,    1, false },
   { 0x8000000000000000LL,    1, false },
   { 0xffffffffffffffffLL,    1, true },
   { 0,                     2, true },   { 1,                     2, true },   { 2,                     2, true },   { 0x7fffffffLL,            2, true },
   { 0x80000000LL,            2, true },
   { 0xffffffffLL,            2, true },
   { 0x100000000LL,           2, false },
   { 0x200000000LL,           2, false },
   { 0x7fffffffffffffffLL,    2, false },
   { 0x8000000000000000LL,    2, false },
   { 0xffffffffffffffffLL,    2, true },
   { 0LL,                     0x7fffffff, true },
   { 1LL,                     0x7fffffff, true },
   { 2LL,                     0x7fffffff, true },
   { 0x7fffffffLL,            0x7fffffff, true },
   { 0x80000000LL,            0x7fffffff, true },
   { 0xffffffffLL,            0x7fffffff, true },
   { 0x100000000LL,           0x7fffffff, true },
   { 0x200000000LL,           0x7fffffff, true },
   { 0x7fffffffffffffffLL,    0x7fffffff, false },
   { 0x8000000000000000LL,    0x7fffffff, false },
   { 0xffffffffffffffffLL,    0x7fffffff, true },
   { 0LL,                     0x80000000, true },
   { 1LL,                     0x80000000, true },
   { 2LL,                     0x80000000, true },
   { 0x7fffffffLL,            0x80000000, true },
   { 0x80000000LL,            0x80000000, true },
   { 0xffffffffLL,            0x80000000, true },
   { 0x100000000LL,           0x80000000, true },
   { 0x200000000LL,           0x80000000, true },
   { 0x7fffffffffffffffLL,    0x80000000, false },
   { 0x8000000000000000LL,    0x80000000, false },
   { 0xffffffffffffffffLL,    0x80000000, true },
   { 0LL,                     0xffffffff, true },
   { 1LL,                     0xffffffff, true },
   { 2LL,                     0xffffffff, true },
   { 0x7fffffffLL,            0xffffffff, true },
   { 0x80000000LL,            0xffffffff, true },
   { 0xffffffffLL,            0xffffffff, false },
   { 0x100000000LL,           0xffffffff, false },
   { 0x200000000LL,           0xffffffff, false },
   { 0x7fffffffffffffffLL,    0xffffffff, false },
   { 0x8000000000000000LL,    0xffffffff, false },
   { 0xffffffffffffffffLL,    0xffffffff, true },
};void DivVerifyInt64Int32_2(){   size_t i;   for( i = 0; i < sizeof(int64_int32_2)/sizeof(int64_int32_2[0]); ++i )   {      // Now test throwing version      bool fSuccess = true;      try      {         SafeInt<__int32> si(int64_int32_2[i].y);         SafeInt<__int32> si2;         si2 = int64_int32_2[i].x / si;      }      catch(...)      {         fSuccess = false;      }      if( fSuccess != int64_int32_2[i].fExpected )      {         cerr << "Error in case int64_int32_2: " << int64_int32_2[i].x << ", " << int64_int32_2[i].y;         cerr << ", expected = " << (int64_int32_2[i].fExpected ? "true" : "false") << endl;      }   }}DivTest< __int64, unsigned __int64 > int64_uint64[] = 
{   { 0,                     0, false },   { 1,                     0, false },   { 2,                     0, false },   { 0x7fffffffLL,            0ULL, false },
   { 0x80000000LL,            0ULL, false },
   { 0xffffffffLL,            0ULL, false },
   { 0x100000000LL,           0ULL, false },
   { 0x200000000LL,           0ULL, false },
   { 0x7fffffffffffffffLL,    0ULL, false },
   { 0x8000000000000000LL,    0ULL, false },
   { 0xffffffffffffffffLL,    0ULL, false },
   { 0,                     1, true },   { 1,                     1, true },   { 2,                     1, true },   { 0x7fffffffLL,            1ULL, true },
   { 0x80000000LL,            1ULL, true },
   { 0xffffffffLL,            1ULL, true },
   { 0x100000000LL,           1ULL, true },
   { 0x200000000LL,           1ULL, true },
   { 0x7fffffffffffffffLL,    1ULL, true },
   { 0x8000000000000000LL,    1ULL, true },
   { 0xffffffffffffffffLL,    1ULL, true },
   { 0,                     2, true },   { 1,                     2, true },   { 2,                     2, true },   { 0x7fffffffLL,            2ULL, true },
   { 0x80000000LL,            2ULL, true },
   { 0xffffffffLL,            2ULL, true },
   { 0x100000000LL,           2ULL, true },
   { 0x200000000LL,           2ULL, true },
   { 0x7fffffffffffffffLL,    2ULL, true },
   { 0x8000000000000000LL,    2ULL, true },
   { 0xffffffffffffffffLL,    2ULL, true },
   { 0LL,                     0x7fffffffULL, true },
   { 1LL,                     0x7fffffffULL, true },
   { 2LL,                     0x7fffffffULL, true },
   { 0x7fffffffLL,            0x7fffffffULL, true },
   { 0x80000000LL,            0x7fffffffULL, true },
   { 0xffffffffLL,            0x7fffffffULL, true },
   { 0x100000000LL,           0x7fffffffULL, true },
   { 0x200000000LL,           0x7fffffffULL, true },
   { 0x7fffffffffffffffLL,    0x7fffffffULL, true },
   { 0x8000000000000000LL,    0x7fffffffULL, true },
   { 0xffffffffffffffffLL,    0x7fffffffULL, true },
   { 0LL,                     0x80000000ULL, true },
   { 1LL,                     0x80000000ULL, true },
   { 2LL,                     0x80000000ULL, true },
   { 0x7fffffffLL,            0x80000000ULL, true },
   { 0x80000000LL,            0x80000000ULL, true },
   { 0xffffffffLL,            0x80000000ULL, true },
   { 0x100000000LL,           0x80000000ULL, true },
   { 0x200000000LL,           0x80000000ULL, true },
   { 0x7fffffffffffffffLL,    0x80000000ULL, true },
   { 0x8000000000000000LL,    0x80000000ULL, true },
   { 0xffffffffffffffffLL,    0x80000000ULL, true },
   { 0LL,                     0xffffffffULL, true },
   { 1LL,                     0xffffffffULL, true },
   { 2LL,                     0xffffffffULL, true },
   { 0x7fffffffLL,            0xffffffffULL, true },
   { 0x80000000LL,            0xffffffffULL, true },
   { 0xffffffffLL,            0xffffffffULL, true },
   { 0x100000000LL,           0xffffffffULL, true },
   { 0x200000000LL,           0xffffffffULL, true },
   { 0x7fffffffffffffffLL,    0xffffffffULL, true },
   { 0x8000000000000000LL,    0xffffffffULL, true },
   { 0xffffffffffffffffLL,    0xffffffffULL, true },
   { 0LL,                     0x100000000ULL, true },
   { 1LL,                     0x100000000ULL, true },
   { 2LL,                     0x100000000ULL, true },
   { 0x7fffffffLL,            0x100000000ULL, true },
   { 0x80000000LL,            0x100000000ULL, true },
   { 0xffffffffLL,            0x100000000ULL, true },
   { 0x100000000LL,           0x100000000ULL, true },
   { 0x200000000LL,           0x100000000ULL, true },
   { 0x7fffffffffffffffLL,    0x100000000ULL, true },
   { 0x8000000000000000LL,    0x100000000ULL, true },
   { 0xffffffffffffffffLL,    0x100000000ULL, true },
   { 0LL,                     0x200000000ULL, true },
   { 1LL,                     0x200000000ULL, true },
   { 2LL,                     0x200000000ULL, true },
   { 0x7fffffffLL,            0x200000000ULL, true },
   { 0x80000000LL,            0x200000000ULL, true },
   { 0xffffffffLL,            0x200000000ULL, true },
   { 0x100000000LL,           0x200000000ULL, true },
   { 0x200000000LL,           0x200000000ULL, true },
   { 0x7fffffffffffffffLL,    0x200000000ULL, true },
   { 0x8000000000000000LL,    0x200000000ULL, true },
   { 0xffffffffffffffffLL,    0x200000000ULL, true },
   { 0LL,                     0x7fffffffffffffffULL, true },
   { 1LL,                     0x7fffffffffffffffULL, true },
   { 2LL,                     0x7fffffffffffffffULL, true },
   { 0x7fffffffLL,            0x7fffffffffffffffULL, true },
   { 0x80000000LL,            0x7fffffffffffffffULL, true },
   { 0xffffffffLL,            0x7fffffffffffffffULL, true },
   { 0x100000000LL,           0x7fffffffffffffffULL, true },
   { 0x200000000LL,           0x7fffffffffffffffULL, true },
   { 0x7fffffffffffffffLL,    0x7fffffffffffffffULL, true },
   { 0x8000000000000000LL,    0x7fffffffffffffffULL, true },
   { 0xffffffffffffffffLL,    0x7fffffffffffffffULL, true },
   { 0LL,                     0x8000000000000000ULL, true },
   { 1LL,                     0x8000000000000000ULL, true },
   { 2LL,                     0x8000000000000000ULL, true },
   { 0x7fffffffLL,            0x8000000000000000ULL, true },
   { 0x80000000LL,            0x8000000000000000ULL, true },
   { 0xffffffffLL,            0x8000000000000000ULL, true },
   { 0x100000000LL,           0x8000000000000000ULL, true },
   { 0x200000000LL,           0x8000000000000000ULL, true },
   { 0x7fffffffffffffffLL,    0x8000000000000000ULL, true },
   { 0x8000000000000000LL,    0x8000000000000000ULL, true },
   { 0xffffffffffffffffLL,    0x8000000000000000ULL, true },
   { 0LL,                     0xffffffffffffffffULL, true },
   { 1LL,                     0xffffffffffffffffULL, true },
   { 2LL,                     0xffffffffffffffffULL, true },
   { 0x7fffffffLL,            0xffffffffffffffffULL, true },
   { 0x80000000LL,            0xffffffffffffffffULL, true },
   { 0xffffffffLL,            0xffffffffffffffffULL, true },
   { 0x100000000LL,           0xffffffffffffffffULL, true },
   { 0x200000000LL,           0xffffffffffffffffULL, true },
   { 0x7fffffffffffffffLL,    0xffffffffffffffffULL, true },
   { 0x8000000000000000LL,    0xffffffffffffffffULL, true },
   { 0xffffffffffffffffLL,    0xffffffffffffffffULL, true },
};void DivVerifyInt64Uint64(){   size_t i;   for( i = 0; i < sizeof(int64_uint64)/sizeof(int64_uint64[0]); ++i )   {      __int64 ret;      if( SafeDivide(int64_uint64[i].x, int64_uint64[i].y, ret) != int64_uint64[i].fExpected )      {         cerr << "Error in case int64_uint64: " << int64_uint64[i].x << ", " << int64_uint64[i].y;         cerr << ", expected = " << (int64_uint64[i].fExpected ? "true" : "false") << endl;      }      // Now test throwing version      bool fSuccess = true;      try      {         SafeInt<__int64> si(int64_uint64[i].x);         si /= int64_uint64[i].y;      }      catch(...)      {         fSuccess = false;      }      if( fSuccess != int64_uint64[i].fExpected )      {         cerr << "Error in case int64_uint64: " << int64_uint64[i].x << ", " << int64_uint64[i].y;         cerr << ", expected = " << (int64_uint64[i].fExpected ? "true" : "false") << endl;      }      // Also need to test the version that assigns back out      // to a plain int, as it has different logic      fSuccess = true;      try      {         __int64 x(int64_uint64[i].x);         x /= SafeInt<unsigned __int64>(int64_uint64[i].y);      }      catch(...)      {         fSuccess = false;      }      if( fSuccess != int64_uint64[i].fExpected )      {         cerr << "Error in case int64_uint64: " << int64_uint64[i].x << ", " << int64_uint64[i].y;         cerr << ", expected = " << (int64_uint64[i].fExpected ? "true" : "false") << endl;      }   }}DivTest< __int64, unsigned __int64 > int64_uint64_3[] = 
{   { 0,                     0, false },   { 1,                     0, false },   { 2,                     0, false },   { 0x7fffffffLL,            0ULL, false },
   { 0x80000000LL,            0ULL, false },
   { 0xffffffffLL,            0ULL, false },
   { 0x100000000LL,           0ULL, false },
   { 0x200000000LL,           0ULL, false },
   { 0x7fffffffffffffffLL,    0ULL, false },
   { 0x8000000000000000LL,    0ULL, false },
   { 0xffffffffffffffffLL,    0ULL, false },
   { 0,                     1, true },   { 1,                     1, true },   { 2,                     1, true },   { 0x7fffffffLL,            1ULL, true },
   { 0x80000000LL,            1ULL, true },
   { 0xffffffffLL,            1ULL, true },
   { 0x100000000LL,           1ULL, true },
   { 0x200000000LL,           1ULL, true },
   { 0x7fffffffffffffffLL,    1ULL, true },
   { 0x8000000000000000LL,    1ULL, false },
   { 0xffffffffffffffffLL,    1ULL, false },
   { 0,                     2, true },   { 1,                     2, true },   { 2,                     2, true },   { 0x7fffffffLL,            2ULL, true },
   { 0x80000000LL,            2ULL, true },
   { 0xffffffffLL,            2ULL, true },
   { 0x100000000LL,           2ULL, true },
   { 0x200000000LL,           2ULL, true },
   { 0x7fffffffffffffffLL,    2ULL, true },
   { 0x8000000000000000LL,    2ULL, false },
   { 0xffffffffffffffffLL,    2ULL, true },
   { 0LL,                     0x7fffffffULL, true },
   { 1LL,                     0x7fffffffULL, true },
   { 2LL,                     0x7fffffffULL, true },
   { 0x7fffffffLL,            0x7fffffffULL, true },
   { 0x80000000LL,            0x7fffffffULL, true },
   { 0xffffffffLL,            0x7fffffffULL, true },
   { 0x100000000LL,           0x7fffffffULL, true },
   { 0x200000000LL,           0x7fffffffULL, true },
   { 0x7fffffffffffffffLL,    0x7fffffffULL, true },
   { 0x8000000000000000LL,    0x7fffffffULL, false },
   { 0xffffffffffffffffLL,    0x7fffffffULL, true },
   { 0LL,                     0x80000000ULL, true },
   { 1LL,                     0x80000000ULL, true },
   { 2LL,                     0x80000000ULL, true },
   { 0x7fffffffLL,            0x80000000ULL, true },
   { 0x80000000LL,            0x80000000ULL, true },
   { 0xffffffffLL,            0x80000000ULL, true },
   { 0x100000000LL,           0x80000000ULL, true },
   { 0x200000000LL,           0x80000000ULL, true },
   { 0x7fffffffffffffffLL,    0x80000000ULL, true },
   { 0x8000000000000000LL,    0x80000000ULL, false },
   { 0xffffffffffffffffLL,    0x80000000ULL, true },
   { 0LL,                     0xffffffffULL, true },
   { 1LL,                     0xffffffffULL, true },
   { 2LL,                     0xffffffffULL, true },
   { 0x7fffffffLL,            0xffffffffULL, true },
   { 0x80000000LL,            0xffffffffULL, true },
   { 0xffffffffLL,            0xffffffffULL, true },
   { 0x100000000LL,           0xffffffffULL, true },
   { 0x200000000LL,           0xffffffffULL, true },
   { 0x7fffffffffffffffLL,    0xffffffffULL, true },
   { 0x8000000000000000LL,    0xffffffffULL, false },
   { 0xffffffffffffffffLL,    0xffffffffULL, true },
   { 0LL,                     0x100000000ULL, true },
   { 1LL,                     0x100000000ULL, true },
   { 2LL,                     0x100000000ULL, true },
   { 0x7fffffffLL,            0x100000000ULL, true },
   { 0x80000000LL,            0x100000000ULL, true },
   { 0xffffffffLL,            0x100000000ULL, true },
   { 0x100000000LL,           0x100000000ULL, true },
   { 0x200000000LL,           0x100000000ULL, true },
   { 0x7fffffffffffffffLL,    0x100000000ULL, true },
   { 0x8000000000000000LL,    0x100000000ULL, false },
   { 0xffffffffffffffffLL,    0x100000000ULL, true },
   { 0LL,                     0x200000000ULL, true },
   { 1LL,                     0x200000000ULL, true },
   { 2LL,                     0x200000000ULL, true },
   { 0x7fffffffLL,            0x200000000ULL, true },
   { 0x80000000LL,            0x200000000ULL, true },
   { 0xffffffffLL,            0x200000000ULL, true },
   { 0x100000000LL,           0x200000000ULL, true },
   { 0x200000000LL,           0x200000000ULL, true },
   { 0x7fffffffffffffffLL,    0x200000000ULL, true },
   { 0x8000000000000000LL,    0x200000000ULL, false },
   { 0xffffffffffffffffLL,    0x200000000ULL, true },
   { 0LL,                     0x7fffffffffffffffULL, true },
   { 1LL,                     0x7fffffffffffffffULL, true },
   { 2LL,                     0x7fffffffffffffffULL, true },
   { 0x7fffffffLL,            0x7fffffffffffffffULL, true },
   { 0x80000000LL,            0x7fffffffffffffffULL, true },
   { 0xffffffffLL,            0x7fffffffffffffffULL, true },
   { 0x100000000LL,           0x7fffffffffffffffULL, true },
   { 0x200000000LL,           0x7fffffffffffffffULL, true },
   { 0x7fffffffffffffffLL,    0x7fffffffffffffffULL, true },
   { 0x8000000000000000LL,    0x7fffffffffffffffULL, false },
   { 0xffffffffffffffffLL,    0x7fffffffffffffffULL, true },
   { 0LL,                     0x8000000000000000ULL, true },
   { 1LL,                     0x8000000000000000ULL, true },
   { 2LL,                     0x8000000000000000ULL, true },
   { 0x7fffffffLL,            0x8000000000000000ULL, true },
   { 0x80000000LL,            0x8000000000000000ULL, true },
   { 0xffffffffLL,            0x8000000000000000ULL, true },
   { 0x100000000LL,           0x8000000000000000ULL, true },
   { 0x200000000LL,           0x8000000000000000ULL, true },
   { 0x7fffffffffffffffLL,    0x8000000000000000ULL, true },
   { 0x8000000000000000LL,    0x8000000000000000ULL, false },
   { 0xffffffffffffffffLL,    0x8000000000000000ULL, true },
   { 0LL,                     0xffffffffffffffffULL, true },
   { 1LL,                     0xffffffffffffffffULL, true },
   { 2LL,                     0xffffffffffffffffULL, true },
   { 0x7fffffffLL,            0xffffffffffffffffULL, true },
   { 0x80000000LL,            0xffffffffffffffffULL, true },
   { 0xffffffffLL,            0xffffffffffffffffULL, true },
   { 0x100000000LL,           0xffffffffffffffffULL, true },
   { 0x200000000LL,           0xffffffffffffffffULL, true },
   { 0x7fffffffffffffffLL,    0xffffffffffffffffULL, true },
   { 0x8000000000000000LL,    0xffffffffffffffffULL, true },
   { 0xffffffffffffffffLL,    0xffffffffffffffffULL, true },
};void DivVerifyInt64Uint64_2(){   size_t i;   for( i = 0; i < sizeof(int64_uint64_3)/sizeof(int64_uint64_3[0]); ++i )   {      // Now test throwing version      bool fSuccess = true;      try      {         SafeInt<unsigned __int64> si(int64_uint64_3[i].y);         SafeInt<unsigned __int64> si2;         si2 = int64_uint64_3[i].x / si;      }      catch(...)      {         fSuccess = false;      }      if( fSuccess != int64_uint64_3[i].fExpected )      {         cerr << "Error in case int64_uint64_3: " << int64_uint64_3[i].x << ", " << int64_uint64_3[i].y;         cerr << ", expected = " << (int64_uint64_3[i].fExpected ? "true" : "false") << endl;      }   }}DivTest< __int64, unsigned __int32 > int64_uint32[] = 
{   { 0,                     0, false },   { 1,                     0, false },   { 2,                     0, false },   { 0x7fffffffLL,            0, false },
   { 0x80000000LL,            0, false },
   { 0xffffffffLL,            0, false },
   { 0x100000000LL,           0, false },
   { 0x200000000LL,           0, false },
   { 0x7fffffffffffffffLL,    0, false },
   { 0x8000000000000000LL,    0, false },
   { 0xffffffffffffffffLL,    0, false },
   { 0,                     1, true },   { 1,                     1, true },   { 2,                     1, true },   { 0x7fffffffLL,            1, true },
   { 0x80000000LL,            1, true },
   { 0xffffffffLL,            1, true },
   { 0x100000000LL,           1, true },
   { 0x200000000LL,           1, true },
   { 0x7fffffffffffffffLL,    1, true },
   { 0x8000000000000000LL,    1, true },
   { 0xffffffffffffffffLL,    1, true },
   { 0,                     2, true },   { 1,                     2, true },   { 2,                     2, true },   { 0x7fffffffLL,            2, true },
   { 0x80000000LL,            2, true },
   { 0xffffffffLL,            2, true },
   { 0x100000000LL,           2, true },
   { 0x200000000LL,           2, true },
   { 0x7fffffffffffffffLL,    2, true },
   { 0x8000000000000000LL,    2, true },
   { 0xffffffffffffffffLL,    2, true },
   { 0LL,                     0x7fffffff, true },
   { 1LL,                     0x7fffffff, true },
   { 2LL,                     0x7fffffff, true },
   { 0x7fffffffLL,            0x7fffffff, true },
   { 0x80000000LL,            0x7fffffff, true },
   { 0xffffffffLL,            0x7fffffff, true },
   { 0x100000000LL,           0x7fffffff, true },
   { 0x200000000LL,           0x7fffffff, true },
   { 0x7fffffffffffffffLL,    0x7fffffff, true },
   { 0x8000000000000000LL,    0x7fffffff, true },
   { 0xffffffffffffffffLL,    0x7fffffff, true },
   { 0LL,                     0x80000000, true },
   { 1LL,                     0x80000000, true },
   { 2LL,                     0x80000000, true },
   { 0x7fffffffLL,            0x80000000, true },
   { 0x80000000LL,            0x80000000, true },
   { 0xffffffffLL,            0x80000000, true },
   { 0x100000000LL,           0x80000000, true },
   { 0x200000000LL,           0x80000000, true },
   { 0x7fffffffffffffffLL,    0x80000000, true },
   { 0x8000000000000000LL,    0x80000000, true },
   { 0xffffffffffffffffLL,    0x80000000, true },
   { 0LL,                     0xffffffff, true },
   { 1LL,                     0xffffffff, true },
   { 2LL,                     0xffffffff, true },
   { 0x7fffffffLL,            0xffffffff, true },
   { 0x80000000LL,            0xffffffff, true },
   { 0xffffffffLL,            0xffffffff, true },
   { 0x100000000LL,           0xffffffff, true },
   { 0x200000000LL,           0xffffffff, true },
   { 0x7fffffffffffffffLL,    0xffffffff, true },
   { 0x8000000000000000LL,    0xffffffff, true },
   { 0xffffffffffffffffLL,    0xffffffff, true },
};void DivVerifyInt64Uint32(){   size_t i;   for( i = 0; i < sizeof(int64_uint32)/sizeof(int64_uint32[0]); ++i )   {      __int64 ret;      if( SafeDivide(int64_uint32[i].x, int64_uint32[i].y, ret) != int64_uint32[i].fExpected )      {         cerr << "Error in case int64_uint32: " << int64_uint32[i].x << ", " << int64_uint32[i].y;         cerr << ", expected = " << (int64_uint32[i].fExpected ? "true" : "false") << endl;      }      // Now test throwing version      bool fSuccess = true;      try      {         SafeInt<__int64> si(int64_uint32[i].x);         si /= int64_uint32[i].y;      }      catch(...)      {         fSuccess = false;      }      if( fSuccess != int64_uint32[i].fExpected )      {         cerr << "Error in case int64_uint32: " << int64_uint32[i].x << ", " << int64_uint32[i].y;         cerr << ", expected = " << (int64_uint32[i].fExpected ? "true" : "false") << endl;      }      // Also need to test the version that assigns back out      // to a plain int, as it has different logic      fSuccess = true;      try      {         __int64 x(int64_uint32[i].x);         x /= SafeInt<unsigned __int32>(int64_uint32[i].y);      }      catch(...)      {         fSuccess = false;      }      if( fSuccess != int64_uint32[i].fExpected )      {         cerr << "Error in case int64_uint32: " << int64_uint32[i].x << ", " << int64_uint32[i].y;         cerr << ", expected = " << (int64_uint32[i].fExpected ? "true" : "false") << endl;      }   }}DivTest< __int64, unsigned __int32 > int64_uint32_2[] = 
{   { 0,                     0, false },   { 1,                     0, false },   { 2,                     0, false },   { 0x7fffffffLL,            0, false },
   { 0x80000000LL,            0, false },
   { 0xffffffffLL,            0, false },
   { 0x100000000LL,           0, false },
   { 0x200000000LL,           0, false },
   { 0x7fffffffffffffffLL,    0, false },
   { 0x8000000000000000LL,    0, false },
   { 0xffffffffffffffffLL,    0, false },
   { 0,                     1, true },   { 1,                     1, true },   { 2,                     1, true },   { 0x7fffffffLL,            1, true },
   { 0x80000000LL,            1, true },
   { 0xffffffffLL,            1, true },
   { 0x100000000LL,           1, false },
   { 0x200000000LL,           1, false },
   { 0x7fffffffffffffffLL,    1, false },
   { 0x8000000000000000LL,    1, false },
   { 0xffffffffffffffffLL,    1, false },
   { 0,                     2, true },   { 1,                     2, true },   { 2,                     2, true },   { 0x7fffffffLL,            2, true },
   { 0x80000000LL,            2, true },
   { 0xffffffffLL,            2, true },
   { 0x100000000LL,           2, true },
   { 0x200000000LL,           2, false },
   { 0x7fffffffffffffffLL,    2, false },
   { 0x8000000000000000LL,    2, false },
   { 0xffffffffffffffffLL,    2, true },
   { 0LL,                     0x7fffffff, true },
   { 1LL,                     0x7fffffff, true },
   { 2LL,                     0x7fffffff, true },
   { 0x7fffffffLL,            0x7fffffff, true },
   { 0x80000000LL,            0x7fffffff, true },
   { 0xffffffffLL,            0x7fffffff, true },
   { 0x100000000LL,           0x7fffffff, true },
   { 0x200000000LL,           0x7fffffff, true },
   { 0x7fffffffffffffffLL,    0x7fffffff, false },
   { 0x8000000000000000LL,    0x7fffffff, false },
   { 0xffffffffffffffffLL,    0x7fffffff, true },
   { 0LL,                     0x80000000, true },
   { 1LL,                     0x80000000, true },
   { 2LL,                     0x80000000, true },
   { 0x7fffffffLL,            0x80000000, true },
   { 0x80000000LL,            0x80000000, true },
   { 0xffffffffLL,            0x80000000, true },
   { 0x100000000LL,           0x80000000, true },
   { 0x200000000LL,           0x80000000, true },
   { 0x7fffffffffffffffLL,    0x80000000, true },
   { 0x8000000000000000LL,    0x80000000, false },
   { 0xffffffffffffffffLL,    0x80000000, true },
   { 0LL,                     0xffffffff, true },
   { 1LL,                     0xffffffff, true },
   { 2LL,                     0xffffffff, true },
   { 0x7fffffffLL,            0xffffffff, true },
   { 0x80000000LL,            0xffffffff, true },
   { 0xffffffffLL,            0xffffffff, true },
   { 0x100000000LL,           0xffffffff, true },
   { 0x200000000LL,           0xffffffff, true },
   { 0x7fffffffffffffffLL,    0xffffffff, true },
   { 0x8000000000000000LL,    0xffffffff, false },
   { 0xffffffffffffffffLL,    0xffffffff, true },
};void DivVerifyInt64Uint32_2(){   size_t i;   for( i = 0; i < sizeof(int64_uint32_2)/sizeof(int64_uint32_2[0]); ++i )   {      // Now test throwing version      bool fSuccess = true;      try      {         SafeInt<unsigned __int32> si(int64_uint32_2[i].y);         SafeInt<unsigned __int32> si2;         si2 = int64_uint32_2[i].x / si;      }      catch(...)      {         fSuccess = false;      }      if( fSuccess != int64_uint32_2[i].fExpected )      {         cerr << "Error in case int64_uint32_2: " << int64_uint32_2[i].x << ", " << int64_uint32_2[i].y;         cerr << ", expected = " << (int64_uint32_2[i].fExpected ? "true" : "false") << endl;      }   }}void DivVerify(){   cerr << "Verifying Division:" << endl;   // Unsigned int64, unsigned cases   DivVerifyUint64Uint64();   DivVerifyUint64Uint32();   DivVerifyUint64Uint16();   DivVerifyUint64Uint8();   // Unsigned int64, signed cases   DivVerifyUint64Int64();   DivVerifyUint64Int64_2();   DivVerifyUint64Int32();   DivVerifyUint64Int32_2();   DivVerifyUint64Int16();   DivVerifyUint64Int16_2();   DivVerifyUint64Int8();   DivVerifyUint64Int8_2();   // int64, signed   DivVerifyInt64Int64();   DivVerifyInt64Int64_2();   DivVerifyInt64Int32();   DivVerifyInt64Int32_2();   // 16 and 8-bit cases do not go down    // any individual paths   // int64, unsigned   DivVerifyInt64Uint64();   DivVerifyInt64Uint64_2();   DivVerifyInt64Uint32();   DivVerifyInt64Uint32_2();}} //end namespace