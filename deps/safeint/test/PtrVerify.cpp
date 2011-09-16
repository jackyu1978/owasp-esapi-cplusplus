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

namespace ptr_verify
{

  struct S1 {
    __int8 x;
  };

  struct S2 {
    __int16 x;
  };

  struct S3 {
    __int32 x;
  };

  struct S4 {
    __int64 x;
  };

  struct S5 {
    __int64 w;
    __int32 x;
    __int16 y;
    __int8  z;
  };

  void PtrS1Add8Verify()
  {
    S1* BASE = (S1*)(((size_t)-1) -sizeof(S1));
    S1 *ptr1 = BASE, *ptr2 = BASE;

    // The first add should succeed
    try
      {
        ptr1 += SafeInt<unsigned __int8>(1);
      }
    catch(SafeIntException&)
      {
        cerr << "Error in case PtrS1Add8Verify (1): ";
        cerr << "ptr = "  << ptr1 << ", ";
        cerr << "sizeof = "  << sizeof(S1) << endl;
      }

    // Second add should wrap
    try
      {
        const S1* pp = ptr1;
        ptr1 += SafeInt<unsigned __int8>(1);

        cerr << "Error in case PtrS1Add8Verify (2): ";
        cerr << "ptr = "  << pp << ", ";
        cerr << "sizeof = "  << sizeof(S1) << endl;
      }
    catch(SafeIntException&)
      {
      }

    // The third add should succeed
    try
      {
        ptr2 += SafeInt<__int8>(1);
      }
    catch(SafeIntException&)
      {
        cerr << "Error in case PtrS1Add8Verify (3): ";
        cerr << "ptr = "  << ptr2 << ", ";
        cerr << "sizeof = "  << sizeof(S1) << endl;
      }

    // Fourth add should wrap
    try
      {
        const S1* pp = ptr2;
        ptr2 += SafeInt<__int8>(1);

        cerr << "Error in case PtrS1Add8Verify (4): ";
        cerr << "ptr = "  << pp << ", ";
        cerr << "sizeof = "  << sizeof(S1) << endl;
      }
    catch(SafeIntException&)
      {
      }
  }

  void PtrS1Add16Verify()
  {
    S1* BASE = (S1*)(((size_t)-1) -sizeof(S1));
    S1 *ptr1 = BASE, *ptr2 = BASE;

    // The first add should succeed
    try
      {
        ptr1 += SafeInt<unsigned __int16>(1);
      }
    catch(SafeIntException&)
      {
        cerr << "Error in case PtrS1Add16Verify (1): ";
        cerr << "ptr = "  << ptr1 << ", ";
        cerr << "sizeof = "  << sizeof(S1) << endl;
      }

    // Second add should wrap
    try
      {
        const S1* pp = ptr1;
        ptr1 += SafeInt<unsigned __int16>(1);

        cerr << "Error in case PtrS1Add16Verify (2): ";
        cerr << "ptr = "  << pp << ", ";
        cerr << "sizeof = "  << sizeof(S1) << endl;
      }
    catch(SafeIntException&)
      {
      }

    // The third add should succeed
    try
      {
        ptr2 += SafeInt<__int16>(1);
      }
    catch(SafeIntException&)
      {
        cerr << "Error in case PtrS1Add16Verify (3): ";
        cerr << "ptr = "  << ptr2 << ", ";
        cerr << "sizeof = "  << sizeof(S1) << endl;
      }

    // Fourth add should wrap
    try
      {
        const S1* pp = ptr2;
        ptr2 += SafeInt<__int16>(1);

        cerr << "Error in case PtrS1Add16Verify (4): ";
        cerr << "ptr = "  << pp << ", ";
        cerr << "sizeof = "  << sizeof(S1) << endl;
      }
    catch(SafeIntException&)
      {
      }
  }

  void PtrS1Add32Verify()
  {
    S1* BASE = (S1*)(((size_t)-1) -sizeof(S1));
    S1 *ptr1 = BASE, *ptr2 = BASE;

    // The first add should succeed
    try
      {
        ptr1 += SafeInt<unsigned __int32>(1);
      }
    catch(SafeIntException&)
      {
        cerr << "Error in case PtrS1Add32Verify (1): ";
        cerr << "ptr = "  << ptr1 << ", ";
        cerr << "sizeof = "  << sizeof(S1) << endl;
      }

    // Second add should wrap
    try
      {
        const S1* pp = ptr1;
        ptr1 += SafeInt<unsigned __int32>(1);

        cerr << "Error in case PtrS1Add32Verify (2): ";
        cerr << "ptr = "  << pp << ", ";
        cerr << "sizeof = "  << sizeof(S1) << endl;
      }
    catch(SafeIntException&)
      {
      }

    // The third add should succeed
    try
      {
        ptr2 += SafeInt<__int32>(1);
      }
    catch(SafeIntException&)
      {
        cerr << "Error in case PtrS1Add32Verify (3): ";
        cerr << "ptr = "  << ptr2 << ", ";
        cerr << "sizeof = "  << sizeof(S1) << endl;
      }

    // Fourth add should wrap
    try
      {
        const S1* pp = ptr2;
        ptr2 += SafeInt<__int32>(1);

        cerr << "Error in case PtrS1Add32Verify (4): ";
        cerr << "ptr = "  << pp << ", ";
        cerr << "sizeof = "  << sizeof(S1) << endl;
      }
    catch(SafeIntException&)
      {
      }
  }

  void PtrS1Add64Verify()
  {
    S1* BASE = (S1*)(((size_t)-1) -sizeof(S1));
    S1 *ptr1 = BASE, *ptr2 = BASE;

    // The first add should succeed
    try
      {
        ptr1 += SafeInt<unsigned __int64>(1);
      }
    catch(SafeIntException&)
      {
        cerr << "Error in case PtrS1Add64Verify (1): ";
        cerr << "ptr = "  << ptr1 << ", ";
        cerr << "sizeof = "  << sizeof(S1) << endl;
      }

    // Second add should wrap
    try
      {
        const S1* pp = ptr1;
        ptr1 += SafeInt<unsigned __int64>(1);

        cerr << "Error in case PtrS1Add64Verify (2): ";
        cerr << "ptr = "  << pp << ", ";
        cerr << "sizeof = "  << sizeof(S1) << endl;
      }
    catch(SafeIntException&)
      {
      }

    // The third add should succeed
    try
      {
        ptr2 += SafeInt<__int64>(1);
      }
    catch(SafeIntException&)
      {
        cerr << "Error in case PtrS1Add64Verify (3): ";
        cerr << "ptr = "  << ptr2 << ", ";
        cerr << "sizeof = "  << sizeof(S1) << endl;
      }

    // Fourth add should wrap
    try
      {
        const S1* pp = ptr2;
        ptr2 += SafeInt<__int64>(1);

        cerr << "Error in case PtrS1Add64Verify (4): ";
        cerr << "ptr = "  << pp << ", ";
        cerr << "sizeof = "  << sizeof(S1) << endl;
      }
    catch(SafeIntException&)
      {
      }
  }

  void PtrS2Add8Verify()
  {
    S2* BASE = (S2*)(((size_t)-1) -sizeof(S2));
    S2 *ptr1 = BASE, *ptr2 = BASE;

    // The first add should succeed
    try
      {
        ptr1 += SafeInt<unsigned __int8>(1);
      }
    catch(SafeIntException&)
      {
        cerr << "Error in case PtrS2Add8Verify (1): ";
        cerr << "ptr = "  << ptr1 << ", ";
        cerr << "sizeof = "  << sizeof(S2) << endl;
      }

    // Second add should wrap
    try
      {
        const S2* pp = ptr1;
        ptr1 += SafeInt<unsigned __int8>(1);

        cerr << "Error in case PtrS2Add8Verify (2): ";
        cerr << "ptr = "  << pp << ", ";
        cerr << "sizeof = "  << sizeof(S2) << endl;
      }
    catch(SafeIntException&)
      {
      }

    // The third add should succeed
    try
      {
        ptr2 += SafeInt<__int8>(1);
      }
    catch(SafeIntException&)
      {
        cerr << "Error in case PtrS2Add8Verify (3): ";
        cerr << "ptr = "  << ptr2 << ", ";
        cerr << "sizeof = "  << sizeof(S2) << endl;
      }

    // Fourth add should wrap
    try
      {
        const S2* pp = ptr2;
        ptr2 += SafeInt<__int8>(1);

        cerr << "Error in case PtrS2Add8Verify (4): ";
        cerr << "ptr = "  << pp << ", ";
        cerr << "sizeof = "  << sizeof(S2) << endl;
      }
    catch(SafeIntException&)
      {
      }
  }

  void PtrS2Add16Verify()
  {
    S2* BASE = (S2*)(((size_t)-1) -sizeof(S2));
    S2 *ptr1 = BASE, *ptr2 = BASE;

    // The first add should succeed
    try
      {
        ptr1 += SafeInt<unsigned __int16>(1);
      }
    catch(SafeIntException&)
      {
        cerr << "Error in case PtrS2Add16Verify (1): ";
        cerr << "ptr = "  << ptr1 << ", ";
        cerr << "sizeof = "  << sizeof(S2) << endl;
      }

    // Second add should wrap
    try
      {
        const S2* pp = ptr1;
        ptr1 += SafeInt<unsigned __int16>(1);

        cerr << "Error in case PtrS2Add16Verify (2): ";
        cerr << "ptr = "  << pp << ", ";
        cerr << "sizeof = "  << sizeof(S2) << endl;
      }
    catch(SafeIntException&)
      {
      }

    // The third add should succeed
    try
      {
        ptr2 += SafeInt<__int16>(1);
      }
    catch(SafeIntException&)
      {
        cerr << "Error in case PtrS2Add16Verify (3): ";
        cerr << "ptr = "  << ptr2 << ", ";
        cerr << "sizeof = "  << sizeof(S2) << endl;
      }

    // Fourth add should wrap
    try
      {
        const S2* pp = ptr2;
        ptr2 += SafeInt<__int16>(1);

        cerr << "Error in case PtrS2Add16Verify (4): ";
        cerr << "ptr = "  << pp << ", ";
        cerr << "sizeof = "  << sizeof(S2) << endl;
      }
    catch(SafeIntException&)
      {
      }
  }

  void PtrS2Add32Verify()
  {
    S2* BASE = (S2*)(((size_t)-1) -sizeof(S2));
    S2 *ptr1 = BASE, *ptr2 = BASE;

    // The first add should succeed
    try
      {
        ptr1 += SafeInt<unsigned __int32>(1);
      }
    catch(SafeIntException&)
      {
        cerr << "Error in case PtrS2Add32Verify (1): ";
        cerr << "ptr = "  << ptr1 << ", ";
        cerr << "sizeof = "  << sizeof(S2) << endl;
      }

    // Second add should wrap
    try
      {
        const S2* pp = ptr1;
        ptr1 += SafeInt<unsigned __int32>(1);

        cerr << "Error in case PtrS2Add32Verify (2): ";
        cerr << "ptr = "  << pp << ", ";
        cerr << "sizeof = "  << sizeof(S2) << endl;
      }
    catch(SafeIntException&)
      {
      }

    // The third add should succeed
    try
      {
        ptr2 += SafeInt<__int32>(1);
      }
    catch(SafeIntException&)
      {
        cerr << "Error in case PtrS2Add32Verify (3): ";
        cerr << "ptr = "  << ptr2 << ", ";
        cerr << "sizeof = "  << sizeof(S2) << endl;
      }

    // Fourth add should wrap
    try
      {
        const S2* pp = ptr2;
        ptr2 += SafeInt<__int32>(1);

        cerr << "Error in case PtrS2Add32Verify (4): ";
        cerr << "ptr = "  << pp << ", ";
        cerr << "sizeof = "  << sizeof(S2) << endl;
      }
    catch(SafeIntException&)
      {
      }
  }

  void PtrS2Add64Verify()
  {
    S2* BASE = (S2*)(((size_t)-1) -sizeof(S2));
    S2 *ptr1 = BASE, *ptr2 = BASE;

    // The first add should succeed
    try
      {
        ptr1 += SafeInt<unsigned __int64>(1);
      }
    catch(SafeIntException&)
      {
        cerr << "Error in case PtrS2Add64Verify (1): ";
        cerr << "ptr = "  << ptr1 << ", ";
        cerr << "sizeof = "  << sizeof(S2) << endl;
      }

    // Second add should wrap
    try
      {
        const S2* pp = ptr1;
        ptr1 += SafeInt<unsigned __int64>(1);

        cerr << "Error in case PtrS2Add64Verify (2): ";
        cerr << "ptr = "  << pp << ", ";
        cerr << "sizeof = "  << sizeof(S2) << endl;
      }
    catch(SafeIntException&)
      {
      }

    // The third add should succeed
    try
      {
        ptr2 += SafeInt<__int64>(1);
      }
    catch(SafeIntException&)
      {
        cerr << "Error in case PtrS2Add64Verify (3): ";
        cerr << "ptr = "  << ptr2 << ", ";
        cerr << "sizeof = "  << sizeof(S2) << endl;
      }

    // Fourth add should wrap
    try
      {
        const S2* pp = ptr2;
        ptr2 += SafeInt<__int64>(1);

        cerr << "Error in case PtrS2Add64Verify (4): ";
        cerr << "ptr = "  << pp << ", ";
        cerr << "sizeof = "  << sizeof(S2) << endl;
      }
    catch(SafeIntException&)
      {
      }
  }

  void PtrS3Add8Verify()
  {
    S3* BASE = (S3*)(((size_t)-1) -sizeof(S3));
    S3 *ptr1 = BASE, *ptr2 = BASE;

    // The first add should succeed
    try
      {
        ptr1 += SafeInt<unsigned __int8>(1);
      }
    catch(SafeIntException&)
      {
        cerr << "Error in case PtrS3Add8Verify (1): ";
        cerr << "ptr = "  << ptr1 << ", ";
        cerr << "sizeof = "  << sizeof(S3) << endl;
      }

    // Second add should wrap
    try
      {
        const S3* pp = ptr1;
        ptr1 += SafeInt<unsigned __int8>(1);

        cerr << "Error in case PtrS3Add8Verify (2): ";
        cerr << "ptr = "  << pp << ", ";
        cerr << "sizeof = "  << sizeof(S3) << endl;
      }
    catch(SafeIntException&)
      {
      }

    // The third add should succeed
    try
      {
        ptr2 += SafeInt<__int8>(1);
      }
    catch(SafeIntException&)
      {
        cerr << "Error in case PtrS3Add8Verify (3): ";
        cerr << "ptr = "  << ptr2 << ", ";
        cerr << "sizeof = "  << sizeof(S3) << endl;
      }

    // Fourth add should wrap
    try
      {
        const S3* pp = ptr2;
        ptr2 += SafeInt<__int8>(1);

        cerr << "Error in case PtrS3Add8Verify (4): ";
        cerr << "ptr = "  << pp << ", ";
        cerr << "sizeof = "  << sizeof(S3) << endl;
      }
    catch(SafeIntException&)
      {
      }
  }

  void PtrS3Add16Verify()
  {
    S3* BASE = (S3*)(((size_t)-1) -sizeof(S3));
    S3 *ptr1 = BASE, *ptr2 = BASE;

    // The first add should succeed
    try
      {
        ptr1 += SafeInt<unsigned __int16>(1);
      }
    catch(SafeIntException&)
      {
        cerr << "Error in case PtrS3Add16Verify (1): ";
        cerr << "ptr = "  << ptr1 << ", ";
        cerr << "sizeof = "  << sizeof(S3) << endl;
      }

    // Second add should wrap
    try
      {
        const S3* pp = ptr1;
        ptr1 += SafeInt<unsigned __int16>(1);

        cerr << "Error in case PtrS3Add16Verify (2): ";
        cerr << "ptr = "  << pp << ", ";
        cerr << "sizeof = "  << sizeof(S3) << endl;
      }
    catch(SafeIntException&)
      {
      }

    // The third add should succeed
    try
      {
        ptr2 += SafeInt<__int16>(1);
      }
    catch(SafeIntException&)
      {
        cerr << "Error in case PtrS3Add16Verify (3): ";
        cerr << "ptr = "  << ptr2 << ", ";
        cerr << "sizeof = "  << sizeof(S3) << endl;
      }

    // Fourth add should wrap
    try
      {
        const S3* pp = ptr2;
        ptr2 += SafeInt<__int16>(1);

        cerr << "Error in case PtrS3Add16Verify (4): ";
        cerr << "ptr = "  << pp << ", ";
        cerr << "sizeof = "  << sizeof(S3) << endl;
      }
    catch(SafeIntException&)
      {
      }
  }

  void PtrS3Add32Verify()
  {
    S3* BASE = (S3*)(((size_t)-1) -sizeof(S3));
    S3 *ptr1 = BASE, *ptr2 = BASE;

    // The first add should succeed
    try
      {
        ptr1 += SafeInt<unsigned __int32>(1);
      }
    catch(SafeIntException&)
      {
        cerr << "Error in case PtrS3Add32Verify (1): ";
        cerr << "ptr = "  << ptr1 << ", ";
        cerr << "sizeof = "  << sizeof(S3) << endl;
      }

    // Second add should wrap
    try
      {
        const S3* pp = ptr1;
        ptr1 += SafeInt<unsigned __int32>(1);

        cerr << "Error in case PtrS3Add32Verify (2): ";
        cerr << "ptr = "  << pp << ", ";
        cerr << "sizeof = "  << sizeof(S3) << endl;
      }
    catch(SafeIntException&)
      {
      }

    // The third add should succeed
    try
      {
        ptr2 += SafeInt<__int32>(1);
      }
    catch(SafeIntException&)
      {
        cerr << "Error in case PtrS3Add32Verify (3): ";
        cerr << "ptr = "  << ptr2 << ", ";
        cerr << "sizeof = "  << sizeof(S3) << endl;
      }

    // Fourth add should wrap
    try
      {
        const S3* pp = ptr2;
        ptr2 += SafeInt<__int32>(1);

        cerr << "Error in case PtrS3Add32Verify (4): ";
        cerr << "ptr = "  << pp << ", ";
        cerr << "sizeof = "  << sizeof(S3) << endl;
      }
    catch(SafeIntException&)
      {
      }
  }

  void PtrS3Add64Verify()
  {
    S3* BASE = (S3*)(((size_t)-1) -sizeof(S3));
    S3 *ptr1 = BASE, *ptr2 = BASE;

    // The first add should succeed
    try
      {
        ptr1 += SafeInt<unsigned __int64>(1);
      }
    catch(SafeIntException&)
      {
        cerr << "Error in case PtrS3Add64Verify (1): ";
        cerr << "ptr = "  << ptr1 << ", ";
        cerr << "sizeof = "  << sizeof(S3) << endl;
      }

    // Second add should wrap
    try
      {
        const S3* pp = ptr1;
        ptr1 += SafeInt<unsigned __int64>(1);

        cerr << "Error in case PtrS3Add64Verify (2): ";
        cerr << "ptr = "  << pp << ", ";
        cerr << "sizeof = "  << sizeof(S3) << endl;
      }
    catch(SafeIntException&)
      {
      }

    // The third add should succeed
    try
      {
        ptr2 += SafeInt<__int64>(1);
      }
    catch(SafeIntException&)
      {
        cerr << "Error in case PtrS3Add64Verify (3): ";
        cerr << "ptr = "  << ptr2 << ", ";
        cerr << "sizeof = "  << sizeof(S3) << endl;
      }

    // Fourth add should wrap
    try
      {
        const S3* pp = ptr2;
        ptr2 += SafeInt<__int64>(1);

        cerr << "Error in case PtrS3Add64Verify (4): ";
        cerr << "ptr = "  << pp << ", ";
        cerr << "sizeof = "  << sizeof(S3) << endl;
      }
    catch(SafeIntException&)
      {
      }
  }

  void PtrS4Add8Verify()
  {
    S4* BASE = (S4*)(((size_t)-1) -sizeof(S4));
    S4 *ptr1 = BASE, *ptr2 = BASE;

    // The first add should succeed
    try
      {
        ptr1 += SafeInt<unsigned __int8>(1);
      }
    catch(SafeIntException&)
      {
        cerr << "Error in case PtrS4Add8Verify (1): ";
        cerr << "ptr = "  << ptr1 << ", ";
        cerr << "sizeof = "  << sizeof(S4) << endl;
      }

    // Second add should wrap
    try
      {
        const S4* pp = ptr1;
        ptr1 += SafeInt<unsigned __int8>(1);

        cerr << "Error in case PtrS4Add8Verify (2): ";
        cerr << "ptr = "  << pp << ", ";
        cerr << "sizeof = "  << sizeof(S4) << endl;
      }
    catch(SafeIntException&)
      {
      }

    // The third add should succeed
    try
      {
        ptr2 += SafeInt<__int8>(1);
      }
    catch(SafeIntException&)
      {
        cerr << "Error in case PtrS4Add8Verify (3): ";
        cerr << "ptr = "  << ptr2 << ", ";
        cerr << "sizeof = "  << sizeof(S4) << endl;
      }

    // Fourth add should wrap
    try
      {
        const S4* pp = ptr2;
        ptr2 += SafeInt<__int8>(1);

        cerr << "Error in case PtrS4Add8Verify (4): ";
        cerr << "ptr = "  << pp << ", ";
        cerr << "sizeof = "  << sizeof(S4) << endl;
      }
    catch(SafeIntException&)
      {
      }
  }

  void PtrS4Add16Verify()
  {
    S4* BASE = (S4*)(((size_t)-1) -sizeof(S4));
    S4 *ptr1 = BASE, *ptr2 = BASE;

    // The first add should succeed
    try
      {
        ptr1 += SafeInt<unsigned __int16>(1);
      }
    catch(SafeIntException&)
      {
        cerr << "Error in case PtrS4Add16Verify (1): ";
        cerr << "ptr = "  << ptr1 << ", ";
        cerr << "sizeof = "  << sizeof(S4) << endl;
      }

    // Second add should wrap
    try
      {
        const S4* pp = ptr1;
        ptr1 += SafeInt<unsigned __int16>(1);

        cerr << "Error in case PtrS4Add16Verify (2): ";
        cerr << "ptr = "  << pp << ", ";
        cerr << "sizeof = "  << sizeof(S4) << endl;
      }
    catch(SafeIntException&)
      {
      }

    // The third add should succeed
    try
      {
        ptr2 += SafeInt<__int16>(1);
      }
    catch(SafeIntException&)
      {
        cerr << "Error in case PtrS4Add16Verify (3): ";
        cerr << "ptr = "  << ptr2 << ", ";
        cerr << "sizeof = "  << sizeof(S4) << endl;
      }

    // Fourth add should wrap
    try
      {
        const S4* pp = ptr2;
        ptr2 += SafeInt<__int16>(1);

        cerr << "Error in case PtrS4Add16Verify (4): ";
        cerr << "ptr = "  << pp << ", ";
        cerr << "sizeof = "  << sizeof(S4) << endl;
      }
    catch(SafeIntException&)
      {
      }
  }

  void PtrS4Add32Verify()
  {
    S4* BASE = (S4*)(((size_t)-1) -sizeof(S4));
    S4 *ptr1 = BASE, *ptr2 = BASE;

    // The first add should succeed
    try
      {
        ptr1 += SafeInt<unsigned __int32>(1);
      }
    catch(SafeIntException&)
      {
        cerr << "Error in case PtrS4Add32Verify (1): ";
        cerr << "ptr = "  << ptr1 << ", ";
        cerr << "sizeof = "  << sizeof(S4) << endl;
      }

    // Second add should wrap
    try
      {
        const S4* pp = ptr1;
        ptr1 += SafeInt<unsigned __int32>(1);

        cerr << "Error in case PtrS4Add32Verify (2): ";
        cerr << "ptr = "  << pp << ", ";
        cerr << "sizeof = "  << sizeof(S4) << endl;
      }
    catch(SafeIntException&)
      {
      }

    // The third add should succeed
    try
      {
        ptr2 += SafeInt<__int32>(1);
      }
    catch(SafeIntException&)
      {
        cerr << "Error in case PtrS4Add32Verify (3): ";
        cerr << "ptr = "  << ptr2 << ", ";
        cerr << "sizeof = "  << sizeof(S4) << endl;
      }

    // Fourth add should wrap
    try
      {
        const S4* pp = ptr2;
        ptr2 += SafeInt<__int32>(1);

        cerr << "Error in case PtrS4Add32Verify (4): ";
        cerr << "ptr = "  << pp << ", ";
        cerr << "sizeof = "  << sizeof(S4) << endl;
      }
    catch(SafeIntException&)
      {
      }
  }

  void PtrS4Add64Verify()
  {
    S4* BASE = (S4*)(((size_t)-1) -sizeof(S4));
    S4 *ptr1 = BASE, *ptr2 = BASE;

    // The first add should succeed
    try
      {
        ptr1 += SafeInt<unsigned __int64>(1);
      }
    catch(SafeIntException&)
      {
        cerr << "Error in case PtrS4Add64Verify (1): ";
        cerr << "ptr = "  << ptr1 << ", ";
        cerr << "sizeof = "  << sizeof(S4) << endl;
      }

    // Second add should wrap
    try
      {
        const S4* pp = ptr1;
        ptr1 += SafeInt<unsigned __int64>(1);

        cerr << "Error in case PtrS4Add64Verify (2): ";
        cerr << "ptr = "  << pp << ", ";
        cerr << "sizeof = "  << sizeof(S4) << endl;
      }
    catch(SafeIntException&)
      {
      }

    // The third add should succeed
    try
      {
        ptr2 += SafeInt<__int64>(1);
      }
    catch(SafeIntException&)
      {
        cerr << "Error in case PtrS4Add64Verify (3): ";
        cerr << "ptr = "  << ptr2 << ", ";
        cerr << "sizeof = "  << sizeof(S4) << endl;
      }

    // Fourth add should wrap
    try
      {
        const S4* pp = ptr2;
        ptr2 += SafeInt<__int64>(1);

        cerr << "Error in case PtrS4Add64Verify (4): ";
        cerr << "ptr = "  << pp << ", ";
        cerr << "sizeof = "  << sizeof(S4) << endl;
      }
    catch(SafeIntException&)
      {
      }
  }

  void PtrS5Add8Verify()
  {
    S5* BASE = (S5*)(((size_t)-1) -sizeof(S5));
    S5 *ptr1 = BASE, *ptr2 = BASE;

    // The first add should succeed
    try
      {
        ptr1 += SafeInt<unsigned __int8>(1);
      }
    catch(SafeIntException&)
      {
        cerr << "Error in case PtrS5Add8Verify (1): ";
        cerr << "ptr = "  << ptr1 << ", ";
        cerr << "sizeof = "  << sizeof(S5) << endl;
      }

    // Second add should wrap
    try
      {
        const S5* pp = ptr1;
        ptr1 += SafeInt<unsigned __int8>(1);

        cerr << "Error in case PtrS5Add8Verify (2): ";
        cerr << "ptr = "  << pp << ", ";
        cerr << "sizeof = "  << sizeof(S5) << endl;
      }
    catch(SafeIntException&)
      {
      }

    // The third add should succeed
    try
      {
        ptr2 += SafeInt<__int8>(1);
      }
    catch(SafeIntException&)
      {
        cerr << "Error in case PtrS5Add8Verify (3): ";
        cerr << "ptr = "  << ptr2 << ", ";
        cerr << "sizeof = "  << sizeof(S5) << endl;
      }

    // Fourth add should wrap
    try
      {
        const S5* pp = ptr2;
        ptr2 += SafeInt<__int8>(1);

        cerr << "Error in case PtrS5Add8Verify (4): ";
        cerr << "ptr = "  << pp << ", ";
        cerr << "sizeof = "  << sizeof(S5) << endl;
      }
    catch(SafeIntException&)
      {
      }
  }

  void PtrS5Add16Verify()
  {
    S5* BASE = (S5*)(((size_t)-1) -sizeof(S5));
    S5 *ptr1 = BASE, *ptr2 = BASE;

    // The first add should succeed
    try
      {
        ptr1 += SafeInt<unsigned __int16>(1);
      }
    catch(SafeIntException&)
      {
        cerr << "Error in case PtrS5Add16Verify (1): ";
        cerr << "ptr = "  << ptr1 << ", ";
        cerr << "sizeof = "  << sizeof(S5) << endl;
      }

    // Second add should wrap
    try
      {
        const S5* pp = ptr1;
        ptr1 += SafeInt<unsigned __int16>(1);

        cerr << "Error in case PtrS5Add16Verify (2): ";
        cerr << "ptr = "  << pp << ", ";
        cerr << "sizeof = "  << sizeof(S5) << endl;
      }
    catch(SafeIntException&)
      {
      }

    // The third add should succeed
    try
      {
        ptr2 += SafeInt<__int16>(1);
      }
    catch(SafeIntException&)
      {
        cerr << "Error in case PtrS5Add16Verify (3): ";
        cerr << "ptr = "  << ptr2 << ", ";
        cerr << "sizeof = "  << sizeof(S5) << endl;
      }

    // Fourth add should wrap
    try
      {
        const S5* pp = ptr2;
        ptr2 += SafeInt<__int16>(1);

        cerr << "Error in case PtrS5Add16Verify (4): ";
        cerr << "ptr = "  << pp << ", ";
        cerr << "sizeof = "  << sizeof(S5) << endl;
      }
    catch(SafeIntException&)
      {
      }
  }

  void PtrS5Add32Verify()
  {
    S5* BASE = (S5*)(((size_t)-1) -sizeof(S5));
    S5 *ptr1 = BASE, *ptr2 = BASE;

    // The first add should succeed
    try
      {
        ptr1 += SafeInt<unsigned __int32>(1);
      }
    catch(SafeIntException&)
      {
        cerr << "Error in case PtrS5Add32Verify (1): ";
        cerr << "ptr = "  << ptr1 << ", ";
        cerr << "sizeof = "  << sizeof(S5) << endl;
      }

    // Second add should wrap
    try
      {
        const S5* pp = ptr1;
        ptr1 += SafeInt<unsigned __int32>(1);

        cerr << "Error in case PtrS5Add32Verify (2): ";
        cerr << "ptr = "  << pp << ", ";
        cerr << "sizeof = "  << sizeof(S5) << endl;
      }
    catch(SafeIntException&)
      {
      }

    // The third add should succeed
    try
      {
        ptr2 += SafeInt<__int32>(1);
      }
    catch(SafeIntException&)
      {
        cerr << "Error in case PtrS5Add32Verify (3): ";
        cerr << "ptr = "  << ptr2 << ", ";
        cerr << "sizeof = "  << sizeof(S5) << endl;
      }

    // Fourth add should wrap
    try
      {
        const S5* pp = ptr2;
        ptr2 += SafeInt<__int32>(1);

        cerr << "Error in case PtrS5Add32Verify (4): ";
        cerr << "ptr = "  << pp << ", ";
        cerr << "sizeof = "  << sizeof(S5) << endl;
      }
    catch(SafeIntException&)
      {
      }
  }

  void PtrS5Add64Verify()
  {
    S5* BASE = (S5*)(((size_t)-1) -sizeof(S5));
    S5 *ptr1 = BASE, *ptr2 = BASE;

    // The first add should succeed
    try
      {
        ptr1 += SafeInt<unsigned __int64>(1);
      }
    catch(SafeIntException&)
      {
        cerr << "Error in case PtrS5Add64Verify (1): ";
        cerr << "ptr = "  << ptr1 << ", ";
        cerr << "sizeof = "  << sizeof(S5) << endl;
      }

    // Second add should wrap
    try
      {
        const S5* pp = ptr1;
        ptr1 += SafeInt<unsigned __int64>(1);

        cerr << "Error in case PtrS5Add64Verify (2): ";
        cerr << "ptr = "  << pp << ", ";
        cerr << "sizeof = "  << sizeof(S5) << endl;
      }
    catch(SafeIntException&)
      {
      }

    // The third add should succeed
    try
      {
        ptr2 += SafeInt<__int64>(1);
      }
    catch(SafeIntException&)
      {
        cerr << "Error in case PtrS5Add64Verify (3): ";
        cerr << "ptr = "  << ptr2 << ", ";
        cerr << "sizeof = "  << sizeof(S5) << endl;
      }

    // Fourth add should wrap
    try
      {
        const S5* pp = ptr2;
        ptr2 += SafeInt<__int64>(1);

        cerr << "Error in case PtrS5Add64Verify (4): ";
        cerr << "ptr = "  << pp << ", ";
        cerr << "sizeof = "  << sizeof(S5) << endl;
      }
    catch(SafeIntException&)
      {
      }
  }

  void PtrS1Sub8Verify()
  {
    S1* BASE = (S1*)(0 + sizeof(S1));
    S1 *ptr1 = BASE, *ptr2 = BASE;

    // The first sub should succeed
    try
      {
        ptr1 -= SafeInt<unsigned __int8>(1);
      }
    catch(SafeIntException&)
      {
        cerr << "Error in case PtrS1Sub8Verify (1): ";
        cerr << "ptr = "  << ptr1 << ", ";
        cerr << "sizeof = "  << sizeof(S1) << endl;
      }

    // Second sub should wrap
    try
      {
        const S1* pp = ptr1;
        ptr1 -= SafeInt<unsigned __int8>(1);

        cerr << "Error in case PtrS1Sub8Verify (2): ";
        cerr << "ptr = "  << pp << ", ";
        cerr << "sizeof = "  << sizeof(S1) << endl;
      }
    catch(SafeIntException&)
      {
      }

    // The third sub should succeed
    try
      {
        ptr2 -= SafeInt<__int8>(1);
      }
    catch(SafeIntException&)
      {
        cerr << "Error in case PtrS1Sub8Verify (3): ";
        cerr << "ptr = "  << ptr2 << ", ";
        cerr << "sizeof = "  << sizeof(S1) << endl;
      }

    // Fourth sub should wrap
    try
      {
        const S1* pp = ptr2;
        ptr2 -= SafeInt<__int8>(1);

        cerr << "Error in case PtrS1Sub8Verify (4): ";
        cerr << "ptr = "  << pp << ", ";
        cerr << "sizeof = "  << sizeof(S1) << endl;
      }
    catch(SafeIntException&)
      {
      }
  }

  void PtrS1Sub16Verify()
  {
    S1* BASE = (S1*)(0 + sizeof(S1));
    S1 *ptr1 = BASE, *ptr2 = BASE;

    // The first sub should succeed
    try
      {
        ptr1 -= SafeInt<unsigned __int16>(1);
      }
    catch(SafeIntException&)
      {
        cerr << "Error in case PtrS1Sub16Verify (1): ";
        cerr << "ptr = "  << ptr1 << ", ";
        cerr << "sizeof = "  << sizeof(S1) << endl;
      }

    // Second sub should wrap
    try
      {
        const S1* pp = ptr1;
        ptr1 -= SafeInt<unsigned __int16>(1);

        cerr << "Error in case PtrS1Sub16Verify (2): ";
        cerr << "ptr = "  << pp << ", ";
        cerr << "sizeof = "  << sizeof(S1) << endl;
      }
    catch(SafeIntException&)
      {
      }

    // The third sub should succeed
    try
      {
        ptr2 -= SafeInt<__int16>(1);
      }
    catch(SafeIntException&)
      {
        cerr << "Error in case PtrS1Sub16Verify (3): ";
        cerr << "ptr = "  << ptr2 << ", ";
        cerr << "sizeof = "  << sizeof(S1) << endl;
      }

    // Fourth sub should wrap
    try
      {
        const S1* pp = ptr2;
        ptr2 -= SafeInt<__int16>(1);

        cerr << "Error in case PtrS1Sub16Verify (4): ";
        cerr << "ptr = "  << pp << ", ";
        cerr << "sizeof = "  << sizeof(S1) << endl;
      }
    catch(SafeIntException&)
      {
      }
  }

  void PtrS1Sub32Verify()
  {
    S1* BASE = (S1*)(0 + sizeof(S1));
    S1 *ptr1 = BASE, *ptr2 = BASE;

    // The first sub should succeed
    try
      {
        ptr1 -= SafeInt<unsigned __int32>(1);
      }
    catch(SafeIntException&)
      {
        cerr << "Error in case PtrS1Sub32Verify (1): ";
        cerr << "ptr = "  << ptr1 << ", ";
        cerr << "sizeof = "  << sizeof(S1) << endl;
      }

    // Second sub should wrap
    try
      {
        const S1* pp = ptr1;
        ptr1 -= SafeInt<unsigned __int32>(1);

        cerr << "Error in case PtrS1Sub32Verify (2): ";
        cerr << "ptr = "  << pp << ", ";
        cerr << "sizeof = "  << sizeof(S1) << endl;
      }
    catch(SafeIntException&)
      {
      }

    // The third sub should succeed
    try
      {
        ptr2 -= SafeInt<__int32>(1);
      }
    catch(SafeIntException&)
      {
        cerr << "Error in case PtrS1Sub32Verify (3): ";
        cerr << "ptr = "  << ptr2 << ", ";
        cerr << "sizeof = "  << sizeof(S1) << endl;
      }

    // Fourth sub should wrap
    try
      {
        const S1* pp = ptr2;
        ptr2 -= SafeInt<__int32>(1);

        cerr << "Error in case PtrS1Sub32Verify (4): ";
        cerr << "ptr = "  << pp << ", ";
        cerr << "sizeof = "  << sizeof(S1) << endl;
      }
    catch(SafeIntException&)
      {
      }
  }

  void PtrS1Sub64Verify()
  {
    S1* BASE = (S1*)(0 + sizeof(S1));
    S1 *ptr1 = BASE, *ptr2 = BASE;

    // The first sub should succeed
    try
      {
        ptr1 -= SafeInt<unsigned __int64>(1);
      }
    catch(SafeIntException&)
      {
        cerr << "Error in case PtrS1Sub64Verify (1): ";
        cerr << "ptr = "  << ptr1 << ", ";
        cerr << "sizeof = "  << sizeof(S1) << endl;
      }

    // Second sub should wrap
    try
      {
        const S1* pp = ptr1;
        ptr1 -= SafeInt<unsigned __int64>(1);

        cerr << "Error in case PtrS1Sub64Verify (2): ";
        cerr << "ptr = "  << pp << ", ";
        cerr << "sizeof = "  << sizeof(S1) << endl;
      }
    catch(SafeIntException&)
      {
      }

    // The third sub should succeed
    try
      {
        ptr2 -= SafeInt<__int64>(1);
      }
    catch(SafeIntException&)
      {
        cerr << "Error in case PtrS1Sub64Verify (3): ";
        cerr << "ptr = "  << ptr2 << ", ";
        cerr << "sizeof = "  << sizeof(S1) << endl;
      }

    // Fourth sub should wrap
    try
      {
        const S1* pp = ptr2;
        ptr2 -= SafeInt<__int64>(1);

        cerr << "Error in case PtrS1Sub64Verify (4): ";
        cerr << "ptr = "  << pp << ", ";
        cerr << "sizeof = "  << sizeof(S1) << endl;
      }
    catch(SafeIntException&)
      {
      }
  }

  void PtrS2Sub8Verify()
  {
    S2* BASE = (S2*)(0 + sizeof(S2));
    S2 *ptr1 = BASE, *ptr2 = BASE;

    // The first sub should succeed
    try
      {
        ptr1 -= SafeInt<unsigned __int8>(1);
      }
    catch(SafeIntException&)
      {
        cerr << "Error in case PtrS2Sub8Verify (1): ";
        cerr << "ptr = "  << ptr1 << ", ";
        cerr << "sizeof = "  << sizeof(S2) << endl;
      }

    // Second sub should wrap
    try
      {
        const S2* pp = ptr1;
        ptr1 -= SafeInt<unsigned __int8>(1);

        cerr << "Error in case PtrS2Sub8Verify (2): ";
        cerr << "ptr = "  << pp << ", ";
        cerr << "sizeof = "  << sizeof(S2) << endl;
      }
    catch(SafeIntException&)
      {
      }

    // The third sub should succeed
    try
      {
        ptr2 -= SafeInt<__int8>(1);
      }
    catch(SafeIntException&)
      {
        cerr << "Error in case PtrS2Sub8Verify (3): ";
        cerr << "ptr = "  << ptr2 << ", ";
        cerr << "sizeof = "  << sizeof(S2) << endl;
      }

    // Fourth sub should wrap
    try
      {
        const S2* pp = ptr2;
        ptr2 -= SafeInt<__int8>(1);

        cerr << "Error in case PtrS2Sub8Verify (4): ";
        cerr << "ptr = "  << pp << ", ";
        cerr << "sizeof = "  << sizeof(S2) << endl;
      }
    catch(SafeIntException&)
      {
      }
  }

  void PtrS2Sub16Verify()
  {
    S2* BASE = (S2*)(0 + sizeof(S2));
    S2 *ptr1 = BASE, *ptr2 = BASE;

    // The first sub should succeed
    try
      {
        ptr1 -= SafeInt<unsigned __int16>(1);
      }
    catch(SafeIntException&)
      {
        cerr << "Error in case PtrS2Sub16Verify (1): ";
        cerr << "ptr = "  << ptr1 << ", ";
        cerr << "sizeof = "  << sizeof(S2) << endl;
      }

    // Second sub should wrap
    try
      {
        const S2* pp = ptr1;
        ptr1 -= SafeInt<unsigned __int16>(1);

        cerr << "Error in case PtrS2Sub16Verify (2): ";
        cerr << "ptr = "  << pp << ", ";
        cerr << "sizeof = "  << sizeof(S2) << endl;
      }
    catch(SafeIntException&)
      {
      }

    // The third sub should succeed
    try
      {
        ptr2 -= SafeInt<__int16>(1);
      }
    catch(SafeIntException&)
      {
        cerr << "Error in case PtrS2Sub16Verify (3): ";
        cerr << "ptr = "  << ptr2 << ", ";
        cerr << "sizeof = "  << sizeof(S2) << endl;
      }

    // Fourth sub should wrap
    try
      {
        const S2* pp = ptr2;
        ptr2 -= SafeInt<__int16>(1);

        cerr << "Error in case PtrS2Sub16Verify (4): ";
        cerr << "ptr = "  << pp << ", ";
        cerr << "sizeof = "  << sizeof(S2) << endl;
      }
    catch(SafeIntException&)
      {
      }
  }

  void PtrS2Sub32Verify()
  {
    S2* BASE = (S2*)(0 + sizeof(S2));
    S2 *ptr1 = BASE, *ptr2 = BASE;

    // The first sub should succeed
    try
      {
        ptr1 -= SafeInt<unsigned __int32>(1);
      }
    catch(SafeIntException&)
      {
        cerr << "Error in case PtrS2Sub32Verify (1): ";
        cerr << "ptr = "  << ptr1 << ", ";
        cerr << "sizeof = "  << sizeof(S2) << endl;
      }

    // Second sub should wrap
    try
      {
        const S2* pp = ptr1;
        ptr1 -= SafeInt<unsigned __int32>(1);

        cerr << "Error in case PtrS2Sub32Verify (2): ";
        cerr << "ptr = "  << pp << ", ";
        cerr << "sizeof = "  << sizeof(S2) << endl;
      }
    catch(SafeIntException&)
      {
      }

    // The third sub should succeed
    try
      {
        ptr2 -= SafeInt<__int32>(1);
      }
    catch(SafeIntException&)
      {
        cerr << "Error in case PtrS2Sub32Verify (3): ";
        cerr << "ptr = "  << ptr2 << ", ";
        cerr << "sizeof = "  << sizeof(S2) << endl;
      }

    // Fourth sub should wrap
    try
      {
        const S2* pp = ptr2;
        ptr2 -= SafeInt<__int32>(1);

        cerr << "Error in case PtrS2Sub32Verify (4): ";
        cerr << "ptr = "  << pp << ", ";
        cerr << "sizeof = "  << sizeof(S2) << endl;
      }
    catch(SafeIntException&)
      {
      }
  }

  void PtrS2Sub64Verify()
  {
    S2* BASE = (S2*)(0 + sizeof(S2));
    S2 *ptr1 = BASE, *ptr2 = BASE;

    // The first sub should succeed
    try
      {
        ptr1 -= SafeInt<unsigned __int64>(1);
      }
    catch(SafeIntException&)
      {
        cerr << "Error in case PtrS2Sub64Verify (1): ";
        cerr << "ptr = "  << ptr1 << ", ";
        cerr << "sizeof = "  << sizeof(S2) << endl;
      }

    // Second sub should wrap
    try
      {
        const S2* pp = ptr1;
        ptr1 -= SafeInt<unsigned __int64>(1);

        cerr << "Error in case PtrS2Sub64Verify (2): ";
        cerr << "ptr = "  << pp << ", ";
        cerr << "sizeof = "  << sizeof(S2) << endl;
      }
    catch(SafeIntException&)
      {
      }

    // The third sub should succeed
    try
      {
        ptr2 -= SafeInt<__int64>(1);
      }
    catch(SafeIntException&)
      {
        cerr << "Error in case PtrS2Sub64Verify (3): ";
        cerr << "ptr = "  << ptr2 << ", ";
        cerr << "sizeof = "  << sizeof(S2) << endl;
      }

    // Fourth sub should wrap
    try
      {
        const S2* pp = ptr2;
        ptr2 -= SafeInt<__int64>(1);

        cerr << "Error in case PtrS2Sub64Verify (4): ";
        cerr << "ptr = "  << pp << ", ";
        cerr << "sizeof = "  << sizeof(S2) << endl;
      }
    catch(SafeIntException&)
      {
      }
  }

  void PtrS3Sub8Verify()
  {
    S3* BASE = (S3*)(0 + sizeof(S3));
    S3 *ptr1 = BASE, *ptr2 = BASE;

    // The first sub should succeed
    try
      {
        ptr1 -= SafeInt<unsigned __int8>(1);
      }
    catch(SafeIntException&)
      {
        cerr << "Error in case PtrS3Sub8Verify (1): ";
        cerr << "ptr = "  << ptr1 << ", ";
        cerr << "sizeof = "  << sizeof(S3) << endl;
      }

    // Second sub should wrap
    try
      {
        const S3* pp = ptr1;
        ptr1 -= SafeInt<unsigned __int8>(1);

        cerr << "Error in case PtrS3Sub8Verify (2): ";
        cerr << "ptr = "  << pp << ", ";
        cerr << "sizeof = "  << sizeof(S3) << endl;
      }
    catch(SafeIntException&)
      {
      }

    // The third sub should succeed
    try
      {
        ptr2 -= SafeInt<__int8>(1);
      }
    catch(SafeIntException&)
      {
        cerr << "Error in case PtrS3Sub8Verify (3): ";
        cerr << "ptr = "  << ptr2 << ", ";
        cerr << "sizeof = "  << sizeof(S3) << endl;
      }

    // Fourth sub should wrap
    try
      {
        const S3* pp = ptr2;
        ptr2 -= SafeInt<__int8>(1);

        cerr << "Error in case PtrS3Sub8Verify (4): ";
        cerr << "ptr = "  << pp << ", ";
        cerr << "sizeof = "  << sizeof(S3) << endl;
      }
    catch(SafeIntException&)
      {
      }
  }

  void PtrS3Sub16Verify()
  {
    S3* BASE = (S3*)(0 + sizeof(S3));
    S3 *ptr1 = BASE, *ptr2 = BASE;

    // The first sub should succeed
    try
      {
        ptr1 -= SafeInt<unsigned __int16>(1);
      }
    catch(SafeIntException&)
      {
        cerr << "Error in case PtrS3Sub16Verify (1): ";
        cerr << "ptr = "  << ptr1 << ", ";
        cerr << "sizeof = "  << sizeof(S3) << endl;
      }

    // Second sub should wrap
    try
      {
        const S3* pp = ptr1;
        ptr1 -= SafeInt<unsigned __int16>(1);

        cerr << "Error in case PtrS3Sub16Verify (2): ";
        cerr << "ptr = "  << pp << ", ";
        cerr << "sizeof = "  << sizeof(S3) << endl;
      }
    catch(SafeIntException&)
      {
      }

    // The third sub should succeed
    try
      {
        ptr2 -= SafeInt<__int16>(1);
      }
    catch(SafeIntException&)
      {
        cerr << "Error in case PtrS3Sub16Verify (3): ";
        cerr << "ptr = "  << ptr2 << ", ";
        cerr << "sizeof = "  << sizeof(S3) << endl;
      }

    // Fourth sub should wrap
    try
      {
        const S3* pp = ptr2;
        ptr2 -= SafeInt<__int16>(1);

        cerr << "Error in case PtrS3Sub16Verify (4): ";
        cerr << "ptr = "  << pp << ", ";
        cerr << "sizeof = "  << sizeof(S3) << endl;
      }
    catch(SafeIntException&)
      {
      }
  }

  void PtrS3Sub32Verify()
  {
    S3* BASE = (S3*)(0 + sizeof(S3));
    S3 *ptr1 = BASE, *ptr2 = BASE;

    // The first sub should succeed
    try
      {
        ptr1 -= SafeInt<unsigned __int32>(1);
      }
    catch(SafeIntException&)
      {
        cerr << "Error in case PtrS3Sub32Verify (1): ";
        cerr << "ptr = "  << ptr1 << ", ";
        cerr << "sizeof = "  << sizeof(S3) << endl;
      }

    // Second sub should wrap
    try
      {
        const S3* pp = ptr1;
        ptr1 -= SafeInt<unsigned __int32>(1);

        cerr << "Error in case PtrS3Sub32Verify (2): ";
        cerr << "ptr = "  << pp << ", ";
        cerr << "sizeof = "  << sizeof(S3) << endl;
      }
    catch(SafeIntException&)
      {
      }

    // The third sub should succeed
    try
      {
        ptr2 -= SafeInt<__int32>(1);
      }
    catch(SafeIntException&)
      {
        cerr << "Error in case PtrS3Sub32Verify (3): ";
        cerr << "ptr = "  << ptr2 << ", ";
        cerr << "sizeof = "  << sizeof(S3) << endl;
      }

    // Fourth sub should wrap
    try
      {
        const S3* pp = ptr2;
        ptr2 -= SafeInt<__int32>(1);

        cerr << "Error in case PtrS3Sub32Verify (4): ";
        cerr << "ptr = "  << pp << ", ";
        cerr << "sizeof = "  << sizeof(S3) << endl;
      }
    catch(SafeIntException&)
      {
      }
  }

  void PtrS3Sub64Verify()
  {
    S3* BASE = (S3*)(0 + sizeof(S3));
    S3 *ptr1 = BASE, *ptr2 = BASE;

    // The first sub should succeed
    try
      {
        ptr1 -= SafeInt<unsigned __int64>(1);
      }
    catch(SafeIntException&)
      {
        cerr << "Error in case PtrS3Sub64Verify (1): ";
        cerr << "ptr = "  << ptr1 << ", ";
        cerr << "sizeof = "  << sizeof(S3) << endl;
      }

    // Second sub should wrap
    try
      {
        const S3* pp = ptr1;
        ptr1 -= SafeInt<unsigned __int64>(1);

        cerr << "Error in case PtrS3Sub64Verify (2): ";
        cerr << "ptr = "  << pp << ", ";
        cerr << "sizeof = "  << sizeof(S3) << endl;
      }
    catch(SafeIntException&)
      {
      }

    // The third sub should succeed
    try
      {
        ptr2 -= SafeInt<__int64>(1);
      }
    catch(SafeIntException&)
      {
        cerr << "Error in case PtrS3Sub64Verify (3): ";
        cerr << "ptr = "  << ptr2 << ", ";
        cerr << "sizeof = "  << sizeof(S3) << endl;
      }

    // Fourth sub should wrap
    try
      {
        const S3* pp = ptr2;
        ptr2 -= SafeInt<__int64>(1);

        cerr << "Error in case PtrS3Sub64Verify (4): ";
        cerr << "ptr = "  << pp << ", ";
        cerr << "sizeof = "  << sizeof(S3) << endl;
      }
    catch(SafeIntException&)
      {
      }
  }

  void PtrS4Sub8Verify()
  {
    S4* BASE = (S4*)(0 + sizeof(S4));
    S4 *ptr1 = BASE, *ptr2 = BASE;

    // The first sub should succeed
    try
      {
        ptr1 -= SafeInt<unsigned __int8>(1);
      }
    catch(SafeIntException&)
      {
        cerr << "Error in case PtrS4Sub8Verify (1): ";
        cerr << "ptr = "  << ptr1 << ", ";
        cerr << "sizeof = "  << sizeof(S4) << endl;
      }

    // Second sub should wrap
    try
      {
        const S4* pp = ptr1;
        ptr1 -= SafeInt<unsigned __int8>(1);

        cerr << "Error in case PtrS4Sub8Verify (2): ";
        cerr << "ptr = "  << pp << ", ";
        cerr << "sizeof = "  << sizeof(S4) << endl;
      }
    catch(SafeIntException&)
      {
      }

    // The third sub should succeed
    try
      {
        ptr2 -= SafeInt<__int8>(1);
      }
    catch(SafeIntException&)
      {
        cerr << "Error in case PtrS4Sub8Verify (3): ";
        cerr << "ptr = "  << ptr2 << ", ";
        cerr << "sizeof = "  << sizeof(S4) << endl;
      }

    // Fourth sub should wrap
    try
      {
        const S4* pp = ptr2;
        ptr2 -= SafeInt<__int8>(1);

        cerr << "Error in case PtrS4Sub8Verify (4): ";
        cerr << "ptr = "  << pp << ", ";
        cerr << "sizeof = "  << sizeof(S4) << endl;
      }
    catch(SafeIntException&)
      {
      }
  }

  void PtrS4Sub16Verify()
  {
    S4* BASE = (S4*)(0 + sizeof(S4));
    S4 *ptr1 = BASE, *ptr2 = BASE;

    // The first sub should succeed
    try
      {
        ptr1 -= SafeInt<unsigned __int16>(1);
      }
    catch(SafeIntException&)
      {
        cerr << "Error in case PtrS4Sub16Verify (1): ";
        cerr << "ptr = "  << ptr1 << ", ";
        cerr << "sizeof = "  << sizeof(S4) << endl;
      }

    // Second sub should wrap
    try
      {
        const S4* pp = ptr1;
        ptr1 -= SafeInt<unsigned __int16>(1);

        cerr << "Error in case PtrS4Sub16Verify (2): ";
        cerr << "ptr = "  << pp << ", ";
        cerr << "sizeof = "  << sizeof(S4) << endl;
      }
    catch(SafeIntException&)
      {
      }

    // The third sub should succeed
    try
      {
        ptr2 -= SafeInt<__int16>(1);
      }
    catch(SafeIntException&)
      {
        cerr << "Error in case PtrS4Sub16Verify (3): ";
        cerr << "ptr = "  << ptr2 << ", ";
        cerr << "sizeof = "  << sizeof(S4) << endl;
      }

    // Fourth sub should wrap
    try
      {
        const S4* pp = ptr2;
        ptr2 -= SafeInt<__int16>(1);

        cerr << "Error in case PtrS4Sub16Verify (4): ";
        cerr << "ptr = "  << pp << ", ";
        cerr << "sizeof = "  << sizeof(S4) << endl;
      }
    catch(SafeIntException&)
      {
      }
  }

  void PtrS4Sub32Verify()
  {
    S4* BASE = (S4*)(0 + sizeof(S4));
    S4 *ptr1 = BASE, *ptr2 = BASE;

    // The first sub should succeed
    try
      {
        ptr1 -= SafeInt<unsigned __int32>(1);
      }
    catch(SafeIntException&)
      {
        cerr << "Error in case PtrS4Sub32Verify (1): ";
        cerr << "ptr = "  << ptr1 << ", ";
        cerr << "sizeof = "  << sizeof(S4) << endl;
      }

    // Second sub should wrap
    try
      {
        const S4* pp = ptr1;
        ptr1 -= SafeInt<unsigned __int32>(1);

        cerr << "Error in case PtrS4Sub32Verify (2): ";
        cerr << "ptr = "  << pp << ", ";
        cerr << "sizeof = "  << sizeof(S4) << endl;
      }
    catch(SafeIntException&)
      {
      }

    // The third sub should succeed
    try
      {
        ptr2 -= SafeInt<__int32>(1);
      }
    catch(SafeIntException&)
      {
        cerr << "Error in case PtrS4Sub32Verify (3): ";
        cerr << "ptr = "  << ptr2 << ", ";
        cerr << "sizeof = "  << sizeof(S4) << endl;
      }

    // Fourth sub should wrap
    try
      {
        const S4* pp = ptr2;
        ptr2 -= SafeInt<__int32>(1);

        cerr << "Error in case PtrS4Sub32Verify (4): ";
        cerr << "ptr = "  << pp << ", ";
        cerr << "sizeof = "  << sizeof(S4) << endl;
      }
    catch(SafeIntException&)
      {
      }
  }

  void PtrS4Sub64Verify()
  {
    S4* BASE = (S4*)(0 + sizeof(S4));
    S4 *ptr1 = BASE, *ptr2 = BASE;

    // The first sub should succeed
    try
      {
        ptr1 -= SafeInt<unsigned __int64>(1);
      }
    catch(SafeIntException&)
      {
        cerr << "Error in case PtrS4Sub64Verify (1): ";
        cerr << "ptr = "  << ptr1 << ", ";
        cerr << "sizeof = "  << sizeof(S4) << endl;
      }

    // Second sub should wrap
    try
      {
        const S4* pp = ptr1;
        ptr1 -= SafeInt<unsigned __int64>(1);

        cerr << "Error in case PtrS4Sub64Verify (2): ";
        cerr << "ptr = "  << pp << ", ";
        cerr << "sizeof = "  << sizeof(S4) << endl;
      }
    catch(SafeIntException&)
      {
      }

    // The third sub should succeed
    try
      {
        ptr2 -= SafeInt<__int64>(1);
      }
    catch(SafeIntException&)
      {
        cerr << "Error in case PtrS4Sub64Verify (3): ";
        cerr << "ptr = "  << ptr2 << ", ";
        cerr << "sizeof = "  << sizeof(S4) << endl;
      }

    // Fourth sub should wrap
    try
      {
        const S4* pp = ptr2;
        ptr2 -= SafeInt<__int64>(1);

        cerr << "Error in case PtrS4Sub64Verify (4): ";
        cerr << "ptr = "  << pp << ", ";
        cerr << "sizeof = "  << sizeof(S4) << endl;
      }
    catch(SafeIntException&)
      {
      }
  }

  void PtrS5Sub8Verify()
  {
    S5* BASE = (S5*)(0 + sizeof(S5));
    S5 *ptr1 = BASE, *ptr2 = BASE;

    // The first sub should succeed
    try
      {
        ptr1 -= SafeInt<unsigned __int8>(1);
      }
    catch(SafeIntException&)
      {
        cerr << "Error in case PtrS5Sub8Verify (1): ";
        cerr << "ptr = "  << ptr1 << ", ";
        cerr << "sizeof = "  << sizeof(S5) << endl;
      }

    // Second sub should wrap
    try
      {
        const S5* pp = ptr1;
        ptr1 -= SafeInt<unsigned __int8>(1);

        cerr << "Error in case PtrS5Sub8Verify (2): ";
        cerr << "ptr = "  << pp << ", ";
        cerr << "sizeof = "  << sizeof(S5) << endl;
      }
    catch(SafeIntException&)
      {
      }

    // The third sub should succeed
    try
      {
        ptr2 -= SafeInt<__int8>(1);
      }
    catch(SafeIntException&)
      {
        cerr << "Error in case PtrS5Sub8Verify (3): ";
        cerr << "ptr = "  << ptr2 << ", ";
        cerr << "sizeof = "  << sizeof(S5) << endl;
      }

    // Fourth sub should wrap
    try
      {
        const S5* pp = ptr2;
        ptr2 -= SafeInt<__int8>(1);

        cerr << "Error in case PtrS5Sub8Verify (4): ";
        cerr << "ptr = "  << pp << ", ";
        cerr << "sizeof = "  << sizeof(S5) << endl;
      }
    catch(SafeIntException&)
      {
      }
  }

  void PtrS5Sub16Verify()
  {
    S5* BASE = (S5*)(0 + sizeof(S5));
    S5 *ptr1 = BASE, *ptr2 = BASE;

    // The first sub should succeed
    try
      {
        ptr1 -= SafeInt<unsigned __int16>(1);
      }
    catch(SafeIntException&)
      {
        cerr << "Error in case PtrS5Sub16Verify (1): ";
        cerr << "ptr = "  << ptr1 << ", ";
        cerr << "sizeof = "  << sizeof(S5) << endl;
      }

    // Second sub should wrap
    try
      {
        const S5* pp = ptr1;
        ptr1 -= SafeInt<unsigned __int16>(1);

        cerr << "Error in case PtrS5Sub16Verify (2): ";
        cerr << "ptr = "  << pp << ", ";
        cerr << "sizeof = "  << sizeof(S5) << endl;
      }
    catch(SafeIntException&)
      {
      }

    // The third sub should succeed
    try
      {
        ptr2 -= SafeInt<__int16>(1);
      }
    catch(SafeIntException&)
      {
        cerr << "Error in case PtrS5Sub16Verify (3): ";
        cerr << "ptr = "  << ptr2 << ", ";
        cerr << "sizeof = "  << sizeof(S5) << endl;
      }

    // Fourth sub should wrap
    try
      {
        const S5* pp = ptr2;
        ptr2 -= SafeInt<__int16>(1);

        cerr << "Error in case PtrS5Sub16Verify (4): ";
        cerr << "ptr = "  << pp << ", ";
        cerr << "sizeof = "  << sizeof(S5) << endl;
      }
    catch(SafeIntException&)
      {
      }
  }

  void PtrS5Sub32Verify()
  {
    S5* BASE = (S5*)(0 + sizeof(S5));
    S5 *ptr1 = BASE, *ptr2 = BASE;

    // The first sub should succeed
    try
      {
        ptr1 -= SafeInt<unsigned __int32>(1);
      }
    catch(SafeIntException&)
      {
        cerr << "Error in case PtrS5Sub32Verify (1): ";
        cerr << "ptr = "  << ptr1 << ", ";
        cerr << "sizeof = "  << sizeof(S5) << endl;
      }

    // Second sub should wrap
    try
      {
        const S5* pp = ptr1;
        ptr1 -= SafeInt<unsigned __int32>(1);

        cerr << "Error in case PtrS5Sub32Verify (2): ";
        cerr << "ptr = "  << pp << ", ";
        cerr << "sizeof = "  << sizeof(S5) << endl;
      }
    catch(SafeIntException&)
      {
      }

    // The third sub should succeed
    try
      {
        ptr2 -= SafeInt<__int32>(1);
      }
    catch(SafeIntException&)
      {
        cerr << "Error in case PtrS5Sub32Verify (3): ";
        cerr << "ptr = "  << ptr2 << ", ";
        cerr << "sizeof = "  << sizeof(S5) << endl;
      }

    // Fourth sub should wrap
    try
      {
        const S5* pp = ptr2;
        ptr2 -= SafeInt<__int32>(1);

        cerr << "Error in case PtrS5Sub32Verify (4): ";
        cerr << "ptr = "  << pp << ", ";
        cerr << "sizeof = "  << sizeof(S5) << endl;
      }
    catch(SafeIntException&)
      {
      }
  }

  void PtrS5Sub64Verify()
  {
    S5* BASE = (S5*)(0 + sizeof(S5));
    S5 *ptr1 = BASE, *ptr2 = BASE;

    // The first sub should succeed
    try
      {
        ptr1 -= SafeInt<unsigned __int64>(1);
      }
    catch(SafeIntException&)
      {
        cerr << "Error in case PtrS5Sub64Verify (1): ";
        cerr << "ptr = "  << ptr1 << ", ";
        cerr << "sizeof = "  << sizeof(S5) << endl;
      }

    // Second sub should wrap
    try
      {
        const S5* pp = ptr1;
        ptr1 -= SafeInt<unsigned __int64>(1);

        cerr << "Error in case PtrS5Sub64Verify (2): ";
        cerr << "ptr = "  << pp << ", ";
        cerr << "sizeof = "  << sizeof(S5) << endl;
      }
    catch(SafeIntException&)
      {
      }

    // The third sub should succeed
    try
      {
        ptr2 -= SafeInt<__int64>(1);
      }
    catch(SafeIntException&)
      {
        cerr << "Error in case PtrS5Sub64Verify (3): ";
        cerr << "ptr = "  << ptr2 << ", ";
        cerr << "sizeof = "  << sizeof(S5) << endl;
      }

    // Fourth sub should wrap
    try
      {
        const S5* pp = ptr2;
        ptr2 -= SafeInt<__int64>(1);

        cerr << "Error in case PtrS5Sub64Verify (4): ";
        cerr << "ptr = "  << pp << ", ";
        cerr << "sizeof = "  << sizeof(S5) << endl;
      }
    catch(SafeIntException&)
      {
      }
  }

  void PtrVerify()
  {
    cout << "Verifying Pointers:" << endl;

    PtrS1Add8Verify();
    PtrS1Add16Verify();
    PtrS1Add32Verify();
    PtrS1Add64Verify();

    PtrS2Add8Verify();
    PtrS2Add16Verify();
    PtrS2Add32Verify();
    PtrS2Add64Verify();

    PtrS3Add8Verify();
    PtrS3Add16Verify();
    PtrS3Add32Verify();
    PtrS3Add64Verify();

    PtrS4Add8Verify();
    PtrS4Add16Verify();
    PtrS4Add32Verify();
    PtrS4Add64Verify();

    PtrS5Add8Verify();
    PtrS5Add16Verify();
    PtrS5Add32Verify();
    PtrS5Add64Verify();

    PtrS1Sub8Verify();
    PtrS1Sub16Verify();
    PtrS1Sub32Verify();
    PtrS1Sub64Verify();

    PtrS2Sub8Verify();
    PtrS2Sub16Verify();
    PtrS2Sub32Verify();
    PtrS2Sub64Verify();

    PtrS3Sub8Verify();
    PtrS3Sub16Verify();
    PtrS3Sub32Verify();
    PtrS3Sub64Verify();

    PtrS4Sub8Verify();
    PtrS4Sub16Verify();
    PtrS4Sub32Verify();
    PtrS4Sub64Verify();

    PtrS5Sub8Verify();
    PtrS5Sub16Verify();
    PtrS5Sub32Verify();
    PtrS5Sub64Verify();
  }

} // NAMESPACE
