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


  Copyright (c) Microsoft Corporation. All rights reserved.
*/
#include "TestMain.h"

namespace sub_verify
{

  template <typename T, typename U>
  struct SubTest
  {
    T x;
    U y;
    bool fExpected;
  };

  // For the most part, unsigned-unsigned combinations are not going to give us any problems
  static const SubTest< unsigned __int64, unsigned __int64 > uint64_uint64[] =
    {
      { 0x0000000000000000ULL, 0x0000000000000000ULL, true},
      { 0x0000000000000001ULL, 0x0000000000000000ULL, true},
      { 0x0000000000000002ULL, 0x0000000000000000ULL, true},
      { 0x000000007ffffffeULL, 0x0000000000000000ULL, true},
      { 0x000000007fffffffULL, 0x0000000000000000ULL, true},
      { 0x0000000080000000ULL, 0x0000000000000000ULL, true},
      { 0x0000000080000001ULL, 0x0000000000000000ULL, true},
      { 0x00000000fffffffeULL, 0x0000000000000000ULL, true},
      { 0x00000000ffffffffULL, 0x0000000000000000ULL, true},
      { 0x0000000100000000ULL, 0x0000000000000000ULL, true},
      { 0x0000000200000000ULL, 0x0000000000000000ULL, true},
      { 0x7ffffffffffffffeULL, 0x0000000000000000ULL, true},
      { 0x7fffffffffffffffULL, 0x0000000000000000ULL, true},
      { 0x8000000000000000ULL, 0x0000000000000000ULL, true},
      { 0x8000000000000001ULL, 0x0000000000000000ULL, true},
      { 0xfffffffffffffffeULL, 0x0000000000000000ULL, true},
      { 0xffffffffffffffffULL, 0x0000000000000000ULL, true},

      { 0x0000000000000000ULL, 0x0000000000000001ULL, false},
      { 0x0000000000000001ULL, 0x0000000000000001ULL, true},
      { 0x0000000000000002ULL, 0x0000000000000001ULL, true},
      { 0x000000007ffffffeULL, 0x0000000000000001ULL, true},
      { 0x000000007fffffffULL, 0x0000000000000001ULL, true},
      { 0x0000000080000000ULL, 0x0000000000000001ULL, true},
      { 0x0000000080000001ULL, 0x0000000000000001ULL, true},
      { 0x00000000fffffffeULL, 0x0000000000000001ULL, true},
      { 0x00000000ffffffffULL, 0x0000000000000001ULL, true},
      { 0x0000000100000000ULL, 0x0000000000000001ULL, true},
      { 0x0000000200000000ULL, 0x0000000000000001ULL, true},
      { 0x7ffffffffffffffeULL, 0x0000000000000001ULL, true},
      { 0x7fffffffffffffffULL, 0x0000000000000001ULL, true},
      { 0x8000000000000000ULL, 0x0000000000000001ULL, true},
      { 0x8000000000000001ULL, 0x0000000000000001ULL, true},
      { 0xfffffffffffffffeULL, 0x0000000000000001ULL, true},
      { 0xffffffffffffffffULL, 0x0000000000000001ULL, true},

      { 0x0000000000000000ULL, 0x0000000000000002ULL, false},
      { 0x0000000000000001ULL, 0x0000000000000002ULL, false},
      { 0x0000000000000002ULL, 0x0000000000000002ULL, true},
      { 0x000000007ffffffeULL, 0x0000000000000002ULL, true},
      { 0x000000007fffffffULL, 0x0000000000000002ULL, true},
      { 0x0000000080000000ULL, 0x0000000000000002ULL, true},
      { 0x0000000080000001ULL, 0x0000000000000002ULL, true},
      { 0x00000000fffffffeULL, 0x0000000000000002ULL, true},
      { 0x00000000ffffffffULL, 0x0000000000000002ULL, true},
      { 0x0000000100000000ULL, 0x0000000000000002ULL, true},
      { 0x0000000200000000ULL, 0x0000000000000002ULL, true},
      { 0x7ffffffffffffffeULL, 0x0000000000000002ULL, true},
      { 0x7fffffffffffffffULL, 0x0000000000000002ULL, true},
      { 0x8000000000000000ULL, 0x0000000000000002ULL, true},
      { 0x8000000000000001ULL, 0x0000000000000002ULL, true},
      { 0xfffffffffffffffeULL, 0x0000000000000002ULL, true},
      { 0xffffffffffffffffULL, 0x0000000000000002ULL, true},

      { 0x0000000000000000ULL, 0x000000007ffffffeULL, false},
      { 0x0000000000000001ULL, 0x000000007ffffffeULL, false},
      { 0x0000000000000002ULL, 0x000000007ffffffeULL, false},
      { 0x000000007ffffffeULL, 0x000000007ffffffeULL, true},
      { 0x000000007fffffffULL, 0x000000007ffffffeULL, true},
      { 0x0000000080000000ULL, 0x000000007ffffffeULL, true},
      { 0x0000000080000001ULL, 0x000000007ffffffeULL, true},
      { 0x00000000fffffffeULL, 0x000000007ffffffeULL, true},
      { 0x00000000ffffffffULL, 0x000000007ffffffeULL, true},
      { 0x0000000100000000ULL, 0x000000007ffffffeULL, true},
      { 0x0000000200000000ULL, 0x000000007ffffffeULL, true},
      { 0x7ffffffffffffffeULL, 0x000000007ffffffeULL, true},
      { 0x7fffffffffffffffULL, 0x000000007ffffffeULL, true},
      { 0x8000000000000000ULL, 0x000000007ffffffeULL, true},
      { 0x8000000000000001ULL, 0x000000007ffffffeULL, true},
      { 0xfffffffffffffffeULL, 0x000000007ffffffeULL, true},
      { 0xffffffffffffffffULL, 0x000000007ffffffeULL, true},

      { 0x0000000000000000ULL, 0x000000007fffffffULL, false},
      { 0x0000000000000001ULL, 0x000000007fffffffULL, false},
      { 0x0000000000000002ULL, 0x000000007fffffffULL, false},
      { 0x000000007ffffffeULL, 0x000000007fffffffULL, false},
      { 0x000000007fffffffULL, 0x000000007fffffffULL, true},
      { 0x0000000080000000ULL, 0x000000007fffffffULL, true},
      { 0x0000000080000001ULL, 0x000000007fffffffULL, true},
      { 0x00000000fffffffeULL, 0x000000007fffffffULL, true},
      { 0x00000000ffffffffULL, 0x000000007fffffffULL, true},
      { 0x0000000100000000ULL, 0x000000007fffffffULL, true},
      { 0x0000000200000000ULL, 0x000000007fffffffULL, true},
      { 0x7ffffffffffffffeULL, 0x000000007fffffffULL, true},
      { 0x7fffffffffffffffULL, 0x000000007fffffffULL, true},
      { 0x8000000000000000ULL, 0x000000007fffffffULL, true},
      { 0x8000000000000001ULL, 0x000000007fffffffULL, true},
      { 0xfffffffffffffffeULL, 0x000000007fffffffULL, true},
      { 0xffffffffffffffffULL, 0x000000007fffffffULL, true},

      { 0x0000000000000000ULL, 0x0000000080000000ULL, false},
      { 0x0000000000000001ULL, 0x0000000080000000ULL, false},
      { 0x0000000000000002ULL, 0x0000000080000000ULL, false},
      { 0x000000007ffffffeULL, 0x0000000080000000ULL, false},
      { 0x000000007fffffffULL, 0x0000000080000000ULL, false},
      { 0x0000000080000000ULL, 0x0000000080000000ULL, true},
      { 0x0000000080000001ULL, 0x0000000080000000ULL, true},
      { 0x00000000fffffffeULL, 0x0000000080000000ULL, true},
      { 0x00000000ffffffffULL, 0x0000000080000000ULL, true},
      { 0x0000000100000000ULL, 0x0000000080000000ULL, true},
      { 0x0000000200000000ULL, 0x0000000080000000ULL, true},
      { 0x7ffffffffffffffeULL, 0x0000000080000000ULL, true},
      { 0x7fffffffffffffffULL, 0x0000000080000000ULL, true},
      { 0x8000000000000000ULL, 0x0000000080000000ULL, true},
      { 0x8000000000000001ULL, 0x0000000080000000ULL, true},
      { 0xfffffffffffffffeULL, 0x0000000080000000ULL, true},
      { 0xffffffffffffffffULL, 0x0000000080000000ULL, true},

      { 0x0000000000000000ULL, 0x0000000080000001ULL, false},
      { 0x0000000000000001ULL, 0x0000000080000001ULL, false},
      { 0x0000000000000002ULL, 0x0000000080000001ULL, false},
      { 0x000000007ffffffeULL, 0x0000000080000001ULL, false},
      { 0x000000007fffffffULL, 0x0000000080000001ULL, false},
      { 0x0000000080000000ULL, 0x0000000080000001ULL, false},
      { 0x0000000080000001ULL, 0x0000000080000001ULL, true},
      { 0x00000000fffffffeULL, 0x0000000080000001ULL, true},
      { 0x00000000ffffffffULL, 0x0000000080000001ULL, true},
      { 0x0000000100000000ULL, 0x0000000080000001ULL, true},
      { 0x0000000200000000ULL, 0x0000000080000001ULL, true},
      { 0x7ffffffffffffffeULL, 0x0000000080000001ULL, true},
      { 0x7fffffffffffffffULL, 0x0000000080000001ULL, true},
      { 0x8000000000000000ULL, 0x0000000080000001ULL, true},
      { 0x8000000000000001ULL, 0x0000000080000001ULL, true},
      { 0xfffffffffffffffeULL, 0x0000000080000001ULL, true},
      { 0xffffffffffffffffULL, 0x0000000080000001ULL, true},

      { 0x0000000000000000ULL, 0x00000000fffffffeULL, false},
      { 0x0000000000000001ULL, 0x00000000fffffffeULL, false},
      { 0x0000000000000002ULL, 0x00000000fffffffeULL, false},
      { 0x000000007ffffffeULL, 0x00000000fffffffeULL, false},
      { 0x000000007fffffffULL, 0x00000000fffffffeULL, false},
      { 0x0000000080000000ULL, 0x00000000fffffffeULL, false},
      { 0x0000000080000001ULL, 0x00000000fffffffeULL, false},
      { 0x00000000fffffffeULL, 0x00000000fffffffeULL, true},
      { 0x00000000ffffffffULL, 0x00000000fffffffeULL, true},
      { 0x0000000100000000ULL, 0x00000000fffffffeULL, true},
      { 0x0000000200000000ULL, 0x00000000fffffffeULL, true},
      { 0x7ffffffffffffffeULL, 0x00000000fffffffeULL, true},
      { 0x7fffffffffffffffULL, 0x00000000fffffffeULL, true},
      { 0x8000000000000000ULL, 0x00000000fffffffeULL, true},
      { 0x8000000000000001ULL, 0x00000000fffffffeULL, true},
      { 0xfffffffffffffffeULL, 0x00000000fffffffeULL, true},
      { 0xffffffffffffffffULL, 0x00000000fffffffeULL, true},

      { 0x0000000000000000ULL, 0x00000000ffffffffULL, false},
      { 0x0000000000000001ULL, 0x00000000ffffffffULL, false},
      { 0x0000000000000002ULL, 0x00000000ffffffffULL, false},
      { 0x000000007ffffffeULL, 0x00000000ffffffffULL, false},
      { 0x000000007fffffffULL, 0x00000000ffffffffULL, false},
      { 0x0000000080000000ULL, 0x00000000ffffffffULL, false},
      { 0x0000000080000001ULL, 0x00000000ffffffffULL, false},
      { 0x00000000fffffffeULL, 0x00000000ffffffffULL, false},
      { 0x00000000ffffffffULL, 0x00000000ffffffffULL, true},
      { 0x0000000100000000ULL, 0x00000000ffffffffULL, true},
      { 0x0000000200000000ULL, 0x00000000ffffffffULL, true},
      { 0x7ffffffffffffffeULL, 0x00000000ffffffffULL, true},
      { 0x7fffffffffffffffULL, 0x00000000ffffffffULL, true},
      { 0x8000000000000000ULL, 0x00000000ffffffffULL, true},
      { 0x8000000000000001ULL, 0x00000000ffffffffULL, true},
      { 0xfffffffffffffffeULL, 0x00000000ffffffffULL, true},
      { 0xffffffffffffffffULL, 0x00000000ffffffffULL, true},

      { 0x0000000000000000ULL, 0x0000000100000000ULL, false},
      { 0x0000000000000001ULL, 0x0000000100000000ULL, false},
      { 0x0000000000000002ULL, 0x0000000100000000ULL, false},
      { 0x000000007ffffffeULL, 0x0000000100000000ULL, false},
      { 0x000000007fffffffULL, 0x0000000100000000ULL, false},
      { 0x0000000080000000ULL, 0x0000000100000000ULL, false},
      { 0x0000000080000001ULL, 0x0000000100000000ULL, false},
      { 0x00000000fffffffeULL, 0x0000000100000000ULL, false},
      { 0x00000000ffffffffULL, 0x0000000100000000ULL, false},
      { 0x0000000100000000ULL, 0x0000000100000000ULL, true},
      { 0x0000000200000000ULL, 0x0000000100000000ULL, true},
      { 0x7ffffffffffffffeULL, 0x0000000100000000ULL, true},
      { 0x7fffffffffffffffULL, 0x0000000100000000ULL, true},
      { 0x8000000000000000ULL, 0x0000000100000000ULL, true},
      { 0x8000000000000001ULL, 0x0000000100000000ULL, true},
      { 0xfffffffffffffffeULL, 0x0000000100000000ULL, true},
      { 0xffffffffffffffffULL, 0x0000000100000000ULL, true},

      { 0x0000000000000000ULL, 0x0000000200000000ULL, false},
      { 0x0000000000000001ULL, 0x0000000200000000ULL, false},
      { 0x0000000000000002ULL, 0x0000000200000000ULL, false},
      { 0x000000007ffffffeULL, 0x0000000200000000ULL, false},
      { 0x000000007fffffffULL, 0x0000000200000000ULL, false},
      { 0x0000000080000000ULL, 0x0000000200000000ULL, false},
      { 0x0000000080000001ULL, 0x0000000200000000ULL, false},
      { 0x00000000fffffffeULL, 0x0000000200000000ULL, false},
      { 0x00000000ffffffffULL, 0x0000000200000000ULL, false},
      { 0x0000000100000000ULL, 0x0000000200000000ULL, false},
      { 0x0000000200000000ULL, 0x0000000200000000ULL, true},
      { 0x7ffffffffffffffeULL, 0x0000000200000000ULL, true},
      { 0x7fffffffffffffffULL, 0x0000000200000000ULL, true},
      { 0x8000000000000000ULL, 0x0000000200000000ULL, true},
      { 0x8000000000000001ULL, 0x0000000200000000ULL, true},
      { 0xfffffffffffffffeULL, 0x0000000200000000ULL, true},
      { 0xffffffffffffffffULL, 0x0000000200000000ULL, true},

      { 0x0000000000000000ULL, 0x7ffffffffffffffeULL, false},
      { 0x0000000000000001ULL, 0x7ffffffffffffffeULL, false},
      { 0x0000000000000002ULL, 0x7ffffffffffffffeULL, false},
      { 0x000000007ffffffeULL, 0x7ffffffffffffffeULL, false},
      { 0x000000007fffffffULL, 0x7ffffffffffffffeULL, false},
      { 0x0000000080000000ULL, 0x7ffffffffffffffeULL, false},
      { 0x0000000080000001ULL, 0x7ffffffffffffffeULL, false},
      { 0x00000000fffffffeULL, 0x7ffffffffffffffeULL, false},
      { 0x00000000ffffffffULL, 0x7ffffffffffffffeULL, false},
      { 0x0000000100000000ULL, 0x7ffffffffffffffeULL, false},
      { 0x0000000200000000ULL, 0x7ffffffffffffffeULL, false},
      { 0x7ffffffffffffffeULL, 0x7ffffffffffffffeULL, true},
      { 0x7fffffffffffffffULL, 0x7ffffffffffffffeULL, true},
      { 0x8000000000000000ULL, 0x7ffffffffffffffeULL, true},
      { 0x8000000000000001ULL, 0x7ffffffffffffffeULL, true},
      { 0xfffffffffffffffeULL, 0x7ffffffffffffffeULL, true},
      { 0xffffffffffffffffULL, 0x7ffffffffffffffeULL, true},

      { 0x0000000000000000ULL, 0x7fffffffffffffffULL, false},
      { 0x0000000000000001ULL, 0x7fffffffffffffffULL, false},
      { 0x0000000000000002ULL, 0x7fffffffffffffffULL, false},
      { 0x000000007ffffffeULL, 0x7fffffffffffffffULL, false},
      { 0x000000007fffffffULL, 0x7fffffffffffffffULL, false},
      { 0x0000000080000000ULL, 0x7fffffffffffffffULL, false},
      { 0x0000000080000001ULL, 0x7fffffffffffffffULL, false},
      { 0x00000000fffffffeULL, 0x7fffffffffffffffULL, false},
      { 0x00000000ffffffffULL, 0x7fffffffffffffffULL, false},
      { 0x0000000100000000ULL, 0x7fffffffffffffffULL, false},
      { 0x0000000200000000ULL, 0x7fffffffffffffffULL, false},
      { 0x7ffffffffffffffeULL, 0x7fffffffffffffffULL, false},
      { 0x7fffffffffffffffULL, 0x7fffffffffffffffULL, true},
      { 0x8000000000000000ULL, 0x7fffffffffffffffULL, true},
      { 0x8000000000000001ULL, 0x7fffffffffffffffULL, true},
      { 0xfffffffffffffffeULL, 0x7fffffffffffffffULL, true},
      { 0xffffffffffffffffULL, 0x7fffffffffffffffULL, true},

      { 0x0000000000000000ULL, 0x8000000000000000ULL, false},
      { 0x0000000000000001ULL, 0x8000000000000000ULL, false},
      { 0x0000000000000002ULL, 0x8000000000000000ULL, false},
      { 0x000000007ffffffeULL, 0x8000000000000000ULL, false},
      { 0x000000007fffffffULL, 0x8000000000000000ULL, false},
      { 0x0000000080000000ULL, 0x8000000000000000ULL, false},
      { 0x0000000080000001ULL, 0x8000000000000000ULL, false},
      { 0x00000000fffffffeULL, 0x8000000000000000ULL, false},
      { 0x00000000ffffffffULL, 0x8000000000000000ULL, false},
      { 0x0000000100000000ULL, 0x8000000000000000ULL, false},
      { 0x0000000200000000ULL, 0x8000000000000000ULL, false},
      { 0x7ffffffffffffffeULL, 0x8000000000000000ULL, false},
      { 0x7fffffffffffffffULL, 0x8000000000000000ULL, false},
      { 0x8000000000000000ULL, 0x8000000000000000ULL, true},
      { 0x8000000000000001ULL, 0x8000000000000000ULL, true},
      { 0xfffffffffffffffeULL, 0x8000000000000000ULL, true},
      { 0xffffffffffffffffULL, 0x8000000000000000ULL, true},

      { 0x0000000000000000ULL, 0x8000000000000001ULL, false},
      { 0x0000000000000001ULL, 0x8000000000000001ULL, false},
      { 0x0000000000000002ULL, 0x8000000000000001ULL, false},
      { 0x000000007ffffffeULL, 0x8000000000000001ULL, false},
      { 0x000000007fffffffULL, 0x8000000000000001ULL, false},
      { 0x0000000080000000ULL, 0x8000000000000001ULL, false},
      { 0x0000000080000001ULL, 0x8000000000000001ULL, false},
      { 0x00000000fffffffeULL, 0x8000000000000001ULL, false},
      { 0x00000000ffffffffULL, 0x8000000000000001ULL, false},
      { 0x0000000100000000ULL, 0x8000000000000001ULL, false},
      { 0x0000000200000000ULL, 0x8000000000000001ULL, false},
      { 0x7ffffffffffffffeULL, 0x8000000000000001ULL, false},
      { 0x7fffffffffffffffULL, 0x8000000000000001ULL, false},
      { 0x8000000000000000ULL, 0x8000000000000001ULL, false},
      { 0x8000000000000001ULL, 0x8000000000000001ULL, true},
      { 0xfffffffffffffffeULL, 0x8000000000000001ULL, true},
      { 0xffffffffffffffffULL, 0x8000000000000001ULL, true},

      { 0x0000000000000000ULL, 0xfffffffffffffffeULL, false},
      { 0x0000000000000001ULL, 0xfffffffffffffffeULL, false},
      { 0x0000000000000002ULL, 0xfffffffffffffffeULL, false},
      { 0x000000007ffffffeULL, 0xfffffffffffffffeULL, false},
      { 0x000000007fffffffULL, 0xfffffffffffffffeULL, false},
      { 0x0000000080000000ULL, 0xfffffffffffffffeULL, false},
      { 0x0000000080000001ULL, 0xfffffffffffffffeULL, false},
      { 0x00000000fffffffeULL, 0xfffffffffffffffeULL, false},
      { 0x00000000ffffffffULL, 0xfffffffffffffffeULL, false},
      { 0x0000000100000000ULL, 0xfffffffffffffffeULL, false},
      { 0x0000000200000000ULL, 0xfffffffffffffffeULL, false},
      { 0x7ffffffffffffffeULL, 0xfffffffffffffffeULL, false},
      { 0x7fffffffffffffffULL, 0xfffffffffffffffeULL, false},
      { 0x8000000000000000ULL, 0xfffffffffffffffeULL, false},
      { 0x8000000000000001ULL, 0xfffffffffffffffeULL, false},
      { 0xfffffffffffffffeULL, 0xfffffffffffffffeULL, true},
      { 0xffffffffffffffffULL, 0xfffffffffffffffeULL, true},

      { 0x0000000000000000ULL, 0xffffffffffffffffULL, false},
      { 0x0000000000000001ULL, 0xffffffffffffffffULL, false},
      { 0x0000000000000002ULL, 0xffffffffffffffffULL, false},
      { 0x000000007ffffffeULL, 0xffffffffffffffffULL, false},
      { 0x000000007fffffffULL, 0xffffffffffffffffULL, false},
      { 0x0000000080000000ULL, 0xffffffffffffffffULL, false},
      { 0x0000000080000001ULL, 0xffffffffffffffffULL, false},
      { 0x00000000fffffffeULL, 0xffffffffffffffffULL, false},
      { 0x00000000ffffffffULL, 0xffffffffffffffffULL, false},
      { 0x0000000100000000ULL, 0xffffffffffffffffULL, false},
      { 0x0000000200000000ULL, 0xffffffffffffffffULL, false},
      { 0x7ffffffffffffffeULL, 0xffffffffffffffffULL, false},
      { 0x7fffffffffffffffULL, 0xffffffffffffffffULL, false},
      { 0x8000000000000000ULL, 0xffffffffffffffffULL, false},
      { 0x8000000000000001ULL, 0xffffffffffffffffULL, false},
      { 0xfffffffffffffffeULL, 0xffffffffffffffffULL, false},
      { 0xffffffffffffffffULL, 0xffffffffffffffffULL, true},
    };

  void SubVerifyUint64Uint64()
  {
    size_t i;

    for( i = 0; i < COUNTOF(uint64_uint64); ++i )
      {
        unsigned __int64 ret;
        if( SafeSubtract(uint64_uint64[i].x, uint64_uint64[i].y, ret) != uint64_uint64[i].fExpected )
          {
            cerr << "Error in case uint64_uint64: ";
            cerr << hex << setw(16) << setfill('0') << uint64_uint64[i].x << ", ";
            cerr << hex << setw(16) << setfill('0') << uint64_uint64[i].y << ", ";
            cerr << "expected = " << uint64_uint64[i].fExpected << endl;
          }

        // Now test throwing version
        bool fSuccess = true;
        try
          {
            SafeInt<unsigned __int64> si(uint64_uint64[i].x);
            si -= uint64_uint64[i].y;
          }
        catch(...)
          {
            fSuccess = false;
          }

        if( fSuccess != uint64_uint64[i].fExpected )
          {
            cerr << "Error in case uint64_uint64 throw (1): ";
            cerr << hex << setw(16) << setfill('0') << uint64_uint64[i].x << ", ";
            cerr << hex << setw(16) << setfill('0') << uint64_uint64[i].y << ", ";
            cerr << "expected = " << uint64_uint64[i].fExpected << endl;
          }

        // Also need to test the version that assigns back out
        // to a plain int, as it has different logic
        fSuccess = true;
        try
          {
            unsigned __int64 x(uint64_uint64[i].x);
            x -= SafeInt<unsigned __int64>(uint64_uint64[i].y);
          }
        catch(...)
          {
            fSuccess = false;
          }

        if( fSuccess != uint64_uint64[i].fExpected )
          {
            cerr << "Error in case uint64_uint64 throw (2): ";
            cerr << hex << setw(16) << setfill('0') << uint64_uint64[i].x << ", ";
            cerr << hex << setw(16) << setfill('0') << uint64_uint64[i].y << ", ";
            cerr << "expected = " << uint64_uint64[i].fExpected << endl;
          }
      }
  }

  static const SubTest< unsigned __int64, unsigned __int32 > uint64_uint32[] =
    {
      { 0x0000000000000000ULL, 0x00000000, true},
      { 0x0000000000000001ULL, 0x00000000, true},
      { 0x0000000000000002ULL, 0x00000000, true},
      { 0x000000007ffffffeULL, 0x00000000, true},
      { 0x000000007fffffffULL, 0x00000000, true},
      { 0x0000000080000000ULL, 0x00000000, true},
      { 0x0000000080000001ULL, 0x00000000, true},
      { 0x00000000fffffffeULL, 0x00000000, true},
      { 0x00000000ffffffffULL, 0x00000000, true},
      { 0x0000000100000000ULL, 0x00000000, true},
      { 0x0000000200000000ULL, 0x00000000, true},
      { 0x7ffffffffffffffeULL, 0x00000000, true},
      { 0x7fffffffffffffffULL, 0x00000000, true},
      { 0x8000000000000000ULL, 0x00000000, true},
      { 0x8000000000000001ULL, 0x00000000, true},
      { 0xfffffffffffffffeULL, 0x00000000, true},
      { 0xffffffffffffffffULL, 0x00000000, true},

      { 0x0000000000000000ULL, 0x00000001, false},
      { 0x0000000000000001ULL, 0x00000001, true},
      { 0x0000000000000002ULL, 0x00000001, true},
      { 0x000000007ffffffeULL, 0x00000001, true},
      { 0x000000007fffffffULL, 0x00000001, true},
      { 0x0000000080000000ULL, 0x00000001, true},
      { 0x0000000080000001ULL, 0x00000001, true},
      { 0x00000000fffffffeULL, 0x00000001, true},
      { 0x00000000ffffffffULL, 0x00000001, true},
      { 0x0000000100000000ULL, 0x00000001, true},
      { 0x0000000200000000ULL, 0x00000001, true},
      { 0x7ffffffffffffffeULL, 0x00000001, true},
      { 0x7fffffffffffffffULL, 0x00000001, true},
      { 0x8000000000000000ULL, 0x00000001, true},
      { 0x8000000000000001ULL, 0x00000001, true},
      { 0xfffffffffffffffeULL, 0x00000001, true},
      { 0xffffffffffffffffULL, 0x00000001, true},

      { 0x0000000000000000ULL, 0x00000002, false},
      { 0x0000000000000001ULL, 0x00000002, false},
      { 0x0000000000000002ULL, 0x00000002, true},
      { 0x000000007ffffffeULL, 0x00000002, true},
      { 0x000000007fffffffULL, 0x00000002, true},
      { 0x0000000080000000ULL, 0x00000002, true},
      { 0x0000000080000001ULL, 0x00000002, true},
      { 0x00000000fffffffeULL, 0x00000002, true},
      { 0x00000000ffffffffULL, 0x00000002, true},
      { 0x0000000100000000ULL, 0x00000002, true},
      { 0x0000000200000000ULL, 0x00000002, true},
      { 0x7ffffffffffffffeULL, 0x00000002, true},
      { 0x7fffffffffffffffULL, 0x00000002, true},
      { 0x8000000000000000ULL, 0x00000002, true},
      { 0x8000000000000001ULL, 0x00000002, true},
      { 0xfffffffffffffffeULL, 0x00000002, true},
      { 0xffffffffffffffffULL, 0x00000002, true},

      { 0x0000000000000000ULL, 0x7ffffffe, false},
      { 0x0000000000000001ULL, 0x7ffffffe, false},
      { 0x0000000000000002ULL, 0x7ffffffe, false},
      { 0x000000007ffffffeULL, 0x7ffffffe, true},
      { 0x000000007fffffffULL, 0x7ffffffe, true},
      { 0x0000000080000000ULL, 0x7ffffffe, true},
      { 0x0000000080000001ULL, 0x7ffffffe, true},
      { 0x00000000fffffffeULL, 0x7ffffffe, true},
      { 0x00000000ffffffffULL, 0x7ffffffe, true},
      { 0x0000000100000000ULL, 0x7ffffffe, true},
      { 0x0000000200000000ULL, 0x7ffffffe, true},
      { 0x7ffffffffffffffeULL, 0x7ffffffe, true},
      { 0x7fffffffffffffffULL, 0x7ffffffe, true},
      { 0x8000000000000000ULL, 0x7ffffffe, true},
      { 0x8000000000000001ULL, 0x7ffffffe, true},
      { 0xfffffffffffffffeULL, 0x7ffffffe, true},
      { 0xffffffffffffffffULL, 0x7ffffffe, true},

      { 0x0000000000000000ULL, 0x7fffffff, false},
      { 0x0000000000000001ULL, 0x7fffffff, false},
      { 0x0000000000000002ULL, 0x7fffffff, false},
      { 0x000000007ffffffeULL, 0x7fffffff, false},
      { 0x000000007fffffffULL, 0x7fffffff, true},
      { 0x0000000080000000ULL, 0x7fffffff, true},
      { 0x0000000080000001ULL, 0x7fffffff, true},
      { 0x00000000fffffffeULL, 0x7fffffff, true},
      { 0x00000000ffffffffULL, 0x7fffffff, true},
      { 0x0000000100000000ULL, 0x7fffffff, true},
      { 0x0000000200000000ULL, 0x7fffffff, true},
      { 0x7ffffffffffffffeULL, 0x7fffffff, true},
      { 0x7fffffffffffffffULL, 0x7fffffff, true},
      { 0x8000000000000000ULL, 0x7fffffff, true},
      { 0x8000000000000001ULL, 0x7fffffff, true},
      { 0xfffffffffffffffeULL, 0x7fffffff, true},
      { 0xffffffffffffffffULL, 0x7fffffff, true},

      { 0x0000000000000000ULL, 0x80000000, false},
      { 0x0000000000000001ULL, 0x80000000, false},
      { 0x0000000000000002ULL, 0x80000000, false},
      { 0x000000007ffffffeULL, 0x80000000, false},
      { 0x000000007fffffffULL, 0x80000000, false},
      { 0x0000000080000000ULL, 0x80000000, true},
      { 0x0000000080000001ULL, 0x80000000, true},
      { 0x00000000fffffffeULL, 0x80000000, true},
      { 0x00000000ffffffffULL, 0x80000000, true},
      { 0x0000000100000000ULL, 0x80000000, true},
      { 0x0000000200000000ULL, 0x80000000, true},
      { 0x7ffffffffffffffeULL, 0x80000000, true},
      { 0x7fffffffffffffffULL, 0x80000000, true},
      { 0x8000000000000000ULL, 0x80000000, true},
      { 0x8000000000000001ULL, 0x80000000, true},
      { 0xfffffffffffffffeULL, 0x80000000, true},
      { 0xffffffffffffffffULL, 0x80000000, true},

      { 0x0000000000000000ULL, 0x80000001, false},
      { 0x0000000000000001ULL, 0x80000001, false},
      { 0x0000000000000002ULL, 0x80000001, false},
      { 0x000000007ffffffeULL, 0x80000001, false},
      { 0x000000007fffffffULL, 0x80000001, false},
      { 0x0000000080000000ULL, 0x80000001, false},
      { 0x0000000080000001ULL, 0x80000001, true},
      { 0x00000000fffffffeULL, 0x80000001, true},
      { 0x00000000ffffffffULL, 0x80000001, true},
      { 0x0000000100000000ULL, 0x80000001, true},
      { 0x0000000200000000ULL, 0x80000001, true},
      { 0x7ffffffffffffffeULL, 0x80000001, true},
      { 0x7fffffffffffffffULL, 0x80000001, true},
      { 0x8000000000000000ULL, 0x80000001, true},
      { 0x8000000000000001ULL, 0x80000001, true},
      { 0xfffffffffffffffeULL, 0x80000001, true},
      { 0xffffffffffffffffULL, 0x80000001, true},

      { 0x0000000000000000ULL, 0xfffffffe, false},
      { 0x0000000000000001ULL, 0xfffffffe, false},
      { 0x0000000000000002ULL, 0xfffffffe, false},
      { 0x000000007ffffffeULL, 0xfffffffe, false},
      { 0x000000007fffffffULL, 0xfffffffe, false},
      { 0x0000000080000000ULL, 0xfffffffe, false},
      { 0x0000000080000001ULL, 0xfffffffe, false},
      { 0x00000000fffffffeULL, 0xfffffffe, true},
      { 0x00000000ffffffffULL, 0xfffffffe, true},
      { 0x0000000100000000ULL, 0xfffffffe, true},
      { 0x0000000200000000ULL, 0xfffffffe, true},
      { 0x7ffffffffffffffeULL, 0xfffffffe, true},
      { 0x7fffffffffffffffULL, 0xfffffffe, true},
      { 0x8000000000000000ULL, 0xfffffffe, true},
      { 0x8000000000000001ULL, 0xfffffffe, true},
      { 0xfffffffffffffffeULL, 0xfffffffe, true},
      { 0xffffffffffffffffULL, 0xfffffffe, true},

      { 0x0000000000000000ULL, 0xffffffff, false},
      { 0x0000000000000001ULL, 0xffffffff, false},
      { 0x0000000000000002ULL, 0xffffffff, false},
      { 0x000000007ffffffeULL, 0xffffffff, false},
      { 0x000000007fffffffULL, 0xffffffff, false},
      { 0x0000000080000000ULL, 0xffffffff, false},
      { 0x0000000080000001ULL, 0xffffffff, false},
      { 0x00000000fffffffeULL, 0xffffffff, false},
      { 0x00000000ffffffffULL, 0xffffffff, true},
      { 0x0000000100000000ULL, 0xffffffff, true},
      { 0x0000000200000000ULL, 0xffffffff, true},
      { 0x7ffffffffffffffeULL, 0xffffffff, true},
      { 0x7fffffffffffffffULL, 0xffffffff, true},
      { 0x8000000000000000ULL, 0xffffffff, true},
      { 0x8000000000000001ULL, 0xffffffff, true},
      { 0xfffffffffffffffeULL, 0xffffffff, true},
      { 0xffffffffffffffffULL, 0xffffffff, true},
    };

  void SubVerifyUint64Uint32()
  {
    size_t i;

    for( i = 0; i < COUNTOF(uint64_uint32); ++i )
      {
        unsigned __int64 ret;
        if( SafeSubtract(uint64_uint32[i].x, uint64_uint32[i].y, ret) != uint64_uint32[i].fExpected )
          {
            cerr << "Error in case uint64_uint32: ";
            cerr << hex << setw(16) << setfill('0') << uint64_uint32[i].x << ", ";
            cerr << hex << setw(8) << setfill('0') << uint64_uint32[i].y << ", ";
            cerr << "expected = " << uint64_uint32[i].fExpected << endl;
          }

        // Now test throwing version
        bool fSuccess = true;
        try
          {
            SafeInt<unsigned __int64> si(uint64_uint32[i].x);
            si -= uint64_uint32[i].y;
          }
        catch(...)
          {
            fSuccess = false;
          }

        if( fSuccess != uint64_uint32[i].fExpected )
          {
            cerr << "Error in case uint64_uint32 throw (1): ";
            cerr << hex << setw(16) << setfill('0') << uint64_uint32[i].x << ", ";
            cerr << hex << setw(8) << setfill('0') << uint64_uint32[i].y << ", ";
            cerr << "expected = " << uint64_uint32[i].fExpected << endl;
          }

        // Also need to test the version that assigns back out
        // to a plain int, as it has different logic
        fSuccess = true;
        try
          {
            unsigned __int64 x(uint64_uint32[i].x);
            x -= SafeInt<unsigned __int64>(uint64_uint32[i].y);
          }
        catch(...)
          {
            fSuccess = false;
          }

        if( fSuccess != uint64_uint32[i].fExpected )
          {
            cerr << "Error in case uint64_uint32 throw (2): ";
            cerr << hex << setw(16) << setfill('0') << uint64_uint32[i].x << ", ";
            cerr << hex << setw(8) << setfill('0') << uint64_uint32[i].y << ", ";
            cerr << "expected = " << uint64_uint32[i].fExpected << endl;
          }
      }
  }

  static const SubTest< unsigned __int64, unsigned __int16 > uint64_uint16[] =
    {
      { 0x0000000000000000ULL, 0x0000, true},
      { 0x0000000000000001ULL, 0x0000, true},
      { 0x0000000000000002ULL, 0x0000, true},
      { 0x000000007ffffffeULL, 0x0000, true},
      { 0x000000007fffffffULL, 0x0000, true},
      { 0x0000000080000000ULL, 0x0000, true},
      { 0x0000000080000001ULL, 0x0000, true},
      { 0x00000000fffffffeULL, 0x0000, true},
      { 0x00000000ffffffffULL, 0x0000, true},
      { 0x0000000100000000ULL, 0x0000, true},
      { 0x0000000200000000ULL, 0x0000, true},
      { 0x7ffffffffffffffeULL, 0x0000, true},
      { 0x7fffffffffffffffULL, 0x0000, true},
      { 0x8000000000000000ULL, 0x0000, true},
      { 0x8000000000000001ULL, 0x0000, true},
      { 0xfffffffffffffffeULL, 0x0000, true},
      { 0xffffffffffffffffULL, 0x0000, true},

      { 0x0000000000000000ULL, 0x0001, false},
      { 0x0000000000000001ULL, 0x0001, true},
      { 0x0000000000000002ULL, 0x0001, true},
      { 0x000000007ffffffeULL, 0x0001, true},
      { 0x000000007fffffffULL, 0x0001, true},
      { 0x0000000080000000ULL, 0x0001, true},
      { 0x0000000080000001ULL, 0x0001, true},
      { 0x00000000fffffffeULL, 0x0001, true},
      { 0x00000000ffffffffULL, 0x0001, true},
      { 0x0000000100000000ULL, 0x0001, true},
      { 0x0000000200000000ULL, 0x0001, true},
      { 0x7ffffffffffffffeULL, 0x0001, true},
      { 0x7fffffffffffffffULL, 0x0001, true},
      { 0x8000000000000000ULL, 0x0001, true},
      { 0x8000000000000001ULL, 0x0001, true},
      { 0xfffffffffffffffeULL, 0x0001, true},
      { 0xffffffffffffffffULL, 0x0001, true},

      { 0x0000000000000000ULL, 0x0002, false},
      { 0x0000000000000001ULL, 0x0002, false},
      { 0x0000000000000002ULL, 0x0002, true},
      { 0x000000007ffffffeULL, 0x0002, true},
      { 0x000000007fffffffULL, 0x0002, true},
      { 0x0000000080000000ULL, 0x0002, true},
      { 0x0000000080000001ULL, 0x0002, true},
      { 0x00000000fffffffeULL, 0x0002, true},
      { 0x00000000ffffffffULL, 0x0002, true},
      { 0x0000000100000000ULL, 0x0002, true},
      { 0x0000000200000000ULL, 0x0002, true},
      { 0x7ffffffffffffffeULL, 0x0002, true},
      { 0x7fffffffffffffffULL, 0x0002, true},
      { 0x8000000000000000ULL, 0x0002, true},
      { 0x8000000000000001ULL, 0x0002, true},
      { 0xfffffffffffffffeULL, 0x0002, true},
      { 0xffffffffffffffffULL, 0x0002, true},

      { 0x0000000000000000ULL, 0x7ffe, false},
      { 0x0000000000000001ULL, 0x7ffe, false},
      { 0x0000000000000002ULL, 0x7ffe, false},
      { 0x000000007ffffffeULL, 0x7ffe, true},
      { 0x000000007fffffffULL, 0x7ffe, true},
      { 0x0000000080000000ULL, 0x7ffe, true},
      { 0x0000000080000001ULL, 0x7ffe, true},
      { 0x00000000fffffffeULL, 0x7ffe, true},
      { 0x00000000ffffffffULL, 0x7ffe, true},
      { 0x0000000100000000ULL, 0x7ffe, true},
      { 0x0000000200000000ULL, 0x7ffe, true},
      { 0x7ffffffffffffffeULL, 0x7ffe, true},
      { 0x7fffffffffffffffULL, 0x7ffe, true},
      { 0x8000000000000000ULL, 0x7ffe, true},
      { 0x8000000000000001ULL, 0x7ffe, true},
      { 0xfffffffffffffffeULL, 0x7ffe, true},
      { 0xffffffffffffffffULL, 0x7ffe, true},

      { 0x0000000000000000ULL, 0x7fff, false},
      { 0x0000000000000001ULL, 0x7fff, false},
      { 0x0000000000000002ULL, 0x7fff, false},
      { 0x000000007ffffffeULL, 0x7fff, true},
      { 0x000000007fffffffULL, 0x7fff, true},
      { 0x0000000080000000ULL, 0x7fff, true},
      { 0x0000000080000001ULL, 0x7fff, true},
      { 0x00000000fffffffeULL, 0x7fff, true},
      { 0x00000000ffffffffULL, 0x7fff, true},
      { 0x0000000100000000ULL, 0x7fff, true},
      { 0x0000000200000000ULL, 0x7fff, true},
      { 0x7ffffffffffffffeULL, 0x7fff, true},
      { 0x7fffffffffffffffULL, 0x7fff, true},
      { 0x8000000000000000ULL, 0x7fff, true},
      { 0x8000000000000001ULL, 0x7fff, true},
      { 0xfffffffffffffffeULL, 0x7fff, true},
      { 0xffffffffffffffffULL, 0x7fff, true},

      { 0x0000000000000000ULL, 0x8000, false},
      { 0x0000000000000001ULL, 0x8000, false},
      { 0x0000000000000002ULL, 0x8000, false},
      { 0x000000007ffffffeULL, 0x8000, true},
      { 0x000000007fffffffULL, 0x8000, true},
      { 0x0000000080000000ULL, 0x8000, true},
      { 0x0000000080000001ULL, 0x8000, true},
      { 0x00000000fffffffeULL, 0x8000, true},
      { 0x00000000ffffffffULL, 0x8000, true},
      { 0x0000000100000000ULL, 0x8000, true},
      { 0x0000000200000000ULL, 0x8000, true},
      { 0x7ffffffffffffffeULL, 0x8000, true},
      { 0x7fffffffffffffffULL, 0x8000, true},
      { 0x8000000000000000ULL, 0x8000, true},
      { 0x8000000000000001ULL, 0x8000, true},
      { 0xfffffffffffffffeULL, 0x8000, true},
      { 0xffffffffffffffffULL, 0x8000, true},

      { 0x0000000000000000ULL, 0x8001, false},
      { 0x0000000000000001ULL, 0x8001, false},
      { 0x0000000000000002ULL, 0x8001, false},
      { 0x000000007ffffffeULL, 0x8001, true},
      { 0x000000007fffffffULL, 0x8001, true},
      { 0x0000000080000000ULL, 0x8001, true},
      { 0x0000000080000001ULL, 0x8001, true},
      { 0x00000000fffffffeULL, 0x8001, true},
      { 0x00000000ffffffffULL, 0x8001, true},
      { 0x0000000100000000ULL, 0x8001, true},
      { 0x0000000200000000ULL, 0x8001, true},
      { 0x7ffffffffffffffeULL, 0x8001, true},
      { 0x7fffffffffffffffULL, 0x8001, true},
      { 0x8000000000000000ULL, 0x8001, true},
      { 0x8000000000000001ULL, 0x8001, true},
      { 0xfffffffffffffffeULL, 0x8001, true},
      { 0xffffffffffffffffULL, 0x8001, true},

      { 0x0000000000000000ULL, 0xfffe, false},
      { 0x0000000000000001ULL, 0xfffe, false},
      { 0x0000000000000002ULL, 0xfffe, false},
      { 0x000000007ffffffeULL, 0xfffe, true},
      { 0x000000007fffffffULL, 0xfffe, true},
      { 0x0000000080000000ULL, 0xfffe, true},
      { 0x0000000080000001ULL, 0xfffe, true},
      { 0x00000000fffffffeULL, 0xfffe, true},
      { 0x00000000ffffffffULL, 0xfffe, true},
      { 0x0000000100000000ULL, 0xfffe, true},
      { 0x0000000200000000ULL, 0xfffe, true},
      { 0x7ffffffffffffffeULL, 0xfffe, true},
      { 0x7fffffffffffffffULL, 0xfffe, true},
      { 0x8000000000000000ULL, 0xfffe, true},
      { 0x8000000000000001ULL, 0xfffe, true},
      { 0xfffffffffffffffeULL, 0xfffe, true},
      { 0xffffffffffffffffULL, 0xfffe, true},

      { 0x0000000000000000ULL, 0xffff, false},
      { 0x0000000000000001ULL, 0xffff, false},
      { 0x0000000000000002ULL, 0xffff, false},
      { 0x000000007ffffffeULL, 0xffff, true},
      { 0x000000007fffffffULL, 0xffff, true},
      { 0x0000000080000000ULL, 0xffff, true},
      { 0x0000000080000001ULL, 0xffff, true},
      { 0x00000000fffffffeULL, 0xffff, true},
      { 0x00000000ffffffffULL, 0xffff, true},
      { 0x0000000100000000ULL, 0xffff, true},
      { 0x0000000200000000ULL, 0xffff, true},
      { 0x7ffffffffffffffeULL, 0xffff, true},
      { 0x7fffffffffffffffULL, 0xffff, true},
      { 0x8000000000000000ULL, 0xffff, true},
      { 0x8000000000000001ULL, 0xffff, true},
      { 0xfffffffffffffffeULL, 0xffff, true},
      { 0xffffffffffffffffULL, 0xffff, true},
    };

  void SubVerifyUint64Uint16()
  {
    size_t i;

    for( i = 0; i < COUNTOF(uint64_uint16); ++i )
      {
        unsigned __int64 ret;
        if( SafeSubtract(uint64_uint16[i].x, uint64_uint16[i].y, ret) != uint64_uint16[i].fExpected )
          {
            cerr << "Error in case uint64_uint16: ";
            cerr << hex << setw(16) << setfill('0') << uint64_uint16[i].x << ", ";
            cerr << hex << setw(4) << setfill('0') << uint64_uint16[i].y << ", ";
            cerr << "expected = " << uint64_uint16[i].fExpected << endl;
          }

        // Now test throwing version
        bool fSuccess = true;
        try
          {
            SafeInt<unsigned __int64> si(uint64_uint16[i].x);
            si -= uint64_uint16[i].y;
          }
        catch(...)
          {
            fSuccess = false;
          }

        if( fSuccess != uint64_uint16[i].fExpected )
          {
            cerr << "Error in case uint64_uint16 throw (1): ";
            cerr << hex << setw(16) << setfill('0') << uint64_uint16[i].x << ", ";
            cerr << hex << setw(4) << setfill('0') << uint64_uint16[i].y << ", ";
            cerr << "expected = " << uint64_uint16[i].fExpected << endl;
          }

        // Also need to test the version that assigns back out
        // to a plain int, as it has different logic
        fSuccess = true;
        try
          {
            unsigned __int64 x(uint64_uint16[i].x);
            x -= SafeInt<unsigned __int64>(uint64_uint16[i].y);
          }
        catch(...)
          {
            fSuccess = false;
          }

        if( fSuccess != uint64_uint16[i].fExpected )
          {
            cerr << "Error in case uint64_uint16 throw (2): ";
            cerr << hex << setw(16) << setfill('0') << uint64_uint16[i].x << ", ";
            cerr << hex << setw(4) << setfill('0') << uint64_uint16[i].y << ", ";
            cerr << "expected = " << uint64_uint16[i].fExpected << endl;
          }
      }
  }

  static const SubTest< unsigned __int64, unsigned __int8 > uint64_uint8[] =
    {
      { 0x0000000000000000ULL, 0x00, true},
      { 0x0000000000000001ULL, 0x00, true},
      { 0x0000000000000002ULL, 0x00, true},
      { 0x000000007ffffffeULL, 0x00, true},
      { 0x000000007fffffffULL, 0x00, true},
      { 0x0000000080000000ULL, 0x00, true},
      { 0x0000000080000001ULL, 0x00, true},
      { 0x00000000fffffffeULL, 0x00, true},
      { 0x00000000ffffffffULL, 0x00, true},
      { 0x0000000100000000ULL, 0x00, true},
      { 0x0000000200000000ULL, 0x00, true},
      { 0x7ffffffffffffffeULL, 0x00, true},
      { 0x7fffffffffffffffULL, 0x00, true},
      { 0x8000000000000000ULL, 0x00, true},
      { 0x8000000000000001ULL, 0x00, true},
      { 0xfffffffffffffffeULL, 0x00, true},
      { 0xffffffffffffffffULL, 0x00, true},

      { 0x0000000000000000ULL, 0x01, false},
      { 0x0000000000000001ULL, 0x01, true},
      { 0x0000000000000002ULL, 0x01, true},
      { 0x000000007ffffffeULL, 0x01, true},
      { 0x000000007fffffffULL, 0x01, true},
      { 0x0000000080000000ULL, 0x01, true},
      { 0x0000000080000001ULL, 0x01, true},
      { 0x00000000fffffffeULL, 0x01, true},
      { 0x00000000ffffffffULL, 0x01, true},
      { 0x0000000100000000ULL, 0x01, true},
      { 0x0000000200000000ULL, 0x01, true},
      { 0x7ffffffffffffffeULL, 0x01, true},
      { 0x7fffffffffffffffULL, 0x01, true},
      { 0x8000000000000000ULL, 0x01, true},
      { 0x8000000000000001ULL, 0x01, true},
      { 0xfffffffffffffffeULL, 0x01, true},
      { 0xffffffffffffffffULL, 0x01, true},

      { 0x0000000000000000ULL, 0x02, false},
      { 0x0000000000000001ULL, 0x02, false},
      { 0x0000000000000002ULL, 0x02, true},
      { 0x000000007ffffffeULL, 0x02, true},
      { 0x000000007fffffffULL, 0x02, true},
      { 0x0000000080000000ULL, 0x02, true},
      { 0x0000000080000001ULL, 0x02, true},
      { 0x00000000fffffffeULL, 0x02, true},
      { 0x00000000ffffffffULL, 0x02, true},
      { 0x0000000100000000ULL, 0x02, true},
      { 0x0000000200000000ULL, 0x02, true},
      { 0x7ffffffffffffffeULL, 0x02, true},
      { 0x7fffffffffffffffULL, 0x02, true},
      { 0x8000000000000000ULL, 0x02, true},
      { 0x8000000000000001ULL, 0x02, true},
      { 0xfffffffffffffffeULL, 0x02, true},
      { 0xffffffffffffffffULL, 0x02, true},

      { 0x0000000000000000ULL, 0x7e, false},
      { 0x0000000000000001ULL, 0x7e, false},
      { 0x0000000000000002ULL, 0x7e, false},
      { 0x000000007ffffffeULL, 0x7e, true},
      { 0x000000007fffffffULL, 0x7e, true},
      { 0x0000000080000000ULL, 0x7e, true},
      { 0x0000000080000001ULL, 0x7e, true},
      { 0x00000000fffffffeULL, 0x7e, true},
      { 0x00000000ffffffffULL, 0x7e, true},
      { 0x0000000100000000ULL, 0x7e, true},
      { 0x0000000200000000ULL, 0x7e, true},
      { 0x7ffffffffffffffeULL, 0x7e, true},
      { 0x7fffffffffffffffULL, 0x7e, true},
      { 0x8000000000000000ULL, 0x7e, true},
      { 0x8000000000000001ULL, 0x7e, true},
      { 0xfffffffffffffffeULL, 0x7e, true},
      { 0xffffffffffffffffULL, 0x7e, true},

      { 0x0000000000000000ULL, 0x7f, false},
      { 0x0000000000000001ULL, 0x7f, false},
      { 0x0000000000000002ULL, 0x7f, false},
      { 0x000000007ffffffeULL, 0x7f, true},
      { 0x000000007fffffffULL, 0x7f, true},
      { 0x0000000080000000ULL, 0x7f, true},
      { 0x0000000080000001ULL, 0x7f, true},
      { 0x00000000fffffffeULL, 0x7f, true},
      { 0x00000000ffffffffULL, 0x7f, true},
      { 0x0000000100000000ULL, 0x7f, true},
      { 0x0000000200000000ULL, 0x7f, true},
      { 0x7ffffffffffffffeULL, 0x7f, true},
      { 0x7fffffffffffffffULL, 0x7f, true},
      { 0x8000000000000000ULL, 0x7f, true},
      { 0x8000000000000001ULL, 0x7f, true},
      { 0xfffffffffffffffeULL, 0x7f, true},
      { 0xffffffffffffffffULL, 0x7f, true},

      { 0x0000000000000000ULL, 0x80, false},
      { 0x0000000000000001ULL, 0x80, false},
      { 0x0000000000000002ULL, 0x80, false},
      { 0x000000007ffffffeULL, 0x80, true},
      { 0x000000007fffffffULL, 0x80, true},
      { 0x0000000080000000ULL, 0x80, true},
      { 0x0000000080000001ULL, 0x80, true},
      { 0x00000000fffffffeULL, 0x80, true},
      { 0x00000000ffffffffULL, 0x80, true},
      { 0x0000000100000000ULL, 0x80, true},
      { 0x0000000200000000ULL, 0x80, true},
      { 0x7ffffffffffffffeULL, 0x80, true},
      { 0x7fffffffffffffffULL, 0x80, true},
      { 0x8000000000000000ULL, 0x80, true},
      { 0x8000000000000001ULL, 0x80, true},
      { 0xfffffffffffffffeULL, 0x80, true},
      { 0xffffffffffffffffULL, 0x80, true},

      { 0x0000000000000000ULL, 0x81, false},
      { 0x0000000000000001ULL, 0x81, false},
      { 0x0000000000000002ULL, 0x81, false},
      { 0x000000007ffffffeULL, 0x81, true},
      { 0x000000007fffffffULL, 0x81, true},
      { 0x0000000080000000ULL, 0x81, true},
      { 0x0000000080000001ULL, 0x81, true},
      { 0x00000000fffffffeULL, 0x81, true},
      { 0x00000000ffffffffULL, 0x81, true},
      { 0x0000000100000000ULL, 0x81, true},
      { 0x0000000200000000ULL, 0x81, true},
      { 0x7ffffffffffffffeULL, 0x81, true},
      { 0x7fffffffffffffffULL, 0x81, true},
      { 0x8000000000000000ULL, 0x81, true},
      { 0x8000000000000001ULL, 0x81, true},
      { 0xfffffffffffffffeULL, 0x81, true},
      { 0xffffffffffffffffULL, 0x81, true},

      { 0x0000000000000000ULL, 0xfe, false},
      { 0x0000000000000001ULL, 0xfe, false},
      { 0x0000000000000002ULL, 0xfe, false},
      { 0x000000007ffffffeULL, 0xfe, true},
      { 0x000000007fffffffULL, 0xfe, true},
      { 0x0000000080000000ULL, 0xfe, true},
      { 0x0000000080000001ULL, 0xfe, true},
      { 0x00000000fffffffeULL, 0xfe, true},
      { 0x00000000ffffffffULL, 0xfe, true},
      { 0x0000000100000000ULL, 0xfe, true},
      { 0x0000000200000000ULL, 0xfe, true},
      { 0x7ffffffffffffffeULL, 0xfe, true},
      { 0x7fffffffffffffffULL, 0xfe, true},
      { 0x8000000000000000ULL, 0xfe, true},
      { 0x8000000000000001ULL, 0xfe, true},
      { 0xfffffffffffffffeULL, 0xfe, true},
      { 0xffffffffffffffffULL, 0xfe, true},

      { 0x0000000000000000ULL, 0xff, false},
      { 0x0000000000000001ULL, 0xff, false},
      { 0x0000000000000002ULL, 0xff, false},
      { 0x000000007ffffffeULL, 0xff, true},
      { 0x000000007fffffffULL, 0xff, true},
      { 0x0000000080000000ULL, 0xff, true},
      { 0x0000000080000001ULL, 0xff, true},
      { 0x00000000fffffffeULL, 0xff, true},
      { 0x00000000ffffffffULL, 0xff, true},
      { 0x0000000100000000ULL, 0xff, true},
      { 0x0000000200000000ULL, 0xff, true},
      { 0x7ffffffffffffffeULL, 0xff, true},
      { 0x7fffffffffffffffULL, 0xff, true},
      { 0x8000000000000000ULL, 0xff, true},
      { 0x8000000000000001ULL, 0xff, true},
      { 0xfffffffffffffffeULL, 0xff, true},
      { 0xffffffffffffffffULL, 0xff, true},
    };

  void SubVerifyUint64Uint8()
  {
    size_t i;

    for( i = 0; i < COUNTOF(uint64_uint8); ++i )
      {
        unsigned __int64 ret;
        if( SafeSubtract(uint64_uint8[i].x, uint64_uint8[i].y, ret) != uint64_uint8[i].fExpected )
          {
            cerr << "Error in case uint64_uint8: ";
            cerr << hex << setw(16) << setfill('0') << uint64_uint8[i].x << ", ";
            cerr << hex << setw(2) << setfill('0') << (0xFF & (int)uint64_uint8[i].y) << ", ";
            cerr << "expected = " << uint64_uint8[i].fExpected << endl;
          }

        // Now test throwing version
        bool fSuccess = true;
        try
          {
            SafeInt<unsigned __int64> si(uint64_uint8[i].x);
            si -= uint64_uint8[i].y;
          }
        catch(...)
          {
            fSuccess = false;
          }

        if( fSuccess != uint64_uint8[i].fExpected )
          {
            cerr << "Error in case uint64_uint8 throw (1): ";
            cerr << hex << setw(16) << setfill('0') << uint64_uint8[i].x << ", ";
            cerr << hex << setw(2) << setfill('0') << (0xFF & (int)uint64_uint8[i].y) << ", ";
            cerr << "expected = " << uint64_uint8[i].fExpected << endl;
          }

        // Also need to test the version that assigns back out
        // to a plain int, as it has different logic
        fSuccess = true;
        try
          {
            unsigned __int64 x(uint64_uint8[i].x);
            x -= SafeInt<unsigned __int64>(uint64_uint8[i].y);
          }
        catch(...)
          {
            fSuccess = false;
          }

        if( fSuccess != uint64_uint8[i].fExpected )
          {
            cerr << "Error in case uint64_uint8 throw (2): ";
            cerr << hex << setw(16) << setfill('0') << uint64_uint8[i].x << ", ";
            cerr << hex << setw(2) << setfill('0') << (0xFF & (int)uint64_uint8[i].y) << ", ";
            cerr << "expected = " << uint64_uint8[i].fExpected << endl;
          }
      }
  }

  static const SubTest< unsigned __int8, unsigned __int64 > uint8_uint64[] =
    {
      { 0x00, 0x0000000000000000ULL, true},
      { 0x01, 0x0000000000000000ULL, true},
      { 0x02, 0x0000000000000000ULL, true},
      { 0x7e, 0x0000000000000000ULL, true},
      { 0x7f, 0x0000000000000000ULL, true},
      { 0x80, 0x0000000000000000ULL, true},
      { 0x81, 0x0000000000000000ULL, true},
      { 0xfe, 0x0000000000000000ULL, true},
      { 0xff, 0x0000000000000000ULL, true},

      { 0x00, 0x0000000000000001ULL, false},
      { 0x01, 0x0000000000000001ULL, true},
      { 0x02, 0x0000000000000001ULL, true},
      { 0x7e, 0x0000000000000001ULL, true},
      { 0x7f, 0x0000000000000001ULL, true},
      { 0x80, 0x0000000000000001ULL, true},
      { 0x81, 0x0000000000000001ULL, true},
      { 0xfe, 0x0000000000000001ULL, true},
      { 0xff, 0x0000000000000001ULL, true},

      { 0x00, 0x0000000000000002ULL, false},
      { 0x01, 0x0000000000000002ULL, false},
      { 0x02, 0x0000000000000002ULL, true},
      { 0x7e, 0x0000000000000002ULL, true},
      { 0x7f, 0x0000000000000002ULL, true},
      { 0x80, 0x0000000000000002ULL, true},
      { 0x81, 0x0000000000000002ULL, true},
      { 0xfe, 0x0000000000000002ULL, true},
      { 0xff, 0x0000000000000002ULL, true},

      { 0x00, 0x000000007ffffffeULL, false},
      { 0x01, 0x000000007ffffffeULL, false},
      { 0x02, 0x000000007ffffffeULL, false},
      { 0x7e, 0x000000007ffffffeULL, false},
      { 0x7f, 0x000000007ffffffeULL, false},
      { 0x80, 0x000000007ffffffeULL, false},
      { 0x81, 0x000000007ffffffeULL, false},
      { 0xfe, 0x000000007ffffffeULL, false},
      { 0xff, 0x000000007ffffffeULL, false},

      { 0x00, 0x000000007fffffffULL, false},
      { 0x01, 0x000000007fffffffULL, false},
      { 0x02, 0x000000007fffffffULL, false},
      { 0x7e, 0x000000007fffffffULL, false},
      { 0x7f, 0x000000007fffffffULL, false},
      { 0x80, 0x000000007fffffffULL, false},
      { 0x81, 0x000000007fffffffULL, false},
      { 0xfe, 0x000000007fffffffULL, false},
      { 0xff, 0x000000007fffffffULL, false},

      { 0x00, 0x0000000080000000ULL, false},
      { 0x01, 0x0000000080000000ULL, false},
      { 0x02, 0x0000000080000000ULL, false},
      { 0x7e, 0x0000000080000000ULL, false},
      { 0x7f, 0x0000000080000000ULL, false},
      { 0x80, 0x0000000080000000ULL, false},
      { 0x81, 0x0000000080000000ULL, false},
      { 0xfe, 0x0000000080000000ULL, false},
      { 0xff, 0x0000000080000000ULL, false},

      { 0x00, 0x0000000080000001ULL, false},
      { 0x01, 0x0000000080000001ULL, false},
      { 0x02, 0x0000000080000001ULL, false},
      { 0x7e, 0x0000000080000001ULL, false},
      { 0x7f, 0x0000000080000001ULL, false},
      { 0x80, 0x0000000080000001ULL, false},
      { 0x81, 0x0000000080000001ULL, false},
      { 0xfe, 0x0000000080000001ULL, false},
      { 0xff, 0x0000000080000001ULL, false},

      { 0x00, 0x00000000fffffffeULL, false},
      { 0x01, 0x00000000fffffffeULL, false},
      { 0x02, 0x00000000fffffffeULL, false},
      { 0x7e, 0x00000000fffffffeULL, false},
      { 0x7f, 0x00000000fffffffeULL, false},
      { 0x80, 0x00000000fffffffeULL, false},
      { 0x81, 0x00000000fffffffeULL, false},
      { 0xfe, 0x00000000fffffffeULL, false},
      { 0xff, 0x00000000fffffffeULL, false},

      { 0x00, 0x00000000ffffffffULL, false},
      { 0x01, 0x00000000ffffffffULL, false},
      { 0x02, 0x00000000ffffffffULL, false},
      { 0x7e, 0x00000000ffffffffULL, false},
      { 0x7f, 0x00000000ffffffffULL, false},
      { 0x80, 0x00000000ffffffffULL, false},
      { 0x81, 0x00000000ffffffffULL, false},
      { 0xfe, 0x00000000ffffffffULL, false},
      { 0xff, 0x00000000ffffffffULL, false},

      { 0x00, 0x0000000100000000ULL, false},
      { 0x01, 0x0000000100000000ULL, false},
      { 0x02, 0x0000000100000000ULL, false},
      { 0x7e, 0x0000000100000000ULL, false},
      { 0x7f, 0x0000000100000000ULL, false},
      { 0x80, 0x0000000100000000ULL, false},
      { 0x81, 0x0000000100000000ULL, false},
      { 0xfe, 0x0000000100000000ULL, false},
      { 0xff, 0x0000000100000000ULL, false},

      { 0x00, 0x0000000200000000ULL, false},
      { 0x01, 0x0000000200000000ULL, false},
      { 0x02, 0x0000000200000000ULL, false},
      { 0x7e, 0x0000000200000000ULL, false},
      { 0x7f, 0x0000000200000000ULL, false},
      { 0x80, 0x0000000200000000ULL, false},
      { 0x81, 0x0000000200000000ULL, false},
      { 0xfe, 0x0000000200000000ULL, false},
      { 0xff, 0x0000000200000000ULL, false},

      { 0x00, 0x7ffffffffffffffeULL, false},
      { 0x01, 0x7ffffffffffffffeULL, false},
      { 0x02, 0x7ffffffffffffffeULL, false},
      { 0x7e, 0x7ffffffffffffffeULL, false},
      { 0x7f, 0x7ffffffffffffffeULL, false},
      { 0x80, 0x7ffffffffffffffeULL, false},
      { 0x81, 0x7ffffffffffffffeULL, false},
      { 0xfe, 0x7ffffffffffffffeULL, false},
      { 0xff, 0x7ffffffffffffffeULL, false},

      { 0x00, 0x7fffffffffffffffULL, false},
      { 0x01, 0x7fffffffffffffffULL, false},
      { 0x02, 0x7fffffffffffffffULL, false},
      { 0x7e, 0x7fffffffffffffffULL, false},
      { 0x7f, 0x7fffffffffffffffULL, false},
      { 0x80, 0x7fffffffffffffffULL, false},
      { 0x81, 0x7fffffffffffffffULL, false},
      { 0xfe, 0x7fffffffffffffffULL, false},
      { 0xff, 0x7fffffffffffffffULL, false},

      { 0x00, 0x8000000000000000ULL, false},
      { 0x01, 0x8000000000000000ULL, false},
      { 0x02, 0x8000000000000000ULL, false},
      { 0x7e, 0x8000000000000000ULL, false},
      { 0x7f, 0x8000000000000000ULL, false},
      { 0x80, 0x8000000000000000ULL, false},
      { 0x81, 0x8000000000000000ULL, false},
      { 0xfe, 0x8000000000000000ULL, false},
      { 0xff, 0x8000000000000000ULL, false},

      { 0x00, 0x8000000000000001ULL, false},
      { 0x01, 0x8000000000000001ULL, false},
      { 0x02, 0x8000000000000001ULL, false},
      { 0x7e, 0x8000000000000001ULL, false},
      { 0x7f, 0x8000000000000001ULL, false},
      { 0x80, 0x8000000000000001ULL, false},
      { 0x81, 0x8000000000000001ULL, false},
      { 0xfe, 0x8000000000000001ULL, false},
      { 0xff, 0x8000000000000001ULL, false},

      { 0x00, 0xfffffffffffffffeULL, false},
      { 0x01, 0xfffffffffffffffeULL, false},
      { 0x02, 0xfffffffffffffffeULL, false},
      { 0x7e, 0xfffffffffffffffeULL, false},
      { 0x7f, 0xfffffffffffffffeULL, false},
      { 0x80, 0xfffffffffffffffeULL, false},
      { 0x81, 0xfffffffffffffffeULL, false},
      { 0xfe, 0xfffffffffffffffeULL, false},
      { 0xff, 0xfffffffffffffffeULL, false},

      { 0x00, 0xffffffffffffffffULL, false},
      { 0x01, 0xffffffffffffffffULL, false},
      { 0x02, 0xffffffffffffffffULL, false},
      { 0x7e, 0xffffffffffffffffULL, false},
      { 0x7f, 0xffffffffffffffffULL, false},
      { 0x80, 0xffffffffffffffffULL, false},
      { 0x81, 0xffffffffffffffffULL, false},
      { 0xfe, 0xffffffffffffffffULL, false},
      { 0xff, 0xffffffffffffffffULL, false},
    };

  void SubVerifyUint8Uint64()
  {
    size_t i;

    for( i = 0; i < COUNTOF(uint8_uint64); ++i )
      {
        unsigned __int8 ret;
        if( SafeSubtract(uint8_uint64[i].x, uint8_uint64[i].y, ret) != uint8_uint64[i].fExpected )
          {
            cerr << "Error in case uint8_uint64: ";
            cerr << hex << setw(2) << setfill('0') << (0xFF & (int)uint8_uint64[i].x) << ", ";
            cerr << hex << setw(16) << setfill('0') << uint8_uint64[i].y << ", ";
            cerr << "expected = " << uint8_uint64[i].fExpected << endl;
          }

        // Now test throwing version
        bool fSuccess = true;
        try
          {
            SafeInt<unsigned __int8> si(uint8_uint64[i].x);
            si -= uint8_uint64[i].y;
          }
        catch(...)
          {
            fSuccess = false;
          }

        if( fSuccess != uint8_uint64[i].fExpected )
          {
            cerr << "Error in case uint8_uint64 throw (1): ";
            cerr << hex << setw(2) << setfill('0') << (0xFF & (int)uint8_uint64[i].x) << ", ";
            cerr << hex << setw(16) << setfill('0') << uint8_uint64[i].y << ", ";
            cerr << "expected = " << uint8_uint64[i].fExpected << endl;
          }

        // Also need to test the version that assigns back out
        // to a plain int, as it has different logic
        fSuccess = true;
        try
          {
            unsigned __int8 x(uint8_uint64[i].x);
            x -= SafeInt<unsigned __int64>(uint8_uint64[i].y);
          }
        catch(...)
          {
            fSuccess = false;
          }

        if( fSuccess != uint8_uint64[i].fExpected )
          {
            cerr << "Error in case uint8_uint64 throw (2): ";
            cerr << hex << setw(2) << setfill('0') << (0xFF & (int)uint8_uint64[i].x) << ", ";
            cerr << hex << setw(16) << setfill('0') << uint8_uint64[i].y << ", ";
            cerr << "expected = " << uint8_uint64[i].fExpected << endl;
          }
      }
  }

  static const SubTest< unsigned __int8, unsigned __int32 > uint8_uint32[] =
    {
      { 0x00, 0x00000000ULL, true},
      { 0x01, 0x00000000ULL, true},
      { 0x02, 0x00000000ULL, true},
      { 0x7e, 0x00000000ULL, true},
      { 0x7f, 0x00000000ULL, true},
      { 0x80, 0x00000000ULL, true},
      { 0x81, 0x00000000ULL, true},
      { 0xfe, 0x00000000ULL, true},
      { 0xff, 0x00000000ULL, true},

      { 0x00, 0x00000001ULL, false},
      { 0x01, 0x00000001ULL, true},
      { 0x02, 0x00000001ULL, true},
      { 0x7e, 0x00000001ULL, true},
      { 0x7f, 0x00000001ULL, true},
      { 0x80, 0x00000001ULL, true},
      { 0x81, 0x00000001ULL, true},
      { 0xfe, 0x00000001ULL, true},
      { 0xff, 0x00000001ULL, true},

      { 0x00, 0x00000002ULL, false},
      { 0x01, 0x00000002ULL, false},
      { 0x02, 0x00000002ULL, true},
      { 0x7e, 0x00000002ULL, true},
      { 0x7f, 0x00000002ULL, true},
      { 0x80, 0x00000002ULL, true},
      { 0x81, 0x00000002ULL, true},
      { 0xfe, 0x00000002ULL, true},
      { 0xff, 0x00000002ULL, true},

      { 0x00, 0x7ffffffeULL, false},
      { 0x01, 0x7ffffffeULL, false},
      { 0x02, 0x7ffffffeULL, false},
      { 0x7e, 0x7ffffffeULL, false},
      { 0x7f, 0x7ffffffeULL, false},
      { 0x80, 0x7ffffffeULL, false},
      { 0x81, 0x7ffffffeULL, false},
      { 0xfe, 0x7ffffffeULL, false},
      { 0xff, 0x7ffffffeULL, false},

      { 0x00, 0x7fffffffULL, false},
      { 0x01, 0x7fffffffULL, false},
      { 0x02, 0x7fffffffULL, false},
      { 0x7e, 0x7fffffffULL, false},
      { 0x7f, 0x7fffffffULL, false},
      { 0x80, 0x7fffffffULL, false},
      { 0x81, 0x7fffffffULL, false},
      { 0xfe, 0x7fffffffULL, false},
      { 0xff, 0x7fffffffULL, false},

      { 0x00, 0x80000000ULL, false},
      { 0x01, 0x80000000ULL, false},
      { 0x02, 0x80000000ULL, false},
      { 0x7e, 0x80000000ULL, false},
      { 0x7f, 0x80000000ULL, false},
      { 0x80, 0x80000000ULL, false},
      { 0x81, 0x80000000ULL, false},
      { 0xfe, 0x80000000ULL, false},
      { 0xff, 0x80000000ULL, false},

      { 0x00, 0x80000001ULL, false},
      { 0x01, 0x80000001ULL, false},
      { 0x02, 0x80000001ULL, false},
      { 0x7e, 0x80000001ULL, false},
      { 0x7f, 0x80000001ULL, false},
      { 0x80, 0x80000001ULL, false},
      { 0x81, 0x80000001ULL, false},
      { 0xfe, 0x80000001ULL, false},
      { 0xff, 0x80000001ULL, false},

      { 0x00, 0xfffffffeULL, false},
      { 0x01, 0xfffffffeULL, false},
      { 0x02, 0xfffffffeULL, false},
      { 0x7e, 0xfffffffeULL, false},
      { 0x7f, 0xfffffffeULL, false},
      { 0x80, 0xfffffffeULL, false},
      { 0x81, 0xfffffffeULL, false},
      { 0xfe, 0xfffffffeULL, false},
      { 0xff, 0xfffffffeULL, false},

      { 0x00, 0xffffffffULL, false},
      { 0x01, 0xffffffffULL, false},
      { 0x02, 0xffffffffULL, false},
      { 0x7e, 0xffffffffULL, false},
      { 0x7f, 0xffffffffULL, false},
      { 0x80, 0xffffffffULL, false},
      { 0x81, 0xffffffffULL, false},
      { 0xfe, 0xffffffffULL, false},
      { 0xff, 0xffffffffULL, false},
    };

  void SubVerifyUint8Uint32()
  {
    size_t i;

    for( i = 0; i < COUNTOF(uint8_uint32); ++i )
      {
        unsigned __int8 ret;
        if( SafeSubtract(uint8_uint32[i].x, uint8_uint32[i].y, ret) != uint8_uint32[i].fExpected )
          {
            cerr << "Error in case uint8_uint32: ";
            cerr << hex << setw(2) << setfill('0') << (0xFF & (int)uint8_uint32[i].x) << ", ";
            cerr << hex << setw(8) << setfill('0') << uint8_uint32[i].y << ", ";
            cerr << "expected = " << uint8_uint32[i].fExpected << endl;
          }

        // Now test throwing version
        bool fSuccess = true;
        try
          {
            SafeInt<unsigned __int8> si(uint8_uint32[i].x);
            si -= uint8_uint32[i].y;
          }
        catch(...)
          {
            fSuccess = false;
          }

        if( fSuccess != uint8_uint32[i].fExpected )
          {
            cerr << "Error in case uint8_uint32 throw (1): ";
            cerr << hex << setw(2) << setfill('0') << (0xFF & (int)uint8_uint32[i].x) << ", ";
            cerr << hex << setw(8) << setfill('0') << uint8_uint32[i].y << ", ";
            cerr << "expected = " << uint8_uint32[i].fExpected << endl;
          }

        // Also need to test the version that assigns back out
        // to a plain int, as it has different logic
        fSuccess = true;
        try
          {
            unsigned __int8 x(uint8_uint32[i].x);
            x -= SafeInt<unsigned __int64>(uint8_uint32[i].y);
          }
        catch(...)
          {
            fSuccess = false;
          }

        if( fSuccess != uint8_uint32[i].fExpected )
          {
            cerr << "Error in case uint8_uint32 throw (2): ";
            cerr << hex << setw(2) << setfill('0') << (0xFF & (int)uint8_uint32[i].x) << ", ";
            cerr << hex << setw(8) << setfill('0') << uint8_uint32[i].y << ", ";
            cerr << "expected = " << uint8_uint32[i].fExpected << endl;
          }
      }
  }

  static const SubTest< unsigned __int8, unsigned __int16 > uint8_uint16[] =
    {
      { 0x00, 0x0000ULL, true},
      { 0x01, 0x0000ULL, true},
      { 0x02, 0x0000ULL, true},
      { 0x7e, 0x0000ULL, true},
      { 0x7f, 0x0000ULL, true},
      { 0x80, 0x0000ULL, true},
      { 0x81, 0x0000ULL, true},
      { 0xfe, 0x0000ULL, true},
      { 0xff, 0x0000ULL, true},

      { 0x00, 0x0001ULL, false},
      { 0x01, 0x0001ULL, true},
      { 0x02, 0x0001ULL, true},
      { 0x7e, 0x0001ULL, true},
      { 0x7f, 0x0001ULL, true},
      { 0x80, 0x0001ULL, true},
      { 0x81, 0x0001ULL, true},
      { 0xfe, 0x0001ULL, true},
      { 0xff, 0x0001ULL, true},

      { 0x00, 0x0002ULL, false},
      { 0x01, 0x0002ULL, false},
      { 0x02, 0x0002ULL, true},
      { 0x7e, 0x0002ULL, true},
      { 0x7f, 0x0002ULL, true},
      { 0x80, 0x0002ULL, true},
      { 0x81, 0x0002ULL, true},
      { 0xfe, 0x0002ULL, true},
      { 0xff, 0x0002ULL, true},

      { 0x00, 0x7ffeULL, false},
      { 0x01, 0x7ffeULL, false},
      { 0x02, 0x7ffeULL, false},
      { 0x7e, 0x7ffeULL, false},
      { 0x7f, 0x7ffeULL, false},
      { 0x80, 0x7ffeULL, false},
      { 0x81, 0x7ffeULL, false},
      { 0xfe, 0x7ffeULL, false},
      { 0xff, 0x7ffeULL, false},

      { 0x00, 0x7fffULL, false},
      { 0x01, 0x7fffULL, false},
      { 0x02, 0x7fffULL, false},
      { 0x7e, 0x7fffULL, false},
      { 0x7f, 0x7fffULL, false},
      { 0x80, 0x7fffULL, false},
      { 0x81, 0x7fffULL, false},
      { 0xfe, 0x7fffULL, false},
      { 0xff, 0x7fffULL, false},

      { 0x00, 0x8000ULL, false},
      { 0x01, 0x8000ULL, false},
      { 0x02, 0x8000ULL, false},
      { 0x7e, 0x8000ULL, false},
      { 0x7f, 0x8000ULL, false},
      { 0x80, 0x8000ULL, false},
      { 0x81, 0x8000ULL, false},
      { 0xfe, 0x8000ULL, false},
      { 0xff, 0x8000ULL, false},

      { 0x00, 0x8001ULL, false},
      { 0x01, 0x8001ULL, false},
      { 0x02, 0x8001ULL, false},
      { 0x7e, 0x8001ULL, false},
      { 0x7f, 0x8001ULL, false},
      { 0x80, 0x8001ULL, false},
      { 0x81, 0x8001ULL, false},
      { 0xfe, 0x8001ULL, false},
      { 0xff, 0x8001ULL, false},

      { 0x00, 0xfffeULL, false},
      { 0x01, 0xfffeULL, false},
      { 0x02, 0xfffeULL, false},
      { 0x7e, 0xfffeULL, false},
      { 0x7f, 0xfffeULL, false},
      { 0x80, 0xfffeULL, false},
      { 0x81, 0xfffeULL, false},
      { 0xfe, 0xfffeULL, false},
      { 0xff, 0xfffeULL, false},

      { 0x00, 0xffffULL, false},
      { 0x01, 0xffffULL, false},
      { 0x02, 0xffffULL, false},
      { 0x7e, 0xffffULL, false},
      { 0x7f, 0xffffULL, false},
      { 0x80, 0xffffULL, false},
      { 0x81, 0xffffULL, false},
      { 0xfe, 0xffffULL, false},
      { 0xff, 0xffffULL, false},
    };

  void SubVerifyUint8Uint16()
  {
    size_t i;

    for( i = 0; i < COUNTOF(uint8_uint16); ++i )
      {
        unsigned __int8 ret;
        if( SafeSubtract(uint8_uint16[i].x, uint8_uint16[i].y, ret) != uint8_uint16[i].fExpected )
          {
            cerr << "Error in case uint8_uint16: ";
            cerr << hex << setw(2) << setfill('0') << (0xFF & (int)uint8_uint16[i].x) << ", ";
            cerr << hex << setw(4) << setfill('0') << uint8_uint16[i].y << ", ";
            cerr << "expected = " << uint8_uint16[i].fExpected << endl;
          }

        // Now test throwing version
        bool fSuccess = true;
        try
          {
            SafeInt<unsigned __int8> si(uint8_uint16[i].x);
            si -= uint8_uint16[i].y;
          }
        catch(...)
          {
            fSuccess = false;
          }

        if( fSuccess != uint8_uint16[i].fExpected )
          {
            cerr << "Error in case uint8_uint16 throw (1): ";
            cerr << hex << setw(2) << setfill('0') << (0xFF & (int)uint8_uint16[i].x) << ", ";
            cerr << hex << setw(4) << setfill('0') << uint8_uint16[i].y << ", ";
            cerr << "expected = " << uint8_uint16[i].fExpected << endl;
          }

        // Also need to test the version that assigns back out
        // to a plain int, as it has different logic
        fSuccess = true;
        try
          {
            unsigned __int8 x(uint8_uint16[i].x);
            x -= SafeInt<unsigned __int64>(uint8_uint16[i].y);
          }
        catch(...)
          {
            fSuccess = false;
          }

        if( fSuccess != uint8_uint16[i].fExpected )
          {
            cerr << "Error in case uint8_uint16 throw (2): ";
            cerr << hex << setw(2) << setfill('0') << (0xFF & (int)uint8_uint16[i].x) << ", ";
            cerr << hex << setw(4) << setfill('0') << uint8_uint16[i].y << ", ";
            cerr << "expected = " << uint8_uint16[i].fExpected << endl;
          }
      }
  }

  static const SubTest< unsigned __int8, unsigned __int8 > uint8_uint8[] =
    {
      { 0x00, 0x00ULL, true},
      { 0x01, 0x00ULL, true},
      { 0x02, 0x00ULL, true},
      { 0x7e, 0x00ULL, true},
      { 0x7f, 0x00ULL, true},
      { 0x80, 0x00ULL, true},
      { 0x81, 0x00ULL, true},
      { 0xfe, 0x00ULL, true},
      { 0xff, 0x00ULL, true},

      { 0x00, 0x01ULL, false},
      { 0x01, 0x01ULL, true},
      { 0x02, 0x01ULL, true},
      { 0x7e, 0x01ULL, true},
      { 0x7f, 0x01ULL, true},
      { 0x80, 0x01ULL, true},
      { 0x81, 0x01ULL, true},
      { 0xfe, 0x01ULL, true},
      { 0xff, 0x01ULL, true},

      { 0x00, 0x02ULL, false},
      { 0x01, 0x02ULL, false},
      { 0x02, 0x02ULL, true},
      { 0x7e, 0x02ULL, true},
      { 0x7f, 0x02ULL, true},
      { 0x80, 0x02ULL, true},
      { 0x81, 0x02ULL, true},
      { 0xfe, 0x02ULL, true},
      { 0xff, 0x02ULL, true},

      { 0x00, 0x7eULL, false},
      { 0x01, 0x7eULL, false},
      { 0x02, 0x7eULL, false},
      { 0x7e, 0x7eULL, true},
      { 0x7f, 0x7eULL, true},
      { 0x80, 0x7eULL, true},
      { 0x81, 0x7eULL, true},
      { 0xfe, 0x7eULL, true},
      { 0xff, 0x7eULL, true},

      { 0x00, 0x7fULL, false},
      { 0x01, 0x7fULL, false},
      { 0x02, 0x7fULL, false},
      { 0x7e, 0x7fULL, false},
      { 0x7f, 0x7fULL, true},
      { 0x80, 0x7fULL, true},
      { 0x81, 0x7fULL, true},
      { 0xfe, 0x7fULL, true},
      { 0xff, 0x7fULL, true},

      { 0x00, 0x80ULL, false},
      { 0x01, 0x80ULL, false},
      { 0x02, 0x80ULL, false},
      { 0x7e, 0x80ULL, false},
      { 0x7f, 0x80ULL, false},
      { 0x80, 0x80ULL, true},
      { 0x81, 0x80ULL, true},
      { 0xfe, 0x80ULL, true},
      { 0xff, 0x80ULL, true},

      { 0x00, 0x81ULL, false},
      { 0x01, 0x81ULL, false},
      { 0x02, 0x81ULL, false},
      { 0x7e, 0x81ULL, false},
      { 0x7f, 0x81ULL, false},
      { 0x80, 0x81ULL, false},
      { 0x81, 0x81ULL, true},
      { 0xfe, 0x81ULL, true},
      { 0xff, 0x81ULL, true},

      { 0x00, 0xfeULL, false},
      { 0x01, 0xfeULL, false},
      { 0x02, 0xfeULL, false},
      { 0x7e, 0xfeULL, false},
      { 0x7f, 0xfeULL, false},
      { 0x80, 0xfeULL, false},
      { 0x81, 0xfeULL, false},
      { 0xfe, 0xfeULL, true},
      { 0xff, 0xfeULL, true},

      { 0x00, 0xffULL, false},
      { 0x01, 0xffULL, false},
      { 0x02, 0xffULL, false},
      { 0x7e, 0xffULL, false},
      { 0x7f, 0xffULL, false},
      { 0x80, 0xffULL, false},
      { 0x81, 0xffULL, false},
      { 0xfe, 0xffULL, false},
      { 0xff, 0xffULL, true},
    };

  void SubVerifyUint8Uint8()
  {
    size_t i;

    for( i = 0; i < COUNTOF(uint8_uint8); ++i )
      {
        unsigned __int8 ret;
        if( SafeSubtract(uint8_uint8[i].x, uint8_uint8[i].y, ret) != uint8_uint8[i].fExpected )
          {
            cerr << "Error in case uint8_uint8: ";
            cerr << hex << setw(2) << setfill('0') << (0xFF & (int)uint8_uint8[i].x) << ", ";
            cerr << hex << setw(2) << setfill('0') << (0xFF & (int)uint8_uint8[i].y) << ", ";
            cerr << "expected = " << uint8_uint8[i].fExpected << endl;
          }

        // Now test throwing version
        bool fSuccess = true;
        try
          {
            SafeInt<unsigned __int8> si(uint8_uint8[i].x);
            si -= uint8_uint8[i].y;
          }
        catch(...)
          {
            fSuccess = false;
          }

        if( fSuccess != uint8_uint8[i].fExpected )
          {
            cerr << "Error in case uint8_uint8 throw (1): ";
            cerr << hex << setw(2) << setfill('0') << (0xFF & (int)uint8_uint8[i].x) << ", ";
            cerr << hex << setw(2) << setfill('0') << (0xFF & (int)uint8_uint8[i].y) << ", ";
            cerr << "expected = " << uint8_uint8[i].fExpected << endl;
          }

        // Also need to test the version that assigns back out
        // to a plain int, as it has different logic
        fSuccess = true;
        try
          {
            unsigned __int8 x(uint8_uint8[i].x);
            x -= SafeInt<unsigned __int64>(uint8_uint8[i].y);
          }
        catch(...)
          {
            fSuccess = false;
          }

        if( fSuccess != uint8_uint8[i].fExpected )
          {
            cerr << "Error in case uint8_uint8 throw (2): ";
            cerr << hex << setw(2) << setfill('0') << (0xFF & (int)uint8_uint8[i].x) << ", ";
            cerr << hex << setw(2) << setfill('0') << (0xFF & (int)uint8_uint8[i].y) << ", ";
            cerr << "expected = " << uint8_uint8[i].fExpected << endl;
          }
      }
  }

  static const SubTest< __int64, __int64 > int64_int64[] =
    {
      { 0x0000000000000000LL, 0x0000000000000000LL, true},
      { 0x0000000000000001LL, 0x0000000000000000LL, true},
      { 0x0000000000000002LL, 0x0000000000000000LL, true},
      { 0x000000007ffffffeLL, 0x0000000000000000LL, true},
      { 0x000000007fffffffLL, 0x0000000000000000LL, true},
      { 0x0000000080000000LL, 0x0000000000000000LL, true},
      { 0x0000000080000001LL, 0x0000000000000000LL, true},
      { 0x00000000fffffffeLL, 0x0000000000000000LL, true},
      { 0x00000000ffffffffLL, 0x0000000000000000LL, true},
      { 0x0000000100000000LL, 0x0000000000000000LL, true},
      { 0x0000000200000000LL, 0x0000000000000000LL, true},
      { 0x7ffffffffffffffeLL, 0x0000000000000000LL, true},
      { 0x7fffffffffffffffLL, 0x0000000000000000LL, true},
      { 0x8000000000000000LL, 0x0000000000000000LL, true},
      { 0x8000000000000001LL, 0x0000000000000000LL, true},
      { 0xfffffffffffffffeLL, 0x0000000000000000LL, true},
      { 0xffffffffffffffffLL, 0x0000000000000000LL, true},

      { 0x0000000000000000LL, 0x0000000000000001LL, true},
      { 0x0000000000000001LL, 0x0000000000000001LL, true},
      { 0x0000000000000002LL, 0x0000000000000001LL, true},
      { 0x000000007ffffffeLL, 0x0000000000000001LL, true},
      { 0x000000007fffffffLL, 0x0000000000000001LL, true},
      { 0x0000000080000000LL, 0x0000000000000001LL, true},
      { 0x0000000080000001LL, 0x0000000000000001LL, true},
      { 0x00000000fffffffeLL, 0x0000000000000001LL, true},
      { 0x00000000ffffffffLL, 0x0000000000000001LL, true},
      { 0x0000000100000000LL, 0x0000000000000001LL, true},
      { 0x0000000200000000LL, 0x0000000000000001LL, true},
      { 0x7ffffffffffffffeLL, 0x0000000000000001LL, true},
      { 0x7fffffffffffffffLL, 0x0000000000000001LL, true},
      { 0x8000000000000000LL, 0x0000000000000001LL, false},
      { 0x8000000000000001LL, 0x0000000000000001LL, true},
      { 0xfffffffffffffffeLL, 0x0000000000000001LL, true},
      { 0xffffffffffffffffLL, 0x0000000000000001LL, true},

      { 0x0000000000000000LL, 0x0000000000000002LL, true},
      { 0x0000000000000001LL, 0x0000000000000002LL, true},
      { 0x0000000000000002LL, 0x0000000000000002LL, true},
      { 0x000000007ffffffeLL, 0x0000000000000002LL, true},
      { 0x000000007fffffffLL, 0x0000000000000002LL, true},
      { 0x0000000080000000LL, 0x0000000000000002LL, true},
      { 0x0000000080000001LL, 0x0000000000000002LL, true},
      { 0x00000000fffffffeLL, 0x0000000000000002LL, true},
      { 0x00000000ffffffffLL, 0x0000000000000002LL, true},
      { 0x0000000100000000LL, 0x0000000000000002LL, true},
      { 0x0000000200000000LL, 0x0000000000000002LL, true},
      { 0x7ffffffffffffffeLL, 0x0000000000000002LL, true},
      { 0x7fffffffffffffffLL, 0x0000000000000002LL, true},
      { 0x8000000000000000LL, 0x0000000000000002LL, false},
      { 0x8000000000000001LL, 0x0000000000000002LL, false},
      { 0xfffffffffffffffeLL, 0x0000000000000002LL, true},
      { 0xffffffffffffffffLL, 0x0000000000000002LL, true},

      { 0x0000000000000000LL, 0x000000007ffffffeLL, true},
      { 0x0000000000000001LL, 0x000000007ffffffeLL, true},
      { 0x0000000000000002LL, 0x000000007ffffffeLL, true},
      { 0x000000007ffffffeLL, 0x000000007ffffffeLL, true},
      { 0x000000007fffffffLL, 0x000000007ffffffeLL, true},
      { 0x0000000080000000LL, 0x000000007ffffffeLL, true},
      { 0x0000000080000001LL, 0x000000007ffffffeLL, true},
      { 0x00000000fffffffeLL, 0x000000007ffffffeLL, true},
      { 0x00000000ffffffffLL, 0x000000007ffffffeLL, true},
      { 0x0000000100000000LL, 0x000000007ffffffeLL, true},
      { 0x0000000200000000LL, 0x000000007ffffffeLL, true},
      { 0x7ffffffffffffffeLL, 0x000000007ffffffeLL, true},
      { 0x7fffffffffffffffLL, 0x000000007ffffffeLL, true},
      { 0x8000000000000000LL, 0x000000007ffffffeLL, false},
      { 0x8000000000000001LL, 0x000000007ffffffeLL, false},
      { 0xfffffffffffffffeLL, 0x000000007ffffffeLL, true},
      { 0xffffffffffffffffLL, 0x000000007ffffffeLL, true},

      { 0x0000000000000000LL, 0x000000007fffffffLL, true},
      { 0x0000000000000001LL, 0x000000007fffffffLL, true},
      { 0x0000000000000002LL, 0x000000007fffffffLL, true},
      { 0x000000007ffffffeLL, 0x000000007fffffffLL, true},
      { 0x000000007fffffffLL, 0x000000007fffffffLL, true},
      { 0x0000000080000000LL, 0x000000007fffffffLL, true},
      { 0x0000000080000001LL, 0x000000007fffffffLL, true},
      { 0x00000000fffffffeLL, 0x000000007fffffffLL, true},
      { 0x00000000ffffffffLL, 0x000000007fffffffLL, true},
      { 0x0000000100000000LL, 0x000000007fffffffLL, true},
      { 0x0000000200000000LL, 0x000000007fffffffLL, true},
      { 0x7ffffffffffffffeLL, 0x000000007fffffffLL, true},
      { 0x7fffffffffffffffLL, 0x000000007fffffffLL, true},
      { 0x8000000000000000LL, 0x000000007fffffffLL, false},
      { 0x8000000000000001LL, 0x000000007fffffffLL, false},
      { 0xfffffffffffffffeLL, 0x000000007fffffffLL, true},
      { 0xffffffffffffffffLL, 0x000000007fffffffLL, true},

      { 0x0000000000000000LL, 0x0000000080000000LL, true},
      { 0x0000000000000001LL, 0x0000000080000000LL, true},
      { 0x0000000000000002LL, 0x0000000080000000LL, true},
      { 0x000000007ffffffeLL, 0x0000000080000000LL, true},
      { 0x000000007fffffffLL, 0x0000000080000000LL, true},
      { 0x0000000080000000LL, 0x0000000080000000LL, true},
      { 0x0000000080000001LL, 0x0000000080000000LL, true},
      { 0x00000000fffffffeLL, 0x0000000080000000LL, true},
      { 0x00000000ffffffffLL, 0x0000000080000000LL, true},
      { 0x0000000100000000LL, 0x0000000080000000LL, true},
      { 0x0000000200000000LL, 0x0000000080000000LL, true},
      { 0x7ffffffffffffffeLL, 0x0000000080000000LL, true},
      { 0x7fffffffffffffffLL, 0x0000000080000000LL, true},
      { 0x8000000000000000LL, 0x0000000080000000LL, false},
      { 0x8000000000000001LL, 0x0000000080000000LL, false},
      { 0xfffffffffffffffeLL, 0x0000000080000000LL, true},
      { 0xffffffffffffffffLL, 0x0000000080000000LL, true},

      { 0x0000000000000000LL, 0x0000000080000001LL, true},
      { 0x0000000000000001LL, 0x0000000080000001LL, true},
      { 0x0000000000000002LL, 0x0000000080000001LL, true},
      { 0x000000007ffffffeLL, 0x0000000080000001LL, true},
      { 0x000000007fffffffLL, 0x0000000080000001LL, true},
      { 0x0000000080000000LL, 0x0000000080000001LL, true},
      { 0x0000000080000001LL, 0x0000000080000001LL, true},
      { 0x00000000fffffffeLL, 0x0000000080000001LL, true},
      { 0x00000000ffffffffLL, 0x0000000080000001LL, true},
      { 0x0000000100000000LL, 0x0000000080000001LL, true},
      { 0x0000000200000000LL, 0x0000000080000001LL, true},
      { 0x7ffffffffffffffeLL, 0x0000000080000001LL, true},
      { 0x7fffffffffffffffLL, 0x0000000080000001LL, true},
      { 0x8000000000000000LL, 0x0000000080000001LL, false},
      { 0x8000000000000001LL, 0x0000000080000001LL, false},
      { 0xfffffffffffffffeLL, 0x0000000080000001LL, true},
      { 0xffffffffffffffffLL, 0x0000000080000001LL, true},

      { 0x0000000000000000LL, 0x00000000fffffffeLL, true},
      { 0x0000000000000001LL, 0x00000000fffffffeLL, true},
      { 0x0000000000000002LL, 0x00000000fffffffeLL, true},
      { 0x000000007ffffffeLL, 0x00000000fffffffeLL, true},
      { 0x000000007fffffffLL, 0x00000000fffffffeLL, true},
      { 0x0000000080000000LL, 0x00000000fffffffeLL, true},
      { 0x0000000080000001LL, 0x00000000fffffffeLL, true},
      { 0x00000000fffffffeLL, 0x00000000fffffffeLL, true},
      { 0x00000000ffffffffLL, 0x00000000fffffffeLL, true},
      { 0x0000000100000000LL, 0x00000000fffffffeLL, true},
      { 0x0000000200000000LL, 0x00000000fffffffeLL, true},
      { 0x7ffffffffffffffeLL, 0x00000000fffffffeLL, true},
      { 0x7fffffffffffffffLL, 0x00000000fffffffeLL, true},
      { 0x8000000000000000LL, 0x00000000fffffffeLL, false},
      { 0x8000000000000001LL, 0x00000000fffffffeLL, false},
      { 0xfffffffffffffffeLL, 0x00000000fffffffeLL, true},
      { 0xffffffffffffffffLL, 0x00000000fffffffeLL, true},

      { 0x0000000000000000LL, 0x00000000ffffffffLL, true},
      { 0x0000000000000001LL, 0x00000000ffffffffLL, true},
      { 0x0000000000000002LL, 0x00000000ffffffffLL, true},
      { 0x000000007ffffffeLL, 0x00000000ffffffffLL, true},
      { 0x000000007fffffffLL, 0x00000000ffffffffLL, true},
      { 0x0000000080000000LL, 0x00000000ffffffffLL, true},
      { 0x0000000080000001LL, 0x00000000ffffffffLL, true},
      { 0x00000000fffffffeLL, 0x00000000ffffffffLL, true},
      { 0x00000000ffffffffLL, 0x00000000ffffffffLL, true},
      { 0x0000000100000000LL, 0x00000000ffffffffLL, true},
      { 0x0000000200000000LL, 0x00000000ffffffffLL, true},
      { 0x7ffffffffffffffeLL, 0x00000000ffffffffLL, true},
      { 0x7fffffffffffffffLL, 0x00000000ffffffffLL, true},
      { 0x8000000000000000LL, 0x00000000ffffffffLL, false},
      { 0x8000000000000001LL, 0x00000000ffffffffLL, false},
      { 0xfffffffffffffffeLL, 0x00000000ffffffffLL, true},
      { 0xffffffffffffffffLL, 0x00000000ffffffffLL, true},

      { 0x0000000000000000LL, 0x0000000100000000LL, true},
      { 0x0000000000000001LL, 0x0000000100000000LL, true},
      { 0x0000000000000002LL, 0x0000000100000000LL, true},
      { 0x000000007ffffffeLL, 0x0000000100000000LL, true},
      { 0x000000007fffffffLL, 0x0000000100000000LL, true},
      { 0x0000000080000000LL, 0x0000000100000000LL, true},
      { 0x0000000080000001LL, 0x0000000100000000LL, true},
      { 0x00000000fffffffeLL, 0x0000000100000000LL, true},
      { 0x00000000ffffffffLL, 0x0000000100000000LL, true},
      { 0x0000000100000000LL, 0x0000000100000000LL, true},
      { 0x0000000200000000LL, 0x0000000100000000LL, true},
      { 0x7ffffffffffffffeLL, 0x0000000100000000LL, true},
      { 0x7fffffffffffffffLL, 0x0000000100000000LL, true},
      { 0x8000000000000000LL, 0x0000000100000000LL, false},
      { 0x8000000000000001LL, 0x0000000100000000LL, false},
      { 0xfffffffffffffffeLL, 0x0000000100000000LL, true},
      { 0xffffffffffffffffLL, 0x0000000100000000LL, true},

      { 0x0000000000000000LL, 0x0000000200000000LL, true},
      { 0x0000000000000001LL, 0x0000000200000000LL, true},
      { 0x0000000000000002LL, 0x0000000200000000LL, true},
      { 0x000000007ffffffeLL, 0x0000000200000000LL, true},
      { 0x000000007fffffffLL, 0x0000000200000000LL, true},
      { 0x0000000080000000LL, 0x0000000200000000LL, true},
      { 0x0000000080000001LL, 0x0000000200000000LL, true},
      { 0x00000000fffffffeLL, 0x0000000200000000LL, true},
      { 0x00000000ffffffffLL, 0x0000000200000000LL, true},
      { 0x0000000100000000LL, 0x0000000200000000LL, true},
      { 0x0000000200000000LL, 0x0000000200000000LL, true},
      { 0x7ffffffffffffffeLL, 0x0000000200000000LL, true},
      { 0x7fffffffffffffffLL, 0x0000000200000000LL, true},
      { 0x8000000000000000LL, 0x0000000200000000LL, false},
      { 0x8000000000000001LL, 0x0000000200000000LL, false},
      { 0xfffffffffffffffeLL, 0x0000000200000000LL, true},
      { 0xffffffffffffffffLL, 0x0000000200000000LL, true},

      { 0x0000000000000000LL, 0x7ffffffffffffffeLL, true},
      { 0x0000000000000001LL, 0x7ffffffffffffffeLL, true},
      { 0x0000000000000002LL, 0x7ffffffffffffffeLL, true},
      { 0x000000007ffffffeLL, 0x7ffffffffffffffeLL, true},
      { 0x000000007fffffffLL, 0x7ffffffffffffffeLL, true},
      { 0x0000000080000000LL, 0x7ffffffffffffffeLL, true},
      { 0x0000000080000001LL, 0x7ffffffffffffffeLL, true},
      { 0x00000000fffffffeLL, 0x7ffffffffffffffeLL, true},
      { 0x00000000ffffffffLL, 0x7ffffffffffffffeLL, true},
      { 0x0000000100000000LL, 0x7ffffffffffffffeLL, true},
      { 0x0000000200000000LL, 0x7ffffffffffffffeLL, true},
      { 0x7ffffffffffffffeLL, 0x7ffffffffffffffeLL, true},
      { 0x7fffffffffffffffLL, 0x7ffffffffffffffeLL, true},
      { 0x8000000000000000LL, 0x7ffffffffffffffeLL, false},
      { 0x8000000000000001LL, 0x7ffffffffffffffeLL, false},
      { 0xfffffffffffffffeLL, 0x7ffffffffffffffeLL, true},
      { 0xffffffffffffffffLL, 0x7ffffffffffffffeLL, true},

      { 0x0000000000000000LL, 0x7fffffffffffffffLL, true},
      { 0x0000000000000001LL, 0x7fffffffffffffffLL, true},
      { 0x0000000000000002LL, 0x7fffffffffffffffLL, true},
      { 0x000000007ffffffeLL, 0x7fffffffffffffffLL, true},
      { 0x000000007fffffffLL, 0x7fffffffffffffffLL, true},
      { 0x0000000080000000LL, 0x7fffffffffffffffLL, true},
      { 0x0000000080000001LL, 0x7fffffffffffffffLL, true},
      { 0x00000000fffffffeLL, 0x7fffffffffffffffLL, true},
      { 0x00000000ffffffffLL, 0x7fffffffffffffffLL, true},
      { 0x0000000100000000LL, 0x7fffffffffffffffLL, true},
      { 0x0000000200000000LL, 0x7fffffffffffffffLL, true},
      { 0x7ffffffffffffffeLL, 0x7fffffffffffffffLL, true},
      { 0x7fffffffffffffffLL, 0x7fffffffffffffffLL, true},
      { 0x8000000000000000LL, 0x7fffffffffffffffLL, false},
      { 0x8000000000000001LL, 0x7fffffffffffffffLL, false},
      { 0xfffffffffffffffeLL, 0x7fffffffffffffffLL, false},
      { 0xffffffffffffffffLL, 0x7fffffffffffffffLL, true},

      { 0x0000000000000000LL, 0x8000000000000000LL, false},
      { 0x0000000000000001LL, 0x8000000000000000LL, false},
      { 0x0000000000000002LL, 0x8000000000000000LL, false},
      { 0x000000007ffffffeLL, 0x8000000000000000LL, false},
      { 0x000000007fffffffLL, 0x8000000000000000LL, false},
      { 0x0000000080000000LL, 0x8000000000000000LL, false},
      { 0x0000000080000001LL, 0x8000000000000000LL, false},
      { 0x00000000fffffffeLL, 0x8000000000000000LL, false},
      { 0x00000000ffffffffLL, 0x8000000000000000LL, false},
      { 0x0000000100000000LL, 0x8000000000000000LL, false},
      { 0x0000000200000000LL, 0x8000000000000000LL, false},
      { 0x7ffffffffffffffeLL, 0x8000000000000000LL, false},
      { 0x7fffffffffffffffLL, 0x8000000000000000LL, false},
      { 0x8000000000000000LL, 0x8000000000000000LL, true},
      { 0x8000000000000001LL, 0x8000000000000000LL, true},
      { 0xfffffffffffffffeLL, 0x8000000000000000LL, true},
      { 0xffffffffffffffffLL, 0x8000000000000000LL, true},

      { 0x0000000000000000LL, 0x8000000000000001LL, true},
      { 0x0000000000000001LL, 0x8000000000000001LL, false},
      { 0x0000000000000002LL, 0x8000000000000001LL, false},
      { 0x000000007ffffffeLL, 0x8000000000000001LL, false},
      { 0x000000007fffffffLL, 0x8000000000000001LL, false},
      { 0x0000000080000000LL, 0x8000000000000001LL, false},
      { 0x0000000080000001LL, 0x8000000000000001LL, false},
      { 0x00000000fffffffeLL, 0x8000000000000001LL, false},
      { 0x00000000ffffffffLL, 0x8000000000000001LL, false},
      { 0x0000000100000000LL, 0x8000000000000001LL, false},
      { 0x0000000200000000LL, 0x8000000000000001LL, false},
      { 0x7ffffffffffffffeLL, 0x8000000000000001LL, false},
      { 0x7fffffffffffffffLL, 0x8000000000000001LL, false},
      { 0x8000000000000000LL, 0x8000000000000001LL, true},
      { 0x8000000000000001LL, 0x8000000000000001LL, true},
      { 0xfffffffffffffffeLL, 0x8000000000000001LL, true},
      { 0xffffffffffffffffLL, 0x8000000000000001LL, true},

      { 0x0000000000000000LL, 0xfffffffffffffffeLL, true},
      { 0x0000000000000001LL, 0xfffffffffffffffeLL, true},
      { 0x0000000000000002LL, 0xfffffffffffffffeLL, true},
      { 0x000000007ffffffeLL, 0xfffffffffffffffeLL, true},
      { 0x000000007fffffffLL, 0xfffffffffffffffeLL, true},
      { 0x0000000080000000LL, 0xfffffffffffffffeLL, true},
      { 0x0000000080000001LL, 0xfffffffffffffffeLL, true},
      { 0x00000000fffffffeLL, 0xfffffffffffffffeLL, true},
      { 0x00000000ffffffffLL, 0xfffffffffffffffeLL, true},
      { 0x0000000100000000LL, 0xfffffffffffffffeLL, true},
      { 0x0000000200000000LL, 0xfffffffffffffffeLL, true},
      { 0x7ffffffffffffffeLL, 0xfffffffffffffffeLL, false},
      { 0x7fffffffffffffffLL, 0xfffffffffffffffeLL, false},
      { 0x8000000000000000LL, 0xfffffffffffffffeLL, true},
      { 0x8000000000000001LL, 0xfffffffffffffffeLL, true},
      { 0xfffffffffffffffeLL, 0xfffffffffffffffeLL, true},
      { 0xffffffffffffffffLL, 0xfffffffffffffffeLL, true},

      { 0x0000000000000000LL, 0xffffffffffffffffLL, true},
      { 0x0000000000000001LL, 0xffffffffffffffffLL, true},
      { 0x0000000000000002LL, 0xffffffffffffffffLL, true},
      { 0x000000007ffffffeLL, 0xffffffffffffffffLL, true},
      { 0x000000007fffffffLL, 0xffffffffffffffffLL, true},
      { 0x0000000080000000LL, 0xffffffffffffffffLL, true},
      { 0x0000000080000001LL, 0xffffffffffffffffLL, true},
      { 0x00000000fffffffeLL, 0xffffffffffffffffLL, true},
      { 0x00000000ffffffffLL, 0xffffffffffffffffLL, true},
      { 0x0000000100000000LL, 0xffffffffffffffffLL, true},
      { 0x0000000200000000LL, 0xffffffffffffffffLL, true},
      { 0x7ffffffffffffffeLL, 0xffffffffffffffffLL, true},
      { 0x7fffffffffffffffLL, 0xffffffffffffffffLL, false},
      { 0x8000000000000000LL, 0xffffffffffffffffLL, true},
      { 0x8000000000000001LL, 0xffffffffffffffffLL, true},
      { 0xfffffffffffffffeLL, 0xffffffffffffffffLL, true},
      { 0xffffffffffffffffLL, 0xffffffffffffffffLL, true},
    };

  void SubVerifyInt64Int64()
  {
    size_t i;

    for( i = 0; i < COUNTOF(int64_int64); ++i )
      {
        __int64 ret;
        if( SafeSubtract(int64_int64[i].x, int64_int64[i].y, ret) != int64_int64[i].fExpected )
          {
            cerr << "Error in case int64_int64: ";
            cerr << hex << setw(16) << setfill('0') << int64_int64[i].x << ", ";
            cerr << hex << setw(16) << setfill('0') << int64_int64[i].y << ", ";
            cerr << "expected = " << int64_int64[i].fExpected << endl;
          }

        // Now test throwing version
        bool fSuccess = true;
        try
          {
            SafeInt<__int64> si(int64_int64[i].x);
            si -= int64_int64[i].y;
          }
        catch(...)
          {
            fSuccess = false;
          }

        if( fSuccess != int64_int64[i].fExpected )
          {
            cerr << "Error in case int64_int64 throw (1): ";
            cerr << hex << setw(16) << setfill('0') << int64_int64[i].x << ", ";
            cerr << hex << setw(16) << setfill('0') << int64_int64[i].y << ", ";
            cerr << "expected = " << int64_int64[i].fExpected << endl;
          }

        // Also need to test the version that assigns back out
        // to a plain int, as it has different logic
        fSuccess = true;
        try
          {
            __int64 x(int64_int64[i].x);
            x -= SafeInt<__int64>(int64_int64[i].y);
          }
        catch(...)
          {
            fSuccess = false;
          }

        if( fSuccess != int64_int64[i].fExpected )
          {
            cerr << "Error in case int64_int64 throw (2): ";
            cerr << hex << setw(16) << setfill('0') << int64_int64[i].x << ", ";
            cerr << hex << setw(16) << setfill('0') << int64_int64[i].y << ", ";
            cerr << "expected = " << int64_int64[i].fExpected << endl;
          }
      }
  }

  static const SubTest< __int64, __int32 > int64_int32[] =
    {
      { 0x0000000000000000LL, 0x00000000, true},
      { 0x0000000000000001LL, 0x00000000, true},
      { 0x0000000000000002LL, 0x00000000, true},
      { 0x000000007ffffffeLL, 0x00000000, true},
      { 0x000000007fffffffLL, 0x00000000, true},
      { 0x0000000080000000LL, 0x00000000, true},
      { 0x0000000080000001LL, 0x00000000, true},
      { 0x00000000fffffffeLL, 0x00000000, true},
      { 0x00000000ffffffffLL, 0x00000000, true},
      { 0x0000000100000000LL, 0x00000000, true},
      { 0x0000000200000000LL, 0x00000000, true},
      { 0x7ffffffffffffffeLL, 0x00000000, true},
      { 0x7fffffffffffffffLL, 0x00000000, true},
      { 0x8000000000000000LL, 0x00000000, true},
      { 0x8000000000000001LL, 0x00000000, true},
      { 0xfffffffffffffffeLL, 0x00000000, true},
      { 0xffffffffffffffffLL, 0x00000000, true},

      { 0x0000000000000000LL, 0x00000001, true},
      { 0x0000000000000001LL, 0x00000001, true},
      { 0x0000000000000002LL, 0x00000001, true},
      { 0x000000007ffffffeLL, 0x00000001, true},
      { 0x000000007fffffffLL, 0x00000001, true},
      { 0x0000000080000000LL, 0x00000001, true},
      { 0x0000000080000001LL, 0x00000001, true},
      { 0x00000000fffffffeLL, 0x00000001, true},
      { 0x00000000ffffffffLL, 0x00000001, true},
      { 0x0000000100000000LL, 0x00000001, true},
      { 0x0000000200000000LL, 0x00000001, true},
      { 0x7ffffffffffffffeLL, 0x00000001, true},
      { 0x7fffffffffffffffLL, 0x00000001, true},
      { 0x8000000000000000LL, 0x00000001, false},
      { 0x8000000000000001LL, 0x00000001, true},
      { 0xfffffffffffffffeLL, 0x00000001, true},
      { 0xffffffffffffffffLL, 0x00000001, true},

      { 0x0000000000000000LL, 0x00000002, true},
      { 0x0000000000000001LL, 0x00000002, true},
      { 0x0000000000000002LL, 0x00000002, true},
      { 0x000000007ffffffeLL, 0x00000002, true},
      { 0x000000007fffffffLL, 0x00000002, true},
      { 0x0000000080000000LL, 0x00000002, true},
      { 0x0000000080000001LL, 0x00000002, true},
      { 0x00000000fffffffeLL, 0x00000002, true},
      { 0x00000000ffffffffLL, 0x00000002, true},
      { 0x0000000100000000LL, 0x00000002, true},
      { 0x0000000200000000LL, 0x00000002, true},
      { 0x7ffffffffffffffeLL, 0x00000002, true},
      { 0x7fffffffffffffffLL, 0x00000002, true},
      { 0x8000000000000000LL, 0x00000002, false},
      { 0x8000000000000001LL, 0x00000002, false},
      { 0xfffffffffffffffeLL, 0x00000002, true},
      { 0xffffffffffffffffLL, 0x00000002, true},

      { 0x0000000000000000LL, 0x7ffffffe, true},
      { 0x0000000000000001LL, 0x7ffffffe, true},
      { 0x0000000000000002LL, 0x7ffffffe, true},
      { 0x000000007ffffffeLL, 0x7ffffffe, true},
      { 0x000000007fffffffLL, 0x7ffffffe, true},
      { 0x0000000080000000LL, 0x7ffffffe, true},
      { 0x0000000080000001LL, 0x7ffffffe, true},
      { 0x00000000fffffffeLL, 0x7ffffffe, true},
      { 0x00000000ffffffffLL, 0x7ffffffe, true},
      { 0x0000000100000000LL, 0x7ffffffe, true},
      { 0x0000000200000000LL, 0x7ffffffe, true},
      { 0x7ffffffffffffffeLL, 0x7ffffffe, true},
      { 0x7fffffffffffffffLL, 0x7ffffffe, true},
      { 0x8000000000000000LL, 0x7ffffffe, false},
      { 0x8000000000000001LL, 0x7ffffffe, false},
      { 0xfffffffffffffffeLL, 0x7ffffffe, true},
      { 0xffffffffffffffffLL, 0x7ffffffe, true},

      { 0x0000000000000000LL, 0x7fffffff, true},
      { 0x0000000000000001LL, 0x7fffffff, true},
      { 0x0000000000000002LL, 0x7fffffff, true},
      { 0x000000007ffffffeLL, 0x7fffffff, true},
      { 0x000000007fffffffLL, 0x7fffffff, true},
      { 0x0000000080000000LL, 0x7fffffff, true},
      { 0x0000000080000001LL, 0x7fffffff, true},
      { 0x00000000fffffffeLL, 0x7fffffff, true},
      { 0x00000000ffffffffLL, 0x7fffffff, true},
      { 0x0000000100000000LL, 0x7fffffff, true},
      { 0x0000000200000000LL, 0x7fffffff, true},
      { 0x7ffffffffffffffeLL, 0x7fffffff, true},
      { 0x7fffffffffffffffLL, 0x7fffffff, true},
      { 0x8000000000000000LL, 0x7fffffff, false},
      { 0x8000000000000001LL, 0x7fffffff, false},
      { 0xfffffffffffffffeLL, 0x7fffffff, true},
      { 0xffffffffffffffffLL, 0x7fffffff, true},

      { 0x0000000000000000LL, 0x80000000, true},
      { 0x0000000000000001LL, 0x80000000, true},
      { 0x0000000000000002LL, 0x80000000, true},
      { 0x000000007ffffffeLL, 0x80000000, true},
      { 0x000000007fffffffLL, 0x80000000, true},
      { 0x0000000080000000LL, 0x80000000, true},
      { 0x0000000080000001LL, 0x80000000, true},
      { 0x00000000fffffffeLL, 0x80000000, true},
      { 0x00000000ffffffffLL, 0x80000000, true},
      { 0x0000000100000000LL, 0x80000000, true},
      { 0x0000000200000000LL, 0x80000000, true},
      { 0x7ffffffffffffffeLL, 0x80000000, false},
      { 0x7fffffffffffffffLL, 0x80000000, false},
      { 0x8000000000000000LL, 0x80000000, true},
      { 0x8000000000000001LL, 0x80000000, true},
      { 0xfffffffffffffffeLL, 0x80000000, true},
      { 0xffffffffffffffffLL, 0x80000000, true},

      { 0x0000000000000000LL, 0x80000001, true},
      { 0x0000000000000001LL, 0x80000001, true},
      { 0x0000000000000002LL, 0x80000001, true},
      { 0x000000007ffffffeLL, 0x80000001, true},
      { 0x000000007fffffffLL, 0x80000001, true},
      { 0x0000000080000000LL, 0x80000001, true},
      { 0x0000000080000001LL, 0x80000001, true},
      { 0x00000000fffffffeLL, 0x80000001, true},
      { 0x00000000ffffffffLL, 0x80000001, true},
      { 0x0000000100000000LL, 0x80000001, true},
      { 0x0000000200000000LL, 0x80000001, true},
      { 0x7ffffffffffffffeLL, 0x80000001, false},
      { 0x7fffffffffffffffLL, 0x80000001, false},
      { 0x8000000000000000LL, 0x80000001, true},
      { 0x8000000000000001LL, 0x80000001, true},
      { 0xfffffffffffffffeLL, 0x80000001, true},
      { 0xffffffffffffffffLL, 0x80000001, true},

      { 0x0000000000000000LL, 0xfffffffe, true},
      { 0x0000000000000001LL, 0xfffffffe, true},
      { 0x0000000000000002LL, 0xfffffffe, true},
      { 0x000000007ffffffeLL, 0xfffffffe, true},
      { 0x000000007fffffffLL, 0xfffffffe, true},
      { 0x0000000080000000LL, 0xfffffffe, true},
      { 0x0000000080000001LL, 0xfffffffe, true},
      { 0x00000000fffffffeLL, 0xfffffffe, true},
      { 0x00000000ffffffffLL, 0xfffffffe, true},
      { 0x0000000100000000LL, 0xfffffffe, true},
      { 0x0000000200000000LL, 0xfffffffe, true},
      { 0x7ffffffffffffffeLL, 0xfffffffe, false},
      { 0x7fffffffffffffffLL, 0xfffffffe, false},
      { 0x8000000000000000LL, 0xfffffffe, true},
      { 0x8000000000000001LL, 0xfffffffe, true},
      { 0xfffffffffffffffeLL, 0xfffffffe, true},
      { 0xffffffffffffffffLL, 0xfffffffe, true},

      { 0x0000000000000000LL, 0xffffffff, true},
      { 0x0000000000000001LL, 0xffffffff, true},
      { 0x0000000000000002LL, 0xffffffff, true},
      { 0x000000007ffffffeLL, 0xffffffff, true},
      { 0x000000007fffffffLL, 0xffffffff, true},
      { 0x0000000080000000LL, 0xffffffff, true},
      { 0x0000000080000001LL, 0xffffffff, true},
      { 0x00000000fffffffeLL, 0xffffffff, true},
      { 0x00000000ffffffffLL, 0xffffffff, true},
      { 0x0000000100000000LL, 0xffffffff, true},
      { 0x0000000200000000LL, 0xffffffff, true},
      { 0x7ffffffffffffffeLL, 0xffffffff, true},
      { 0x7fffffffffffffffLL, 0xffffffff, false},
      { 0x8000000000000000LL, 0xffffffff, true},
      { 0x8000000000000001LL, 0xffffffff, true},
      { 0xfffffffffffffffeLL, 0xffffffff, true},
      { 0xffffffffffffffffLL, 0xffffffff, true},
    };

  void SubVerifyInt64Int32()
  {
    size_t i;

    for( i = 0; i < COUNTOF(int64_int32); ++i )
      {
        __int64 ret;
        if( SafeSubtract(int64_int32[i].x, int64_int32[i].y, ret) != int64_int32[i].fExpected )
          {
            cerr << "Error in case int64_int32: ";
            cerr << hex << setw(16) << setfill('0') << int64_int32[i].x << ", ";
            cerr << hex << setw(8) << setfill('0') << int64_int32[i].y << ", ";
            cerr << "expected = " << int64_int32[i].fExpected << endl;
          }

        // Now test throwing version
        bool fSuccess = true;
        try
          {
            SafeInt<__int64> si(int64_int32[i].x);
            si -= int64_int32[i].y;
          }
        catch(...)
          {
            fSuccess = false;
          }

        if( fSuccess != int64_int32[i].fExpected )
          {
            cerr << "Error in case int64_int32 throw (1): ";
            cerr << hex << setw(16) << setfill('0') << int64_int32[i].x << ", ";
            cerr << hex << setw(8) << setfill('0') << int64_int32[i].y << ", ";
            cerr << "expected = " << int64_int32[i].fExpected << endl;
          }

        // Also need to test the version that assigns back out
        // to a plain int, as it has different logic
        fSuccess = true;
        try
          {
            __int64 x(int64_int32[i].x);
            x -= SafeInt<__int64>(int64_int32[i].y);
          }
        catch(...)
          {
            fSuccess = false;
          }

        if( fSuccess != int64_int32[i].fExpected )
          {
            cerr << "Error in case int64_int32 throw (2): ";
            cerr << hex << setw(16) << setfill('0') << int64_int32[i].x << ", ";
            cerr << hex << setw(8) << setfill('0') << int64_int32[i].y << ", ";
            cerr << "expected = " << int64_int32[i].fExpected << endl;
          }
      }
  }

  static const SubTest< __int64, __int16 > int64_int16[] =
    {
      { 0x0000000000000000LL, 0x0000, true},
      { 0x0000000000000001LL, 0x0000, true},
      { 0x0000000000000002LL, 0x0000, true},
      { 0x000000007ffffffeLL, 0x0000, true},
      { 0x000000007fffffffLL, 0x0000, true},
      { 0x0000000080000000LL, 0x0000, true},
      { 0x0000000080000001LL, 0x0000, true},
      { 0x00000000fffffffeLL, 0x0000, true},
      { 0x00000000ffffffffLL, 0x0000, true},
      { 0x0000000100000000LL, 0x0000, true},
      { 0x0000000200000000LL, 0x0000, true},
      { 0x7ffffffffffffffeLL, 0x0000, true},
      { 0x7fffffffffffffffLL, 0x0000, true},
      { 0x8000000000000000LL, 0x0000, true},
      { 0x8000000000000001LL, 0x0000, true},
      { 0xfffffffffffffffeLL, 0x0000, true},
      { 0xffffffffffffffffLL, 0x0000, true},

      { 0x0000000000000000LL, 0x0001, true},
      { 0x0000000000000001LL, 0x0001, true},
      { 0x0000000000000002LL, 0x0001, true},
      { 0x000000007ffffffeLL, 0x0001, true},
      { 0x000000007fffffffLL, 0x0001, true},
      { 0x0000000080000000LL, 0x0001, true},
      { 0x0000000080000001LL, 0x0001, true},
      { 0x00000000fffffffeLL, 0x0001, true},
      { 0x00000000ffffffffLL, 0x0001, true},
      { 0x0000000100000000LL, 0x0001, true},
      { 0x0000000200000000LL, 0x0001, true},
      { 0x7ffffffffffffffeLL, 0x0001, true},
      { 0x7fffffffffffffffLL, 0x0001, true},
      { 0x8000000000000000LL, 0x0001, false},
      { 0x8000000000000001LL, 0x0001, true},
      { 0xfffffffffffffffeLL, 0x0001, true},
      { 0xffffffffffffffffLL, 0x0001, true},

      { 0x0000000000000000LL, 0x0002, true},
      { 0x0000000000000001LL, 0x0002, true},
      { 0x0000000000000002LL, 0x0002, true},
      { 0x000000007ffffffeLL, 0x0002, true},
      { 0x000000007fffffffLL, 0x0002, true},
      { 0x0000000080000000LL, 0x0002, true},
      { 0x0000000080000001LL, 0x0002, true},
      { 0x00000000fffffffeLL, 0x0002, true},
      { 0x00000000ffffffffLL, 0x0002, true},
      { 0x0000000100000000LL, 0x0002, true},
      { 0x0000000200000000LL, 0x0002, true},
      { 0x7ffffffffffffffeLL, 0x0002, true},
      { 0x7fffffffffffffffLL, 0x0002, true},
      { 0x8000000000000000LL, 0x0002, false},
      { 0x8000000000000001LL, 0x0002, false},
      { 0xfffffffffffffffeLL, 0x0002, true},
      { 0xffffffffffffffffLL, 0x0002, true},

      { 0x0000000000000000LL, 0x7ffe, true},
      { 0x0000000000000001LL, 0x7ffe, true},
      { 0x0000000000000002LL, 0x7ffe, true},
      { 0x000000007ffffffeLL, 0x7ffe, true},
      { 0x000000007fffffffLL, 0x7ffe, true},
      { 0x0000000080000000LL, 0x7ffe, true},
      { 0x0000000080000001LL, 0x7ffe, true},
      { 0x00000000fffffffeLL, 0x7ffe, true},
      { 0x00000000ffffffffLL, 0x7ffe, true},
      { 0x0000000100000000LL, 0x7ffe, true},
      { 0x0000000200000000LL, 0x7ffe, true},
      { 0x7ffffffffffffffeLL, 0x7ffe, true},
      { 0x7fffffffffffffffLL, 0x7ffe, true},
      { 0x8000000000000000LL, 0x7ffe, false},
      { 0x8000000000000001LL, 0x7ffe, false},
      { 0xfffffffffffffffeLL, 0x7ffe, true},
      { 0xffffffffffffffffLL, 0x7ffe, true},

      { 0x0000000000000000LL, 0x7fff, true},
      { 0x0000000000000001LL, 0x7fff, true},
      { 0x0000000000000002LL, 0x7fff, true},
      { 0x000000007ffffffeLL, 0x7fff, true},
      { 0x000000007fffffffLL, 0x7fff, true},
      { 0x0000000080000000LL, 0x7fff, true},
      { 0x0000000080000001LL, 0x7fff, true},
      { 0x00000000fffffffeLL, 0x7fff, true},
      { 0x00000000ffffffffLL, 0x7fff, true},
      { 0x0000000100000000LL, 0x7fff, true},
      { 0x0000000200000000LL, 0x7fff, true},
      { 0x7ffffffffffffffeLL, 0x7fff, true},
      { 0x7fffffffffffffffLL, 0x7fff, true},
      { 0x8000000000000000LL, 0x7fff, false},
      { 0x8000000000000001LL, 0x7fff, false},
      { 0xfffffffffffffffeLL, 0x7fff, true},
      { 0xffffffffffffffffLL, 0x7fff, true},

      { 0x0000000000000000LL, 0x8000, true},
      { 0x0000000000000001LL, 0x8000, true},
      { 0x0000000000000002LL, 0x8000, true},
      { 0x000000007ffffffeLL, 0x8000, true},
      { 0x000000007fffffffLL, 0x8000, true},
      { 0x0000000080000000LL, 0x8000, true},
      { 0x0000000080000001LL, 0x8000, true},
      { 0x00000000fffffffeLL, 0x8000, true},
      { 0x00000000ffffffffLL, 0x8000, true},
      { 0x0000000100000000LL, 0x8000, true},
      { 0x0000000200000000LL, 0x8000, true},
      { 0x7ffffffffffffffeLL, 0x8000, false},
      { 0x7fffffffffffffffLL, 0x8000, false},
      { 0x8000000000000000LL, 0x8000, true},
      { 0x8000000000000001LL, 0x8000, true},
      { 0xfffffffffffffffeLL, 0x8000, true},
      { 0xffffffffffffffffLL, 0x8000, true},

      { 0x0000000000000000LL, 0x8001, true},
      { 0x0000000000000001LL, 0x8001, true},
      { 0x0000000000000002LL, 0x8001, true},
      { 0x000000007ffffffeLL, 0x8001, true},
      { 0x000000007fffffffLL, 0x8001, true},
      { 0x0000000080000000LL, 0x8001, true},
      { 0x0000000080000001LL, 0x8001, true},
      { 0x00000000fffffffeLL, 0x8001, true},
      { 0x00000000ffffffffLL, 0x8001, true},
      { 0x0000000100000000LL, 0x8001, true},
      { 0x0000000200000000LL, 0x8001, true},
      { 0x7ffffffffffffffeLL, 0x8001, false},
      { 0x7fffffffffffffffLL, 0x8001, false},
      { 0x8000000000000000LL, 0x8001, true},
      { 0x8000000000000001LL, 0x8001, true},
      { 0xfffffffffffffffeLL, 0x8001, true},
      { 0xffffffffffffffffLL, 0x8001, true},

      { 0x0000000000000000LL, 0xfffe, true},
      { 0x0000000000000001LL, 0xfffe, true},
      { 0x0000000000000002LL, 0xfffe, true},
      { 0x000000007ffffffeLL, 0xfffe, true},
      { 0x000000007fffffffLL, 0xfffe, true},
      { 0x0000000080000000LL, 0xfffe, true},
      { 0x0000000080000001LL, 0xfffe, true},
      { 0x00000000fffffffeLL, 0xfffe, true},
      { 0x00000000ffffffffLL, 0xfffe, true},
      { 0x0000000100000000LL, 0xfffe, true},
      { 0x0000000200000000LL, 0xfffe, true},
      { 0x7ffffffffffffffeLL, 0xfffe, false},
      { 0x7fffffffffffffffLL, 0xfffe, false},
      { 0x8000000000000000LL, 0xfffe, true},
      { 0x8000000000000001LL, 0xfffe, true},
      { 0xfffffffffffffffeLL, 0xfffe, true},
      { 0xffffffffffffffffLL, 0xfffe, true},

      { 0x0000000000000000LL, 0xffff, true},
      { 0x0000000000000001LL, 0xffff, true},
      { 0x0000000000000002LL, 0xffff, true},
      { 0x000000007ffffffeLL, 0xffff, true},
      { 0x000000007fffffffLL, 0xffff, true},
      { 0x0000000080000000LL, 0xffff, true},
      { 0x0000000080000001LL, 0xffff, true},
      { 0x00000000fffffffeLL, 0xffff, true},
      { 0x00000000ffffffffLL, 0xffff, true},
      { 0x0000000100000000LL, 0xffff, true},
      { 0x0000000200000000LL, 0xffff, true},
      { 0x7ffffffffffffffeLL, 0xffff, true},
      { 0x7fffffffffffffffLL, 0xffff, false},
      { 0x8000000000000000LL, 0xffff, true},
      { 0x8000000000000001LL, 0xffff, true},
      { 0xfffffffffffffffeLL, 0xffff, true},
      { 0xffffffffffffffffLL, 0xffff, true},
    };

  void SubVerifyInt64Int16()
  {
    size_t i;

    for( i = 0; i < COUNTOF(int64_int16); ++i )
      {
        __int64 ret;
        if( SafeSubtract(int64_int16[i].x, int64_int16[i].y, ret) != int64_int16[i].fExpected )
          {
            cerr << "Error in case int64_int16: ";
            cerr << hex << setw(16) << setfill('0') << int64_int16[i].x << ", ";
            cerr << hex << setw(4) << setfill('0') << int64_int16[i].y << ", ";
            cerr << "expected = " << int64_int16[i].fExpected << endl;
          }

        // Now test throwing version
        bool fSuccess = true;
        try
          {
            SafeInt<__int64> si(int64_int16[i].x);
            si -= int64_int16[i].y;
          }
        catch(...)
          {
            fSuccess = false;
          }

        if( fSuccess != int64_int16[i].fExpected )
          {
            cerr << "Error in case int64_int16 throw (1): ";
            cerr << hex << setw(16) << setfill('0') << int64_int16[i].x << ", ";
            cerr << hex << setw(4) << setfill('0') << int64_int16[i].y << ", ";
            cerr << "expected = " << int64_int16[i].fExpected << endl;
          }

        // Also need to test the version that assigns back out
        // to a plain int, as it has different logic
        fSuccess = true;
        try
          {
            __int64 x(int64_int16[i].x);
            x -= SafeInt<__int64>(int64_int16[i].y);
          }
        catch(...)
          {
            fSuccess = false;
          }

        if( fSuccess != int64_int16[i].fExpected )
          {
            cerr << "Error in case int64_int16 throw (2): ";
            cerr << hex << setw(16) << setfill('0') << int64_int16[i].x << ", ";
            cerr << hex << setw(4) << setfill('0') << int64_int16[i].y << ", ";
            cerr << "expected = " << int64_int16[i].fExpected << endl;
          }
      }
  }

  static const SubTest< __int64, __int8 > int64_int8[] =
    {
      { 0x0000000000000000LL, 0x00, true},
      { 0x0000000000000001LL, 0x00, true},
      { 0x0000000000000002LL, 0x00, true},
      { 0x000000007ffffffeLL, 0x00, true},
      { 0x000000007fffffffLL, 0x00, true},
      { 0x0000000080000000LL, 0x00, true},
      { 0x0000000080000001LL, 0x00, true},
      { 0x00000000fffffffeLL, 0x00, true},
      { 0x00000000ffffffffLL, 0x00, true},
      { 0x0000000100000000LL, 0x00, true},
      { 0x0000000200000000LL, 0x00, true},
      { 0x7ffffffffffffffeLL, 0x00, true},
      { 0x7fffffffffffffffLL, 0x00, true},
      { 0x8000000000000000LL, 0x00, true},
      { 0x8000000000000001LL, 0x00, true},
      { 0xfffffffffffffffeLL, 0x00, true},
      { 0xffffffffffffffffLL, 0x00, true},

      { 0x0000000000000000LL, 0x01, true},
      { 0x0000000000000001LL, 0x01, true},
      { 0x0000000000000002LL, 0x01, true},
      { 0x000000007ffffffeLL, 0x01, true},
      { 0x000000007fffffffLL, 0x01, true},
      { 0x0000000080000000LL, 0x01, true},
      { 0x0000000080000001LL, 0x01, true},
      { 0x00000000fffffffeLL, 0x01, true},
      { 0x00000000ffffffffLL, 0x01, true},
      { 0x0000000100000000LL, 0x01, true},
      { 0x0000000200000000LL, 0x01, true},
      { 0x7ffffffffffffffeLL, 0x01, true},
      { 0x7fffffffffffffffLL, 0x01, true},
      { 0x8000000000000000LL, 0x01, false},
      { 0x8000000000000001LL, 0x01, true},
      { 0xfffffffffffffffeLL, 0x01, true},
      { 0xffffffffffffffffLL, 0x01, true},

      { 0x0000000000000000LL, 0x02, true},
      { 0x0000000000000001LL, 0x02, true},
      { 0x0000000000000002LL, 0x02, true},
      { 0x000000007ffffffeLL, 0x02, true},
      { 0x000000007fffffffLL, 0x02, true},
      { 0x0000000080000000LL, 0x02, true},
      { 0x0000000080000001LL, 0x02, true},
      { 0x00000000fffffffeLL, 0x02, true},
      { 0x00000000ffffffffLL, 0x02, true},
      { 0x0000000100000000LL, 0x02, true},
      { 0x0000000200000000LL, 0x02, true},
      { 0x7ffffffffffffffeLL, 0x02, true},
      { 0x7fffffffffffffffLL, 0x02, true},
      { 0x8000000000000000LL, 0x02, false},
      { 0x8000000000000001LL, 0x02, false},
      { 0xfffffffffffffffeLL, 0x02, true},
      { 0xffffffffffffffffLL, 0x02, true},

      { 0x0000000000000000LL, 0x7e, true},
      { 0x0000000000000001LL, 0x7e, true},
      { 0x0000000000000002LL, 0x7e, true},
      { 0x000000007ffffffeLL, 0x7e, true},
      { 0x000000007fffffffLL, 0x7e, true},
      { 0x0000000080000000LL, 0x7e, true},
      { 0x0000000080000001LL, 0x7e, true},
      { 0x00000000fffffffeLL, 0x7e, true},
      { 0x00000000ffffffffLL, 0x7e, true},
      { 0x0000000100000000LL, 0x7e, true},
      { 0x0000000200000000LL, 0x7e, true},
      { 0x7ffffffffffffffeLL, 0x7e, true},
      { 0x7fffffffffffffffLL, 0x7e, true},
      { 0x8000000000000000LL, 0x7e, false},
      { 0x8000000000000001LL, 0x7e, false},
      { 0xfffffffffffffffeLL, 0x7e, true},
      { 0xffffffffffffffffLL, 0x7e, true},

      { 0x0000000000000000LL, 0x7f, true},
      { 0x0000000000000001LL, 0x7f, true},
      { 0x0000000000000002LL, 0x7f, true},
      { 0x000000007ffffffeLL, 0x7f, true},
      { 0x000000007fffffffLL, 0x7f, true},
      { 0x0000000080000000LL, 0x7f, true},
      { 0x0000000080000001LL, 0x7f, true},
      { 0x00000000fffffffeLL, 0x7f, true},
      { 0x00000000ffffffffLL, 0x7f, true},
      { 0x0000000100000000LL, 0x7f, true},
      { 0x0000000200000000LL, 0x7f, true},
      { 0x7ffffffffffffffeLL, 0x7f, true},
      { 0x7fffffffffffffffLL, 0x7f, true},
      { 0x8000000000000000LL, 0x7f, false},
      { 0x8000000000000001LL, 0x7f, false},
      { 0xfffffffffffffffeLL, 0x7f, true},
      { 0xffffffffffffffffLL, 0x7f, true},

      { 0x0000000000000000LL, 0x80, true},
      { 0x0000000000000001LL, 0x80, true},
      { 0x0000000000000002LL, 0x80, true},
      { 0x000000007ffffffeLL, 0x80, true},
      { 0x000000007fffffffLL, 0x80, true},
      { 0x0000000080000000LL, 0x80, true},
      { 0x0000000080000001LL, 0x80, true},
      { 0x00000000fffffffeLL, 0x80, true},
      { 0x00000000ffffffffLL, 0x80, true},
      { 0x0000000100000000LL, 0x80, true},
      { 0x0000000200000000LL, 0x80, true},
      { 0x7ffffffffffffffeLL, 0x80, false},
      { 0x7fffffffffffffffLL, 0x80, false},
      { 0x8000000000000000LL, 0x80, true},
      { 0x8000000000000001LL, 0x80, true},
      { 0xfffffffffffffffeLL, 0x80, true},
      { 0xffffffffffffffffLL, 0x80, true},

      { 0x0000000000000000LL, 0x81, true},
      { 0x0000000000000001LL, 0x81, true},
      { 0x0000000000000002LL, 0x81, true},
      { 0x000000007ffffffeLL, 0x81, true},
      { 0x000000007fffffffLL, 0x81, true},
      { 0x0000000080000000LL, 0x81, true},
      { 0x0000000080000001LL, 0x81, true},
      { 0x00000000fffffffeLL, 0x81, true},
      { 0x00000000ffffffffLL, 0x81, true},
      { 0x0000000100000000LL, 0x81, true},
      { 0x0000000200000000LL, 0x81, true},
      { 0x7ffffffffffffffeLL, 0x81, false},
      { 0x7fffffffffffffffLL, 0x81, false},
      { 0x8000000000000000LL, 0x81, true},
      { 0x8000000000000001LL, 0x81, true},
      { 0xfffffffffffffffeLL, 0x81, true},
      { 0xffffffffffffffffLL, 0x81, true},

      { 0x0000000000000000LL, 0xfe, true},
      { 0x0000000000000001LL, 0xfe, true},
      { 0x0000000000000002LL, 0xfe, true},
      { 0x000000007ffffffeLL, 0xfe, true},
      { 0x000000007fffffffLL, 0xfe, true},
      { 0x0000000080000000LL, 0xfe, true},
      { 0x0000000080000001LL, 0xfe, true},
      { 0x00000000fffffffeLL, 0xfe, true},
      { 0x00000000ffffffffLL, 0xfe, true},
      { 0x0000000100000000LL, 0xfe, true},
      { 0x0000000200000000LL, 0xfe, true},
      { 0x7ffffffffffffffeLL, 0xfe, false},
      { 0x7fffffffffffffffLL, 0xfe, false},
      { 0x8000000000000000LL, 0xfe, true},
      { 0x8000000000000001LL, 0xfe, true},
      { 0xfffffffffffffffeLL, 0xfe, true},
      { 0xffffffffffffffffLL, 0xfe, true},

      { 0x0000000000000000LL, 0xff, true},
      { 0x0000000000000001LL, 0xff, true},
      { 0x0000000000000002LL, 0xff, true},
      { 0x000000007ffffffeLL, 0xff, true},
      { 0x000000007fffffffLL, 0xff, true},
      { 0x0000000080000000LL, 0xff, true},
      { 0x0000000080000001LL, 0xff, true},
      { 0x00000000fffffffeLL, 0xff, true},
      { 0x00000000ffffffffLL, 0xff, true},
      { 0x0000000100000000LL, 0xff, true},
      { 0x0000000200000000LL, 0xff, true},
      { 0x7ffffffffffffffeLL, 0xff, true},
      { 0x7fffffffffffffffLL, 0xff, false},
      { 0x8000000000000000LL, 0xff, true},
      { 0x8000000000000001LL, 0xff, true},
      { 0xfffffffffffffffeLL, 0xff, true},
      { 0xffffffffffffffffLL, 0xff, true},
    };

  void SubVerifyInt64Int8()
  {
    size_t i;

    for( i = 0; i < COUNTOF(int64_int8); ++i )
      {
        __int64 ret;
        if( SafeSubtract(int64_int8[i].x, int64_int8[i].y, ret) != int64_int8[i].fExpected )
          {
            cerr << "Error in case int64_int8: ";
            cerr << hex << setw(16) << setfill('0') << int64_int8[i].x << ", ";
            cerr << hex << setw(2) << setfill('0') << (0xFF & (int)int64_int8[i].y) << ", ";
            cerr << "expected = " << int64_int8[i].fExpected << endl;
          }

        // Now test throwing version
        bool fSuccess = true;
        try
          {
            SafeInt<__int64> si(int64_int8[i].x);
            si -= int64_int8[i].y;
          }
        catch(...)
          {
            fSuccess = false;
          }

        if( fSuccess != int64_int8[i].fExpected )
          {
            cerr << "Error in case int64_int8 throw (1): ";
            cerr << hex << setw(16) << setfill('0') << int64_int8[i].x << ", ";
            cerr << hex << setw(2) << setfill('0') << (0xFF & (int)int64_int8[i].y) << ", ";
            cerr << "expected = " << int64_int8[i].fExpected << endl;
          }

        // Also need to test the version that assigns back out
        // to a plain int, as it has different logic
        fSuccess = true;
        try
          {
            __int64 x(int64_int8[i].x);
            x -= SafeInt<__int64>(int64_int8[i].y);
          }
        catch(...)
          {
            fSuccess = false;
          }

        if( fSuccess != int64_int8[i].fExpected )
          {
            cerr << "Error in case int64_int8 throw (2): ";
            cerr << hex << setw(16) << setfill('0') << int64_int8[i].x << ", ";
            cerr << hex << setw(2) << setfill('0') << (0xFF & (int)int64_int8[i].y) << ", ";
            cerr << "expected = " << int64_int8[i].fExpected << endl;
          }
      }
  }

  static const SubTest< __int8, __int64 > int8_int64[] =
    {
      { 0x00, 0x0000000000000000LL, true},
      { 0x01, 0x0000000000000000LL, true},
      { 0x02, 0x0000000000000000LL, true},
      { 0x7e, 0x0000000000000000LL, true},
      { 0x7f, 0x0000000000000000LL, true},
      { 0x80, 0x0000000000000000LL, true},
      { 0x81, 0x0000000000000000LL, true},
      { 0xfe, 0x0000000000000000LL, true},
      { 0xff, 0x0000000000000000LL, true},

      { 0x00, 0x0000000000000001LL, true},
      { 0x01, 0x0000000000000001LL, true},
      { 0x02, 0x0000000000000001LL, true},
      { 0x7e, 0x0000000000000001LL, true},
      { 0x7f, 0x0000000000000001LL, true},
      { 0x80, 0x0000000000000001LL, false},
      { 0x81, 0x0000000000000001LL, true},
      { 0xfe, 0x0000000000000001LL, true},
      { 0xff, 0x0000000000000001LL, true},

      { 0x00, 0x0000000000000002LL, true},
      { 0x01, 0x0000000000000002LL, true},
      { 0x02, 0x0000000000000002LL, true},
      { 0x7e, 0x0000000000000002LL, true},
      { 0x7f, 0x0000000000000002LL, true},
      { 0x80, 0x0000000000000002LL, false},
      { 0x81, 0x0000000000000002LL, false},
      { 0xfe, 0x0000000000000002LL, true},
      { 0xff, 0x0000000000000002LL, true},

      { 0x00, 0x000000007ffffffeLL, false},
      { 0x01, 0x000000007ffffffeLL, false},
      { 0x02, 0x000000007ffffffeLL, false},
      { 0x7e, 0x000000007ffffffeLL, false},
      { 0x7f, 0x000000007ffffffeLL, false},
      { 0x80, 0x000000007ffffffeLL, false},
      { 0x81, 0x000000007ffffffeLL, false},
      { 0xfe, 0x000000007ffffffeLL, false},
      { 0xff, 0x000000007ffffffeLL, false},

      { 0x00, 0x000000007fffffffLL, false},
      { 0x01, 0x000000007fffffffLL, false},
      { 0x02, 0x000000007fffffffLL, false},
      { 0x7e, 0x000000007fffffffLL, false},
      { 0x7f, 0x000000007fffffffLL, false},
      { 0x80, 0x000000007fffffffLL, false},
      { 0x81, 0x000000007fffffffLL, false},
      { 0xfe, 0x000000007fffffffLL, false},
      { 0xff, 0x000000007fffffffLL, false},

      { 0x00, 0x0000000080000000LL, false},
      { 0x01, 0x0000000080000000LL, false},
      { 0x02, 0x0000000080000000LL, false},
      { 0x7e, 0x0000000080000000LL, false},
      { 0x7f, 0x0000000080000000LL, false},
      { 0x80, 0x0000000080000000LL, false},
      { 0x81, 0x0000000080000000LL, false},
      { 0xfe, 0x0000000080000000LL, false},
      { 0xff, 0x0000000080000000LL, false},

      { 0x00, 0x0000000080000001LL, false},
      { 0x01, 0x0000000080000001LL, false},
      { 0x02, 0x0000000080000001LL, false},
      { 0x7e, 0x0000000080000001LL, false},
      { 0x7f, 0x0000000080000001LL, false},
      { 0x80, 0x0000000080000001LL, false},
      { 0x81, 0x0000000080000001LL, false},
      { 0xfe, 0x0000000080000001LL, false},
      { 0xff, 0x0000000080000001LL, false},

      { 0x00, 0x00000000fffffffeLL, false},
      { 0x01, 0x00000000fffffffeLL, false},
      { 0x02, 0x00000000fffffffeLL, false},
      { 0x7e, 0x00000000fffffffeLL, false},
      { 0x7f, 0x00000000fffffffeLL, false},
      { 0x80, 0x00000000fffffffeLL, false},
      { 0x81, 0x00000000fffffffeLL, false},
      { 0xfe, 0x00000000fffffffeLL, false},
      { 0xff, 0x00000000fffffffeLL, false},

      { 0x00, 0x00000000ffffffffLL, false},
      { 0x01, 0x00000000ffffffffLL, false},
      { 0x02, 0x00000000ffffffffLL, false},
      { 0x7e, 0x00000000ffffffffLL, false},
      { 0x7f, 0x00000000ffffffffLL, false},
      { 0x80, 0x00000000ffffffffLL, false},
      { 0x81, 0x00000000ffffffffLL, false},
      { 0xfe, 0x00000000ffffffffLL, false},
      { 0xff, 0x00000000ffffffffLL, false},

      { 0x00, 0x0000000100000000LL, false},
      { 0x01, 0x0000000100000000LL, false},
      { 0x02, 0x0000000100000000LL, false},
      { 0x7e, 0x0000000100000000LL, false},
      { 0x7f, 0x0000000100000000LL, false},
      { 0x80, 0x0000000100000000LL, false},
      { 0x81, 0x0000000100000000LL, false},
      { 0xfe, 0x0000000100000000LL, false},
      { 0xff, 0x0000000100000000LL, false},

      { 0x00, 0x0000000200000000LL, false},
      { 0x01, 0x0000000200000000LL, false},
      { 0x02, 0x0000000200000000LL, false},
      { 0x7e, 0x0000000200000000LL, false},
      { 0x7f, 0x0000000200000000LL, false},
      { 0x80, 0x0000000200000000LL, false},
      { 0x81, 0x0000000200000000LL, false},
      { 0xfe, 0x0000000200000000LL, false},
      { 0xff, 0x0000000200000000LL, false},

      { 0x00, 0x7ffffffffffffffeLL, false},
      { 0x01, 0x7ffffffffffffffeLL, false},
      { 0x02, 0x7ffffffffffffffeLL, false},
      { 0x7e, 0x7ffffffffffffffeLL, false},
      { 0x7f, 0x7ffffffffffffffeLL, false},
      { 0x80, 0x7ffffffffffffffeLL, false},
      { 0x81, 0x7ffffffffffffffeLL, false},
      { 0xfe, 0x7ffffffffffffffeLL, false},
      { 0xff, 0x7ffffffffffffffeLL, false},

      { 0x00, 0x7fffffffffffffffLL, false},
      { 0x01, 0x7fffffffffffffffLL, false},
      { 0x02, 0x7fffffffffffffffLL, false},
      { 0x7e, 0x7fffffffffffffffLL, false},
      { 0x7f, 0x7fffffffffffffffLL, false},
      { 0x80, 0x7fffffffffffffffLL, false},
      { 0x81, 0x7fffffffffffffffLL, false},
      { 0xfe, 0x7fffffffffffffffLL, false},
      { 0xff, 0x7fffffffffffffffLL, false},

      { 0x00, 0x8000000000000000LL, false},
      { 0x01, 0x8000000000000000LL, false},
      { 0x02, 0x8000000000000000LL, false},
      { 0x7e, 0x8000000000000000LL, false},
      { 0x7f, 0x8000000000000000LL, false},
      { 0x80, 0x8000000000000000LL, false},
      { 0x81, 0x8000000000000000LL, false},
      { 0xfe, 0x8000000000000000LL, false},
      { 0xff, 0x8000000000000000LL, false},

      { 0x00, 0x8000000000000001LL, false},
      { 0x01, 0x8000000000000001LL, false},
      { 0x02, 0x8000000000000001LL, false},
      { 0x7e, 0x8000000000000001LL, false},
      { 0x7f, 0x8000000000000001LL, false},
      { 0x80, 0x8000000000000001LL, false},
      { 0x81, 0x8000000000000001LL, false},
      { 0xfe, 0x8000000000000001LL, false},
      { 0xff, 0x8000000000000001LL, false},

      { 0x00, 0xfffffffffffffffeLL, true},
      { 0x01, 0xfffffffffffffffeLL, true},
      { 0x02, 0xfffffffffffffffeLL, true},
      { 0x7e, 0xfffffffffffffffeLL, false},
      { 0x7f, 0xfffffffffffffffeLL, false},
      { 0x80, 0xfffffffffffffffeLL, true},
      { 0x81, 0xfffffffffffffffeLL, true},
      { 0xfe, 0xfffffffffffffffeLL, true},
      { 0xff, 0xfffffffffffffffeLL, true},

      { 0x00, 0xffffffffffffffffLL, true},
      { 0x01, 0xffffffffffffffffLL, true},
      { 0x02, 0xffffffffffffffffLL, true},
      { 0x7e, 0xffffffffffffffffLL, true},
      { 0x7f, 0xffffffffffffffffLL, false},
      { 0x80, 0xffffffffffffffffLL, true},
      { 0x81, 0xffffffffffffffffLL, true},
      { 0xfe, 0xffffffffffffffffLL, true},
      { 0xff, 0xffffffffffffffffLL, true},
    };

  void SubVerifyInt8Int64()
  {
    size_t i;

    for( i = 0; i < COUNTOF(int8_int64); ++i )
      {
        __int8 ret;
        if( SafeSubtract(int8_int64[i].x, int8_int64[i].y, ret) != int8_int64[i].fExpected )
          {
            cerr << "Error in case int8_int64: ";
            cerr << hex << setw(2) << setfill('0') << (0xFF & (int)int8_int64[i].x) << ", ";
            cerr << hex << setw(16) << setfill('0') << int8_int64[i].y << ", ";
            cerr << "expected = " << int8_int64[i].fExpected << endl;
          }

        // Now test throwing version
        bool fSuccess = true;
        try
          {
            SafeInt<__int8> si(int8_int64[i].x);
            si -= int8_int64[i].y;
          }
        catch(...)
          {
            fSuccess = false;
          }

        if( fSuccess != int8_int64[i].fExpected )
          {
            cerr << "Error in case int8_int64 throw (1): ";
            cerr << hex << setw(2) << setfill('0') << (0xFF & (int)int8_int64[i].x) << ", ";
            cerr << hex << setw(16) << setfill('0') << int8_int64[i].y << ", ";
            cerr << "expected = " << int8_int64[i].fExpected << endl;
          }

        // Also need to test the version that assigns back out
        // to a plain int, as it has different logic
        fSuccess = true;
        try
          {
            __int8 x(int8_int64[i].x);
            x -= SafeInt<__int64>(int8_int64[i].y);
          }
        catch(...)
          {
            fSuccess = false;
          }

        if( fSuccess != int8_int64[i].fExpected )
          {
            cerr << "Error in case int8_int64 throw (2): ";
            cerr << hex << setw(2) << setfill('0') << (0xFF & (int)int8_int64[i].x) << ", ";
            cerr << hex << setw(16) << setfill('0') << int8_int64[i].y << ", ";
            cerr << "expected = " << int8_int64[i].fExpected << endl;
          }
      }
  }

  static const SubTest< __int8, __int32 > int8_int32[] =
    {
      { 0x00, 0x00000000LL, true},
      { 0x01, 0x00000000LL, true},
      { 0x02, 0x00000000LL, true},
      { 0x7e, 0x00000000LL, true},
      { 0x7f, 0x00000000LL, true},
      { 0x80, 0x00000000LL, true},
      { 0x81, 0x00000000LL, true},
      { 0xfe, 0x00000000LL, true},
      { 0xff, 0x00000000LL, true},

      { 0x00, 0x00000001LL, true},
      { 0x01, 0x00000001LL, true},
      { 0x02, 0x00000001LL, true},
      { 0x7e, 0x00000001LL, true},
      { 0x7f, 0x00000001LL, true},
      { 0x80, 0x00000001LL, false},
      { 0x81, 0x00000001LL, true},
      { 0xfe, 0x00000001LL, true},
      { 0xff, 0x00000001LL, true},

      { 0x00, 0x00000002LL, true},
      { 0x01, 0x00000002LL, true},
      { 0x02, 0x00000002LL, true},
      { 0x7e, 0x00000002LL, true},
      { 0x7f, 0x00000002LL, true},
      { 0x80, 0x00000002LL, false},
      { 0x81, 0x00000002LL, false},
      { 0xfe, 0x00000002LL, true},
      { 0xff, 0x00000002LL, true},

      { 0x00, 0x7ffffffeLL, false},
      { 0x01, 0x7ffffffeLL, false},
      { 0x02, 0x7ffffffeLL, false},
      { 0x7e, 0x7ffffffeLL, false},
      { 0x7f, 0x7ffffffeLL, false},
      { 0x80, 0x7ffffffeLL, false},
      { 0x81, 0x7ffffffeLL, false},
      { 0xfe, 0x7ffffffeLL, false},
      { 0xff, 0x7ffffffeLL, false},

      { 0x00, 0x7fffffffLL, false},
      { 0x01, 0x7fffffffLL, false},
      { 0x02, 0x7fffffffLL, false},
      { 0x7e, 0x7fffffffLL, false},
      { 0x7f, 0x7fffffffLL, false},
      { 0x80, 0x7fffffffLL, false},
      { 0x81, 0x7fffffffLL, false},
      { 0xfe, 0x7fffffffLL, false},
      { 0xff, 0x7fffffffLL, false},

      { 0x00, 0x80000000LL, false},
      { 0x01, 0x80000000LL, false},
      { 0x02, 0x80000000LL, false},
      { 0x7e, 0x80000000LL, false},
      { 0x7f, 0x80000000LL, false},
      { 0x80, 0x80000000LL, false},
      { 0x81, 0x80000000LL, false},
      { 0xfe, 0x80000000LL, false},
      { 0xff, 0x80000000LL, false},

      { 0x00, 0x80000001LL, false},
      { 0x01, 0x80000001LL, false},
      { 0x02, 0x80000001LL, false},
      { 0x7e, 0x80000001LL, false},
      { 0x7f, 0x80000001LL, false},
      { 0x80, 0x80000001LL, false},
      { 0x81, 0x80000001LL, false},
      { 0xfe, 0x80000001LL, false},
      { 0xff, 0x80000001LL, false},

      { 0x00, 0xfffffffeLL, true},
      { 0x01, 0xfffffffeLL, true},
      { 0x02, 0xfffffffeLL, true},
      { 0x7e, 0xfffffffeLL, false},
      { 0x7f, 0xfffffffeLL, false},
      { 0x80, 0xfffffffeLL, true},
      { 0x81, 0xfffffffeLL, true},
      { 0xfe, 0xfffffffeLL, true},
      { 0xff, 0xfffffffeLL, true},

      { 0x00, 0xffffffffLL, true},
      { 0x01, 0xffffffffLL, true},
      { 0x02, 0xffffffffLL, true},
      { 0x7e, 0xffffffffLL, true},
      { 0x7f, 0xffffffffLL, false},
      { 0x80, 0xffffffffLL, true},
      { 0x81, 0xffffffffLL, true},
      { 0xfe, 0xffffffffLL, true},
      { 0xff, 0xffffffffLL, true},
    };

  void SubVerifyInt8Int32()
  {
    size_t i;

    for( i = 0; i < COUNTOF(int8_int32); ++i )
      {
        __int8 ret;
        if( SafeSubtract(int8_int32[i].x, int8_int32[i].y, ret) != int8_int32[i].fExpected )
          {
            cerr << "Error in case int8_int32: ";
            cerr << hex << setw(2) << setfill('0') << (0xFF & (int)int8_int32[i].x) << ", ";
            cerr << hex << setw(8) << setfill('0') << int8_int32[i].y << ", ";
            cerr << "expected = " << int8_int32[i].fExpected << endl;
          }

        // Now test throwing version
        bool fSuccess = true;
        try
          {
            SafeInt<__int8> si(int8_int32[i].x);
            si -= int8_int32[i].y;
          }
        catch(...)
          {
            fSuccess = false;
          }

        if( fSuccess != int8_int32[i].fExpected )
          {
            cerr << "Error in case int8_int32 throw (1): ";
            cerr << hex << setw(2) << setfill('0') << (0xFF & (int)int8_int32[i].x) << ", ";
            cerr << hex << setw(8) << setfill('0') << int8_int32[i].y << ", ";
            cerr << "expected = " << int8_int32[i].fExpected << endl;
          }

        // Also need to test the version that assigns back out
        // to a plain int, as it has different logic
        fSuccess = true;
        try
          {
            __int8 x(int8_int32[i].x);
            x -= SafeInt<__int64>(int8_int32[i].y);
          }
        catch(...)
          {
            fSuccess = false;
          }

        if( fSuccess != int8_int32[i].fExpected )
          {
            cerr << "Error in case int8_int32 throw (2): ";
            cerr << hex << setw(2) << setfill('0') << (0xFF & (int)int8_int32[i].x) << ", ";
            cerr << hex << setw(8) << setfill('0') << int8_int32[i].y << ", ";
            cerr << "expected = " << int8_int32[i].fExpected << endl;
          }
      }
  }

  static const SubTest< __int8, __int16 > int8_int16[] =
    {
      { 0x00, 0x0000LL, true},
      { 0x01, 0x0000LL, true},
      { 0x02, 0x0000LL, true},
      { 0x7e, 0x0000LL, true},
      { 0x7f, 0x0000LL, true},
      { 0x80, 0x0000LL, true},
      { 0x81, 0x0000LL, true},
      { 0xfe, 0x0000LL, true},
      { 0xff, 0x0000LL, true},

      { 0x00, 0x0001LL, true},
      { 0x01, 0x0001LL, true},
      { 0x02, 0x0001LL, true},
      { 0x7e, 0x0001LL, true},
      { 0x7f, 0x0001LL, true},
      { 0x80, 0x0001LL, false},
      { 0x81, 0x0001LL, true},
      { 0xfe, 0x0001LL, true},
      { 0xff, 0x0001LL, true},

      { 0x00, 0x0002LL, true},
      { 0x01, 0x0002LL, true},
      { 0x02, 0x0002LL, true},
      { 0x7e, 0x0002LL, true},
      { 0x7f, 0x0002LL, true},
      { 0x80, 0x0002LL, false},
      { 0x81, 0x0002LL, false},
      { 0xfe, 0x0002LL, true},
      { 0xff, 0x0002LL, true},

      { 0x00, 0x7ffeLL, false},
      { 0x01, 0x7ffeLL, false},
      { 0x02, 0x7ffeLL, false},
      { 0x7e, 0x7ffeLL, false},
      { 0x7f, 0x7ffeLL, false},
      { 0x80, 0x7ffeLL, false},
      { 0x81, 0x7ffeLL, false},
      { 0xfe, 0x7ffeLL, false},
      { 0xff, 0x7ffeLL, false},

      { 0x00, 0x7fffLL, false},
      { 0x01, 0x7fffLL, false},
      { 0x02, 0x7fffLL, false},
      { 0x7e, 0x7fffLL, false},
      { 0x7f, 0x7fffLL, false},
      { 0x80, 0x7fffLL, false},
      { 0x81, 0x7fffLL, false},
      { 0xfe, 0x7fffLL, false},
      { 0xff, 0x7fffLL, false},

      { 0x00, 0x8000LL, false},
      { 0x01, 0x8000LL, false},
      { 0x02, 0x8000LL, false},
      { 0x7e, 0x8000LL, false},
      { 0x7f, 0x8000LL, false},
      { 0x80, 0x8000LL, false},
      { 0x81, 0x8000LL, false},
      { 0xfe, 0x8000LL, false},
      { 0xff, 0x8000LL, false},

      { 0x00, 0x8001LL, false},
      { 0x01, 0x8001LL, false},
      { 0x02, 0x8001LL, false},
      { 0x7e, 0x8001LL, false},
      { 0x7f, 0x8001LL, false},
      { 0x80, 0x8001LL, false},
      { 0x81, 0x8001LL, false},
      { 0xfe, 0x8001LL, false},
      { 0xff, 0x8001LL, false},

      { 0x00, 0xfffeLL, true},
      { 0x01, 0xfffeLL, true},
      { 0x02, 0xfffeLL, true},
      { 0x7e, 0xfffeLL, false},
      { 0x7f, 0xfffeLL, false},
      { 0x80, 0xfffeLL, true},
      { 0x81, 0xfffeLL, true},
      { 0xfe, 0xfffeLL, true},
      { 0xff, 0xfffeLL, true},

      { 0x00, 0xffffLL, true},
      { 0x01, 0xffffLL, true},
      { 0x02, 0xffffLL, true},
      { 0x7e, 0xffffLL, true},
      { 0x7f, 0xffffLL, false},
      { 0x80, 0xffffLL, true},
      { 0x81, 0xffffLL, true},
      { 0xfe, 0xffffLL, true},
      { 0xff, 0xffffLL, true},
    };

  void SubVerifyInt8Int16()
  {
    size_t i;

    for( i = 0; i < COUNTOF(int8_int16); ++i )
      {
        __int8 ret;
        if( SafeSubtract(int8_int16[i].x, int8_int16[i].y, ret) != int8_int16[i].fExpected )
          {
            cerr << "Error in case int8_int16: ";
            cerr << hex << setw(2) << setfill('0') << (0xFF & (int)int8_int16[i].x) << ", ";
            cerr << hex << setw(4) << setfill('0') << int8_int16[i].y << ", ";
            cerr << "expected = " << int8_int16[i].fExpected << endl;
          }

        // Now test throwing version
        bool fSuccess = true;
        try
          {
            SafeInt<__int8> si(int8_int16[i].x);
            si -= int8_int16[i].y;
          }
        catch(...)
          {
            fSuccess = false;
          }

        if( fSuccess != int8_int16[i].fExpected )
          {
            cerr << "Error in case int8_int16 throw (1): ";
            cerr << hex << setw(2) << setfill('0') << (0xFF & (int)int8_int16[i].x) << ", ";
            cerr << hex << setw(4) << setfill('0') << int8_int16[i].y << ", ";
            cerr << "expected = " << int8_int16[i].fExpected << endl;
          }

        // Also need to test the version that assigns back out
        // to a plain int, as it has different logic
        fSuccess = true;
        try
          {
            __int8 x(int8_int16[i].x);
            x -= SafeInt<__int64>(int8_int16[i].y);
          }
        catch(...)
          {
            fSuccess = false;
          }

        if( fSuccess != int8_int16[i].fExpected )
          {
            cerr << "Error in case int8_int16 throw (2): ";
            cerr << hex << setw(2) << setfill('0') << (0xFF & (int)int8_int16[i].x) << ", ";
            cerr << hex << setw(4) << setfill('0') << int8_int16[i].y << ", ";
            cerr << "expected = " << int8_int16[i].fExpected << endl;
          }
      }
  }

  static const SubTest< __int8, __int8 > int8_int8[] =
    {
      { 0x00, 0x00LL, true},
      { 0x01, 0x00LL, true},
      { 0x02, 0x00LL, true},
      { 0x7e, 0x00LL, true},
      { 0x7f, 0x00LL, true},
      { 0x80, 0x00LL, true},
      { 0x81, 0x00LL, true},
      { 0xfe, 0x00LL, true},
      { 0xff, 0x00LL, true},

      { 0x00, 0x01LL, true},
      { 0x01, 0x01LL, true},
      { 0x02, 0x01LL, true},
      { 0x7e, 0x01LL, true},
      { 0x7f, 0x01LL, true},
      { 0x80, 0x01LL, false},
      { 0x81, 0x01LL, true},
      { 0xfe, 0x01LL, true},
      { 0xff, 0x01LL, true},

      { 0x00, 0x02LL, true},
      { 0x01, 0x02LL, true},
      { 0x02, 0x02LL, true},
      { 0x7e, 0x02LL, true},
      { 0x7f, 0x02LL, true},
      { 0x80, 0x02LL, false},
      { 0x81, 0x02LL, false},
      { 0xfe, 0x02LL, true},
      { 0xff, 0x02LL, true},

      { 0x00, 0x7eLL, true},
      { 0x01, 0x7eLL, true},
      { 0x02, 0x7eLL, true},
      { 0x7e, 0x7eLL, true},
      { 0x7f, 0x7eLL, true},
      { 0x80, 0x7eLL, false},
      { 0x81, 0x7eLL, false},
      { 0xfe, 0x7eLL, true},
      { 0xff, 0x7eLL, true},

      { 0x00, 0x7fLL, true},
      { 0x01, 0x7fLL, true},
      { 0x02, 0x7fLL, true},
      { 0x7e, 0x7fLL, true},
      { 0x7f, 0x7fLL, true},
      { 0x80, 0x7fLL, false},
      { 0x81, 0x7fLL, false},
      { 0xfe, 0x7fLL, false},
      { 0xff, 0x7fLL, true},

      { 0x00, 0x80LL, false},
      { 0x01, 0x80LL, false},
      { 0x02, 0x80LL, false},
      { 0x7e, 0x80LL, false},
      { 0x7f, 0x80LL, false},
      { 0x80, 0x80LL, true},
      { 0x81, 0x80LL, true},
      { 0xfe, 0x80LL, true},
      { 0xff, 0x80LL, true},

      { 0x00, 0x81LL, true},
      { 0x01, 0x81LL, false},
      { 0x02, 0x81LL, false},
      { 0x7e, 0x81LL, false},
      { 0x7f, 0x81LL, false},
      { 0x80, 0x81LL, true},
      { 0x81, 0x81LL, true},
      { 0xfe, 0x81LL, true},
      { 0xff, 0x81LL, true},

      { 0x00, 0xfeLL, true},
      { 0x01, 0xfeLL, true},
      { 0x02, 0xfeLL, true},
      { 0x7e, 0xfeLL, false},
      { 0x7f, 0xfeLL, false},
      { 0x80, 0xfeLL, true},
      { 0x81, 0xfeLL, true},
      { 0xfe, 0xfeLL, true},
      { 0xff, 0xfeLL, true},

      { 0x00, 0xffLL, true},
      { 0x01, 0xffLL, true},
      { 0x02, 0xffLL, true},
      { 0x7e, 0xffLL, true},
      { 0x7f, 0xffLL, false},
      { 0x80, 0xffLL, true},
      { 0x81, 0xffLL, true},
      { 0xfe, 0xffLL, true},
      { 0xff, 0xffLL, true},
    };

  void SubVerifyInt8Int8()
  {
    size_t i;

    for( i = 0; i < COUNTOF(int8_int8); ++i )
      {
        __int8 ret;
        if( SafeSubtract(int8_int8[i].x, int8_int8[i].y, ret) != int8_int8[i].fExpected )
          {
            cerr << "Error in case int8_int8: ";
            cerr << hex << setw(2) << setfill('0') << (0xFF & (int)int8_int8[i].x) << ", ";
            cerr << hex << setw(2) << setfill('0') << (0xFF & (int)int8_int8[i].y) << ", ";
            cerr << "expected = " << int8_int8[i].fExpected << endl;
          }

        // Now test throwing version
        bool fSuccess = true;
        try
          {
            SafeInt<__int8> si(int8_int8[i].x);
            si -= int8_int8[i].y;
          }
        catch(...)
          {
            fSuccess = false;
          }

        if( fSuccess != int8_int8[i].fExpected )
          {
            cerr << "Error in case int8_int8 throw (1): ";
            cerr << hex << setw(2) << setfill('0') << (0xFF & (int)int8_int8[i].x) << ", ";
            cerr << hex << setw(2) << setfill('0') << (0xFF & (int)int8_int8[i].y) << ", ";
            cerr << "expected = " << int8_int8[i].fExpected << endl;
          }

        // Also need to test the version that assigns back out
        // to a plain int, as it has different logic
        fSuccess = true;
        try
          {
            __int8 x(int8_int8[i].x);
            x -= SafeInt<__int64>(int8_int8[i].y);
          }
        catch(...)
          {
            fSuccess = false;
          }

        if( fSuccess != int8_int8[i].fExpected )
          {
            cerr << "Error in case int8_int8 throw (2): ";
            cerr << hex << setw(2) << setfill('0') << (0xFF & (int)int8_int8[i].x) << ", ";
            cerr << hex << setw(2) << setfill('0') << (0xFF & (int)int8_int8[i].y) << ", ";
            cerr << "expected = " << int8_int8[i].fExpected << endl;
          }
      }
  }

  static const SubTest< unsigned __int64, __int64 > uint64_int64[] =
    {
      { 0x0000000000000000ULL, 0x0000000000000000LL, true},
      { 0x0000000000000001ULL, 0x0000000000000000LL, true},
      { 0x0000000000000002ULL, 0x0000000000000000LL, true},
      { 0x000000007ffffffeULL, 0x0000000000000000LL, true},
      { 0x000000007fffffffULL, 0x0000000000000000LL, true},
      { 0x0000000080000000ULL, 0x0000000000000000LL, true},
      { 0x0000000080000001ULL, 0x0000000000000000LL, true},
      { 0x00000000fffffffeULL, 0x0000000000000000LL, true},
      { 0x00000000ffffffffULL, 0x0000000000000000LL, true},
      { 0x0000000100000000ULL, 0x0000000000000000LL, true},
      { 0x0000000200000000ULL, 0x0000000000000000LL, true},
      { 0x7ffffffffffffffeULL, 0x0000000000000000LL, true},
      { 0x7fffffffffffffffULL, 0x0000000000000000LL, true},
      { 0x8000000000000000ULL, 0x0000000000000000LL, true},
      { 0x8000000000000001ULL, 0x0000000000000000LL, true},
      { 0xfffffffffffffffeULL, 0x0000000000000000LL, true},
      { 0xffffffffffffffffULL, 0x0000000000000000LL, true},

      { 0x0000000000000000ULL, 0x0000000000000001LL, false},
      { 0x0000000000000001ULL, 0x0000000000000001LL, true},
      { 0x0000000000000002ULL, 0x0000000000000001LL, true},
      { 0x000000007ffffffeULL, 0x0000000000000001LL, true},
      { 0x000000007fffffffULL, 0x0000000000000001LL, true},
      { 0x0000000080000000ULL, 0x0000000000000001LL, true},
      { 0x0000000080000001ULL, 0x0000000000000001LL, true},
      { 0x00000000fffffffeULL, 0x0000000000000001LL, true},
      { 0x00000000ffffffffULL, 0x0000000000000001LL, true},
      { 0x0000000100000000ULL, 0x0000000000000001LL, true},
      { 0x0000000200000000ULL, 0x0000000000000001LL, true},
      { 0x7ffffffffffffffeULL, 0x0000000000000001LL, true},
      { 0x7fffffffffffffffULL, 0x0000000000000001LL, true},
      { 0x8000000000000000ULL, 0x0000000000000001LL, true},
      { 0x8000000000000001ULL, 0x0000000000000001LL, true},
      { 0xfffffffffffffffeULL, 0x0000000000000001LL, true},
      { 0xffffffffffffffffULL, 0x0000000000000001LL, true},

      { 0x0000000000000000ULL, 0x0000000000000002LL, false},
      { 0x0000000000000001ULL, 0x0000000000000002LL, false},
      { 0x0000000000000002ULL, 0x0000000000000002LL, true},
      { 0x000000007ffffffeULL, 0x0000000000000002LL, true},
      { 0x000000007fffffffULL, 0x0000000000000002LL, true},
      { 0x0000000080000000ULL, 0x0000000000000002LL, true},
      { 0x0000000080000001ULL, 0x0000000000000002LL, true},
      { 0x00000000fffffffeULL, 0x0000000000000002LL, true},
      { 0x00000000ffffffffULL, 0x0000000000000002LL, true},
      { 0x0000000100000000ULL, 0x0000000000000002LL, true},
      { 0x0000000200000000ULL, 0x0000000000000002LL, true},
      { 0x7ffffffffffffffeULL, 0x0000000000000002LL, true},
      { 0x7fffffffffffffffULL, 0x0000000000000002LL, true},
      { 0x8000000000000000ULL, 0x0000000000000002LL, true},
      { 0x8000000000000001ULL, 0x0000000000000002LL, true},
      { 0xfffffffffffffffeULL, 0x0000000000000002LL, true},
      { 0xffffffffffffffffULL, 0x0000000000000002LL, true},

      { 0x0000000000000000ULL, 0x000000007ffffffeLL, false},
      { 0x0000000000000001ULL, 0x000000007ffffffeLL, false},
      { 0x0000000000000002ULL, 0x000000007ffffffeLL, false},
      { 0x000000007ffffffeULL, 0x000000007ffffffeLL, true},
      { 0x000000007fffffffULL, 0x000000007ffffffeLL, true},
      { 0x0000000080000000ULL, 0x000000007ffffffeLL, true},
      { 0x0000000080000001ULL, 0x000000007ffffffeLL, true},
      { 0x00000000fffffffeULL, 0x000000007ffffffeLL, true},
      { 0x00000000ffffffffULL, 0x000000007ffffffeLL, true},
      { 0x0000000100000000ULL, 0x000000007ffffffeLL, true},
      { 0x0000000200000000ULL, 0x000000007ffffffeLL, true},
      { 0x7ffffffffffffffeULL, 0x000000007ffffffeLL, true},
      { 0x7fffffffffffffffULL, 0x000000007ffffffeLL, true},
      { 0x8000000000000000ULL, 0x000000007ffffffeLL, true},
      { 0x8000000000000001ULL, 0x000000007ffffffeLL, true},
      { 0xfffffffffffffffeULL, 0x000000007ffffffeLL, true},
      { 0xffffffffffffffffULL, 0x000000007ffffffeLL, true},

      { 0x0000000000000000ULL, 0x000000007fffffffLL, false},
      { 0x0000000000000001ULL, 0x000000007fffffffLL, false},
      { 0x0000000000000002ULL, 0x000000007fffffffLL, false},
      { 0x000000007ffffffeULL, 0x000000007fffffffLL, false},
      { 0x000000007fffffffULL, 0x000000007fffffffLL, true},
      { 0x0000000080000000ULL, 0x000000007fffffffLL, true},
      { 0x0000000080000001ULL, 0x000000007fffffffLL, true},
      { 0x00000000fffffffeULL, 0x000000007fffffffLL, true},
      { 0x00000000ffffffffULL, 0x000000007fffffffLL, true},
      { 0x0000000100000000ULL, 0x000000007fffffffLL, true},
      { 0x0000000200000000ULL, 0x000000007fffffffLL, true},
      { 0x7ffffffffffffffeULL, 0x000000007fffffffLL, true},
      { 0x7fffffffffffffffULL, 0x000000007fffffffLL, true},
      { 0x8000000000000000ULL, 0x000000007fffffffLL, true},
      { 0x8000000000000001ULL, 0x000000007fffffffLL, true},
      { 0xfffffffffffffffeULL, 0x000000007fffffffLL, true},
      { 0xffffffffffffffffULL, 0x000000007fffffffLL, true},

      { 0x0000000000000000ULL, 0x0000000080000000LL, false},
      { 0x0000000000000001ULL, 0x0000000080000000LL, false},
      { 0x0000000000000002ULL, 0x0000000080000000LL, false},
      { 0x000000007ffffffeULL, 0x0000000080000000LL, false},
      { 0x000000007fffffffULL, 0x0000000080000000LL, false},
      { 0x0000000080000000ULL, 0x0000000080000000LL, true},
      { 0x0000000080000001ULL, 0x0000000080000000LL, true},
      { 0x00000000fffffffeULL, 0x0000000080000000LL, true},
      { 0x00000000ffffffffULL, 0x0000000080000000LL, true},
      { 0x0000000100000000ULL, 0x0000000080000000LL, true},
      { 0x0000000200000000ULL, 0x0000000080000000LL, true},
      { 0x7ffffffffffffffeULL, 0x0000000080000000LL, true},
      { 0x7fffffffffffffffULL, 0x0000000080000000LL, true},
      { 0x8000000000000000ULL, 0x0000000080000000LL, true},
      { 0x8000000000000001ULL, 0x0000000080000000LL, true},
      { 0xfffffffffffffffeULL, 0x0000000080000000LL, true},
      { 0xffffffffffffffffULL, 0x0000000080000000LL, true},

      { 0x0000000000000000ULL, 0x0000000080000001LL, false},
      { 0x0000000000000001ULL, 0x0000000080000001LL, false},
      { 0x0000000000000002ULL, 0x0000000080000001LL, false},
      { 0x000000007ffffffeULL, 0x0000000080000001LL, false},
      { 0x000000007fffffffULL, 0x0000000080000001LL, false},
      { 0x0000000080000000ULL, 0x0000000080000001LL, false},
      { 0x0000000080000001ULL, 0x0000000080000001LL, true},
      { 0x00000000fffffffeULL, 0x0000000080000001LL, true},
      { 0x00000000ffffffffULL, 0x0000000080000001LL, true},
      { 0x0000000100000000ULL, 0x0000000080000001LL, true},
      { 0x0000000200000000ULL, 0x0000000080000001LL, true},
      { 0x7ffffffffffffffeULL, 0x0000000080000001LL, true},
      { 0x7fffffffffffffffULL, 0x0000000080000001LL, true},
      { 0x8000000000000000ULL, 0x0000000080000001LL, true},
      { 0x8000000000000001ULL, 0x0000000080000001LL, true},
      { 0xfffffffffffffffeULL, 0x0000000080000001LL, true},
      { 0xffffffffffffffffULL, 0x0000000080000001LL, true},

      { 0x0000000000000000ULL, 0x00000000fffffffeLL, false},
      { 0x0000000000000001ULL, 0x00000000fffffffeLL, false},
      { 0x0000000000000002ULL, 0x00000000fffffffeLL, false},
      { 0x000000007ffffffeULL, 0x00000000fffffffeLL, false},
      { 0x000000007fffffffULL, 0x00000000fffffffeLL, false},
      { 0x0000000080000000ULL, 0x00000000fffffffeLL, false},
      { 0x0000000080000001ULL, 0x00000000fffffffeLL, false},
      { 0x00000000fffffffeULL, 0x00000000fffffffeLL, true},
      { 0x00000000ffffffffULL, 0x00000000fffffffeLL, true},
      { 0x0000000100000000ULL, 0x00000000fffffffeLL, true},
      { 0x0000000200000000ULL, 0x00000000fffffffeLL, true},
      { 0x7ffffffffffffffeULL, 0x00000000fffffffeLL, true},
      { 0x7fffffffffffffffULL, 0x00000000fffffffeLL, true},
      { 0x8000000000000000ULL, 0x00000000fffffffeLL, true},
      { 0x8000000000000001ULL, 0x00000000fffffffeLL, true},
      { 0xfffffffffffffffeULL, 0x00000000fffffffeLL, true},
      { 0xffffffffffffffffULL, 0x00000000fffffffeLL, true},

      { 0x0000000000000000ULL, 0x00000000ffffffffLL, false},
      { 0x0000000000000001ULL, 0x00000000ffffffffLL, false},
      { 0x0000000000000002ULL, 0x00000000ffffffffLL, false},
      { 0x000000007ffffffeULL, 0x00000000ffffffffLL, false},
      { 0x000000007fffffffULL, 0x00000000ffffffffLL, false},
      { 0x0000000080000000ULL, 0x00000000ffffffffLL, false},
      { 0x0000000080000001ULL, 0x00000000ffffffffLL, false},
      { 0x00000000fffffffeULL, 0x00000000ffffffffLL, false},
      { 0x00000000ffffffffULL, 0x00000000ffffffffLL, true},
      { 0x0000000100000000ULL, 0x00000000ffffffffLL, true},
      { 0x0000000200000000ULL, 0x00000000ffffffffLL, true},
      { 0x7ffffffffffffffeULL, 0x00000000ffffffffLL, true},
      { 0x7fffffffffffffffULL, 0x00000000ffffffffLL, true},
      { 0x8000000000000000ULL, 0x00000000ffffffffLL, true},
      { 0x8000000000000001ULL, 0x00000000ffffffffLL, true},
      { 0xfffffffffffffffeULL, 0x00000000ffffffffLL, true},
      { 0xffffffffffffffffULL, 0x00000000ffffffffLL, true},

      { 0x0000000000000000ULL, 0x0000000100000000LL, false},
      { 0x0000000000000001ULL, 0x0000000100000000LL, false},
      { 0x0000000000000002ULL, 0x0000000100000000LL, false},
      { 0x000000007ffffffeULL, 0x0000000100000000LL, false},
      { 0x000000007fffffffULL, 0x0000000100000000LL, false},
      { 0x0000000080000000ULL, 0x0000000100000000LL, false},
      { 0x0000000080000001ULL, 0x0000000100000000LL, false},
      { 0x00000000fffffffeULL, 0x0000000100000000LL, false},
      { 0x00000000ffffffffULL, 0x0000000100000000LL, false},
      { 0x0000000100000000ULL, 0x0000000100000000LL, true},
      { 0x0000000200000000ULL, 0x0000000100000000LL, true},
      { 0x7ffffffffffffffeULL, 0x0000000100000000LL, true},
      { 0x7fffffffffffffffULL, 0x0000000100000000LL, true},
      { 0x8000000000000000ULL, 0x0000000100000000LL, true},
      { 0x8000000000000001ULL, 0x0000000100000000LL, true},
      { 0xfffffffffffffffeULL, 0x0000000100000000LL, true},
      { 0xffffffffffffffffULL, 0x0000000100000000LL, true},

      { 0x0000000000000000ULL, 0x0000000200000000LL, false},
      { 0x0000000000000001ULL, 0x0000000200000000LL, false},
      { 0x0000000000000002ULL, 0x0000000200000000LL, false},
      { 0x000000007ffffffeULL, 0x0000000200000000LL, false},
      { 0x000000007fffffffULL, 0x0000000200000000LL, false},
      { 0x0000000080000000ULL, 0x0000000200000000LL, false},
      { 0x0000000080000001ULL, 0x0000000200000000LL, false},
      { 0x00000000fffffffeULL, 0x0000000200000000LL, false},
      { 0x00000000ffffffffULL, 0x0000000200000000LL, false},
      { 0x0000000100000000ULL, 0x0000000200000000LL, false},
      { 0x0000000200000000ULL, 0x0000000200000000LL, true},
      { 0x7ffffffffffffffeULL, 0x0000000200000000LL, true},
      { 0x7fffffffffffffffULL, 0x0000000200000000LL, true},
      { 0x8000000000000000ULL, 0x0000000200000000LL, true},
      { 0x8000000000000001ULL, 0x0000000200000000LL, true},
      { 0xfffffffffffffffeULL, 0x0000000200000000LL, true},
      { 0xffffffffffffffffULL, 0x0000000200000000LL, true},

      { 0x0000000000000000ULL, 0x7ffffffffffffffeLL, false},
      { 0x0000000000000001ULL, 0x7ffffffffffffffeLL, false},
      { 0x0000000000000002ULL, 0x7ffffffffffffffeLL, false},
      { 0x000000007ffffffeULL, 0x7ffffffffffffffeLL, false},
      { 0x000000007fffffffULL, 0x7ffffffffffffffeLL, false},
      { 0x0000000080000000ULL, 0x7ffffffffffffffeLL, false},
      { 0x0000000080000001ULL, 0x7ffffffffffffffeLL, false},
      { 0x00000000fffffffeULL, 0x7ffffffffffffffeLL, false},
      { 0x00000000ffffffffULL, 0x7ffffffffffffffeLL, false},
      { 0x0000000100000000ULL, 0x7ffffffffffffffeLL, false},
      { 0x0000000200000000ULL, 0x7ffffffffffffffeLL, false},
      { 0x7ffffffffffffffeULL, 0x7ffffffffffffffeLL, true},
      { 0x7fffffffffffffffULL, 0x7ffffffffffffffeLL, true},
      { 0x8000000000000000ULL, 0x7ffffffffffffffeLL, true},
      { 0x8000000000000001ULL, 0x7ffffffffffffffeLL, true},
      { 0xfffffffffffffffeULL, 0x7ffffffffffffffeLL, true},
      { 0xffffffffffffffffULL, 0x7ffffffffffffffeLL, true},

      { 0x0000000000000000ULL, 0x7fffffffffffffffLL, false},
      { 0x0000000000000001ULL, 0x7fffffffffffffffLL, false},
      { 0x0000000000000002ULL, 0x7fffffffffffffffLL, false},
      { 0x000000007ffffffeULL, 0x7fffffffffffffffLL, false},
      { 0x000000007fffffffULL, 0x7fffffffffffffffLL, false},
      { 0x0000000080000000ULL, 0x7fffffffffffffffLL, false},
      { 0x0000000080000001ULL, 0x7fffffffffffffffLL, false},
      { 0x00000000fffffffeULL, 0x7fffffffffffffffLL, false},
      { 0x00000000ffffffffULL, 0x7fffffffffffffffLL, false},
      { 0x0000000100000000ULL, 0x7fffffffffffffffLL, false},
      { 0x0000000200000000ULL, 0x7fffffffffffffffLL, false},
      { 0x7ffffffffffffffeULL, 0x7fffffffffffffffLL, false},
      { 0x7fffffffffffffffULL, 0x7fffffffffffffffLL, true},
      { 0x8000000000000000ULL, 0x7fffffffffffffffLL, true},
      { 0x8000000000000001ULL, 0x7fffffffffffffffLL, true},
      { 0xfffffffffffffffeULL, 0x7fffffffffffffffLL, true},
      { 0xffffffffffffffffULL, 0x7fffffffffffffffLL, true},

      { 0x0000000000000000ULL, 0x8000000000000000LL, true},
      { 0x0000000000000001ULL, 0x8000000000000000LL, true},
      { 0x0000000000000002ULL, 0x8000000000000000LL, true},
      { 0x000000007ffffffeULL, 0x8000000000000000LL, true},
      { 0x000000007fffffffULL, 0x8000000000000000LL, true},
      { 0x0000000080000000ULL, 0x8000000000000000LL, true},
      { 0x0000000080000001ULL, 0x8000000000000000LL, true},
      { 0x00000000fffffffeULL, 0x8000000000000000LL, true},
      { 0x00000000ffffffffULL, 0x8000000000000000LL, true},
      { 0x0000000100000000ULL, 0x8000000000000000LL, true},
      { 0x0000000200000000ULL, 0x8000000000000000LL, true},
      { 0x7ffffffffffffffeULL, 0x8000000000000000LL, true},
      { 0x7fffffffffffffffULL, 0x8000000000000000LL, true},
      { 0x8000000000000000ULL, 0x8000000000000000LL, false},
      { 0x8000000000000001ULL, 0x8000000000000000LL, false},
      { 0xfffffffffffffffeULL, 0x8000000000000000LL, false},
      { 0xffffffffffffffffULL, 0x8000000000000000LL, false},

      { 0x0000000000000000ULL, 0x8000000000000001LL, true},
      { 0x0000000000000001ULL, 0x8000000000000001LL, true},
      { 0x0000000000000002ULL, 0x8000000000000001LL, true},
      { 0x000000007ffffffeULL, 0x8000000000000001LL, true},
      { 0x000000007fffffffULL, 0x8000000000000001LL, true},
      { 0x0000000080000000ULL, 0x8000000000000001LL, true},
      { 0x0000000080000001ULL, 0x8000000000000001LL, true},
      { 0x00000000fffffffeULL, 0x8000000000000001LL, true},
      { 0x00000000ffffffffULL, 0x8000000000000001LL, true},
      { 0x0000000100000000ULL, 0x8000000000000001LL, true},
      { 0x0000000200000000ULL, 0x8000000000000001LL, true},
      { 0x7ffffffffffffffeULL, 0x8000000000000001LL, true},
      { 0x7fffffffffffffffULL, 0x8000000000000001LL, true},
      { 0x8000000000000000ULL, 0x8000000000000001LL, true},
      { 0x8000000000000001ULL, 0x8000000000000001LL, false},
      { 0xfffffffffffffffeULL, 0x8000000000000001LL, false},
      { 0xffffffffffffffffULL, 0x8000000000000001LL, false},

      { 0x0000000000000000ULL, 0xfffffffffffffffeLL, true},
      { 0x0000000000000001ULL, 0xfffffffffffffffeLL, true},
      { 0x0000000000000002ULL, 0xfffffffffffffffeLL, true},
      { 0x000000007ffffffeULL, 0xfffffffffffffffeLL, true},
      { 0x000000007fffffffULL, 0xfffffffffffffffeLL, true},
      { 0x0000000080000000ULL, 0xfffffffffffffffeLL, true},
      { 0x0000000080000001ULL, 0xfffffffffffffffeLL, true},
      { 0x00000000fffffffeULL, 0xfffffffffffffffeLL, true},
      { 0x00000000ffffffffULL, 0xfffffffffffffffeLL, true},
      { 0x0000000100000000ULL, 0xfffffffffffffffeLL, true},
      { 0x0000000200000000ULL, 0xfffffffffffffffeLL, true},
      { 0x7ffffffffffffffeULL, 0xfffffffffffffffeLL, true},
      { 0x7fffffffffffffffULL, 0xfffffffffffffffeLL, true},
      { 0x8000000000000000ULL, 0xfffffffffffffffeLL, true},
      { 0x8000000000000001ULL, 0xfffffffffffffffeLL, true},
      { 0xfffffffffffffffeULL, 0xfffffffffffffffeLL, false},
      { 0xffffffffffffffffULL, 0xfffffffffffffffeLL, false},

      { 0x0000000000000000ULL, 0xffffffffffffffffLL, true},
      { 0x0000000000000001ULL, 0xffffffffffffffffLL, true},
      { 0x0000000000000002ULL, 0xffffffffffffffffLL, true},
      { 0x000000007ffffffeULL, 0xffffffffffffffffLL, true},
      { 0x000000007fffffffULL, 0xffffffffffffffffLL, true},
      { 0x0000000080000000ULL, 0xffffffffffffffffLL, true},
      { 0x0000000080000001ULL, 0xffffffffffffffffLL, true},
      { 0x00000000fffffffeULL, 0xffffffffffffffffLL, true},
      { 0x00000000ffffffffULL, 0xffffffffffffffffLL, true},
      { 0x0000000100000000ULL, 0xffffffffffffffffLL, true},
      { 0x0000000200000000ULL, 0xffffffffffffffffLL, true},
      { 0x7ffffffffffffffeULL, 0xffffffffffffffffLL, true},
      { 0x7fffffffffffffffULL, 0xffffffffffffffffLL, true},
      { 0x8000000000000000ULL, 0xffffffffffffffffLL, true},
      { 0x8000000000000001ULL, 0xffffffffffffffffLL, true},
      { 0xfffffffffffffffeULL, 0xffffffffffffffffLL, true},
      { 0xffffffffffffffffULL, 0xffffffffffffffffLL, false},
    };

  void SubVerifyUint64Int64()
  {
    size_t i;

    for( i = 0; i < COUNTOF(uint64_int64); ++i )
      {
        unsigned __int64 ret;
        if( SafeSubtract(uint64_int64[i].x, uint64_int64[i].y, ret) != uint64_int64[i].fExpected )
          {
            cerr << "Error in case uint64_int64: ";
            cerr << hex << setw(16) << setfill('0') << uint64_int64[i].x << ", ";
            cerr << hex << setw(16) << setfill('0') << uint64_int64[i].y << ", ";
            cerr << "expected = " << uint64_int64[i].fExpected << endl;
          }

        // Now test throwing version
        bool fSuccess = true;
        try
          {
            SafeInt<unsigned __int64> si(uint64_int64[i].x);
            si -= (__int64)uint64_int64[i].y;
          }
        catch(...)
          {
            fSuccess = false;
          }

        if( fSuccess != uint64_int64[i].fExpected )
          {
            cerr << "Error in case uint64_int64 throw (1): ";
            cerr << hex << setw(16) << setfill('0') << uint64_int64[i].x << ", ";
            cerr << hex << setw(16) << setfill('0') << uint64_int64[i].y << ", ";
            cerr << "expected = " << uint64_int64[i].fExpected << endl;
          }

        // Also need to test the version that assigns back out
        // to a plain int, as it has different logic
        fSuccess = true;
        try
          {
            unsigned __int64 x(uint64_int64[i].x);
            x -= SafeInt<__int64>(uint64_int64[i].y);
          }
        catch(...)
          {
            fSuccess = false;
          }

        if( fSuccess != uint64_int64[i].fExpected )
          {
            cerr << "Error in case uint64_int64 throw (2): ";
            cerr << hex << setw(16) << setfill('0') << uint64_int64[i].x << ", ";
            cerr << hex << setw(16) << setfill('0') << uint64_int64[i].y << ", ";
            cerr << "expected = " << uint64_int64[i].fExpected << endl;
          }
      }
  }

  static const SubTest< unsigned __int64, __int32 > uint64_int32[] =
    {
      { 0x0000000000000000ULL, 0x00000000, true},
      { 0x0000000000000001ULL, 0x00000000, true},
      { 0x0000000000000002ULL, 0x00000000, true},
      { 0x000000007ffffffeULL, 0x00000000, true},
      { 0x000000007fffffffULL, 0x00000000, true},
      { 0x0000000080000000ULL, 0x00000000, true},
      { 0x0000000080000001ULL, 0x00000000, true},
      { 0x00000000fffffffeULL, 0x00000000, true},
      { 0x00000000ffffffffULL, 0x00000000, true},
      { 0x0000000100000000ULL, 0x00000000, true},
      { 0x0000000200000000ULL, 0x00000000, true},
      { 0x7ffffffffffffffeULL, 0x00000000, true},
      { 0x7fffffffffffffffULL, 0x00000000, true},
      { 0x8000000000000000ULL, 0x00000000, true},
      { 0x8000000000000001ULL, 0x00000000, true},
      { 0xfffffffffffffffeULL, 0x00000000, true},
      { 0xffffffffffffffffULL, 0x00000000, true},

      { 0x0000000000000000ULL, 0x00000001, false},
      { 0x0000000000000001ULL, 0x00000001, true},
      { 0x0000000000000002ULL, 0x00000001, true},
      { 0x000000007ffffffeULL, 0x00000001, true},
      { 0x000000007fffffffULL, 0x00000001, true},
      { 0x0000000080000000ULL, 0x00000001, true},
      { 0x0000000080000001ULL, 0x00000001, true},
      { 0x00000000fffffffeULL, 0x00000001, true},
      { 0x00000000ffffffffULL, 0x00000001, true},
      { 0x0000000100000000ULL, 0x00000001, true},
      { 0x0000000200000000ULL, 0x00000001, true},
      { 0x7ffffffffffffffeULL, 0x00000001, true},
      { 0x7fffffffffffffffULL, 0x00000001, true},
      { 0x8000000000000000ULL, 0x00000001, true},
      { 0x8000000000000001ULL, 0x00000001, true},
      { 0xfffffffffffffffeULL, 0x00000001, true},
      { 0xffffffffffffffffULL, 0x00000001, true},

      { 0x0000000000000000ULL, 0x00000002, false},
      { 0x0000000000000001ULL, 0x00000002, false},
      { 0x0000000000000002ULL, 0x00000002, true},
      { 0x000000007ffffffeULL, 0x00000002, true},
      { 0x000000007fffffffULL, 0x00000002, true},
      { 0x0000000080000000ULL, 0x00000002, true},
      { 0x0000000080000001ULL, 0x00000002, true},
      { 0x00000000fffffffeULL, 0x00000002, true},
      { 0x00000000ffffffffULL, 0x00000002, true},
      { 0x0000000100000000ULL, 0x00000002, true},
      { 0x0000000200000000ULL, 0x00000002, true},
      { 0x7ffffffffffffffeULL, 0x00000002, true},
      { 0x7fffffffffffffffULL, 0x00000002, true},
      { 0x8000000000000000ULL, 0x00000002, true},
      { 0x8000000000000001ULL, 0x00000002, true},
      { 0xfffffffffffffffeULL, 0x00000002, true},
      { 0xffffffffffffffffULL, 0x00000002, true},

      { 0x0000000000000000ULL, 0x7ffffffe, false},
      { 0x0000000000000001ULL, 0x7ffffffe, false},
      { 0x0000000000000002ULL, 0x7ffffffe, false},
      { 0x000000007ffffffeULL, 0x7ffffffe, true},
      { 0x000000007fffffffULL, 0x7ffffffe, true},
      { 0x0000000080000000ULL, 0x7ffffffe, true},
      { 0x0000000080000001ULL, 0x7ffffffe, true},
      { 0x00000000fffffffeULL, 0x7ffffffe, true},
      { 0x00000000ffffffffULL, 0x7ffffffe, true},
      { 0x0000000100000000ULL, 0x7ffffffe, true},
      { 0x0000000200000000ULL, 0x7ffffffe, true},
      { 0x7ffffffffffffffeULL, 0x7ffffffe, true},
      { 0x7fffffffffffffffULL, 0x7ffffffe, true},
      { 0x8000000000000000ULL, 0x7ffffffe, true},
      { 0x8000000000000001ULL, 0x7ffffffe, true},
      { 0xfffffffffffffffeULL, 0x7ffffffe, true},
      { 0xffffffffffffffffULL, 0x7ffffffe, true},

      { 0x0000000000000000ULL, 0x7fffffff, false},
      { 0x0000000000000001ULL, 0x7fffffff, false},
      { 0x0000000000000002ULL, 0x7fffffff, false},
      { 0x000000007ffffffeULL, 0x7fffffff, false},
      { 0x000000007fffffffULL, 0x7fffffff, true},
      { 0x0000000080000000ULL, 0x7fffffff, true},
      { 0x0000000080000001ULL, 0x7fffffff, true},
      { 0x00000000fffffffeULL, 0x7fffffff, true},
      { 0x00000000ffffffffULL, 0x7fffffff, true},
      { 0x0000000100000000ULL, 0x7fffffff, true},
      { 0x0000000200000000ULL, 0x7fffffff, true},
      { 0x7ffffffffffffffeULL, 0x7fffffff, true},
      { 0x7fffffffffffffffULL, 0x7fffffff, true},
      { 0x8000000000000000ULL, 0x7fffffff, true},
      { 0x8000000000000001ULL, 0x7fffffff, true},
      { 0xfffffffffffffffeULL, 0x7fffffff, true},
      { 0xffffffffffffffffULL, 0x7fffffff, true},

      { 0x0000000000000000ULL, 0x80000000, true},
      { 0x0000000000000001ULL, 0x80000000, true},
      { 0x0000000000000002ULL, 0x80000000, true},
      { 0x000000007ffffffeULL, 0x80000000, true},
      { 0x000000007fffffffULL, 0x80000000, true},
      { 0x0000000080000000ULL, 0x80000000, true},
      { 0x0000000080000001ULL, 0x80000000, true},
      { 0x00000000fffffffeULL, 0x80000000, true},
      { 0x00000000ffffffffULL, 0x80000000, true},
      { 0x0000000100000000ULL, 0x80000000, true},
      { 0x0000000200000000ULL, 0x80000000, true},
      { 0x7ffffffffffffffeULL, 0x80000000, true},
      { 0x7fffffffffffffffULL, 0x80000000, true},
      { 0x8000000000000000ULL, 0x80000000, true},
      { 0x8000000000000001ULL, 0x80000000, true},
      { 0xfffffffffffffffeULL, 0x80000000, false},
      { 0xffffffffffffffffULL, 0x80000000, false},

      { 0x0000000000000000ULL, 0x80000001, true},
      { 0x0000000000000001ULL, 0x80000001, true},
      { 0x0000000000000002ULL, 0x80000001, true},
      { 0x000000007ffffffeULL, 0x80000001, true},
      { 0x000000007fffffffULL, 0x80000001, true},
      { 0x0000000080000000ULL, 0x80000001, true},
      { 0x0000000080000001ULL, 0x80000001, true},
      { 0x00000000fffffffeULL, 0x80000001, true},
      { 0x00000000ffffffffULL, 0x80000001, true},
      { 0x0000000100000000ULL, 0x80000001, true},
      { 0x0000000200000000ULL, 0x80000001, true},
      { 0x7ffffffffffffffeULL, 0x80000001, true},
      { 0x7fffffffffffffffULL, 0x80000001, true},
      { 0x8000000000000000ULL, 0x80000001, true},
      { 0x8000000000000001ULL, 0x80000001, true},
      { 0xfffffffffffffffeULL, 0x80000001, false},
      { 0xffffffffffffffffULL, 0x80000001, false},

      { 0x0000000000000000ULL, 0xfffffffe, true},
      { 0x0000000000000001ULL, 0xfffffffe, true},
      { 0x0000000000000002ULL, 0xfffffffe, true},
      { 0x000000007ffffffeULL, 0xfffffffe, true},
      { 0x000000007fffffffULL, 0xfffffffe, true},
      { 0x0000000080000000ULL, 0xfffffffe, true},
      { 0x0000000080000001ULL, 0xfffffffe, true},
      { 0x00000000fffffffeULL, 0xfffffffe, true},
      { 0x00000000ffffffffULL, 0xfffffffe, true},
      { 0x0000000100000000ULL, 0xfffffffe, true},
      { 0x0000000200000000ULL, 0xfffffffe, true},
      { 0x7ffffffffffffffeULL, 0xfffffffe, true},
      { 0x7fffffffffffffffULL, 0xfffffffe, true},
      { 0x8000000000000000ULL, 0xfffffffe, true},
      { 0x8000000000000001ULL, 0xfffffffe, true},
      { 0xfffffffffffffffeULL, 0xfffffffe, false},
      { 0xffffffffffffffffULL, 0xfffffffe, false},

      { 0x0000000000000000ULL, 0xffffffff, true},
      { 0x0000000000000001ULL, 0xffffffff, true},
      { 0x0000000000000002ULL, 0xffffffff, true},
      { 0x000000007ffffffeULL, 0xffffffff, true},
      { 0x000000007fffffffULL, 0xffffffff, true},
      { 0x0000000080000000ULL, 0xffffffff, true},
      { 0x0000000080000001ULL, 0xffffffff, true},
      { 0x00000000fffffffeULL, 0xffffffff, true},
      { 0x00000000ffffffffULL, 0xffffffff, true},
      { 0x0000000100000000ULL, 0xffffffff, true},
      { 0x0000000200000000ULL, 0xffffffff, true},
      { 0x7ffffffffffffffeULL, 0xffffffff, true},
      { 0x7fffffffffffffffULL, 0xffffffff, true},
      { 0x8000000000000000ULL, 0xffffffff, true},
      { 0x8000000000000001ULL, 0xffffffff, true},
      { 0xfffffffffffffffeULL, 0xffffffff, true},
      { 0xffffffffffffffffULL, 0xffffffff, false},
    };

  void SubVerifyUint64Int32()
  {
    size_t i;

    for( i = 0; i < COUNTOF(uint64_int32); ++i )
      {
        unsigned __int64 ret;
        if( SafeSubtract(uint64_int32[i].x, uint64_int32[i].y, ret) != uint64_int32[i].fExpected )
          {
            cerr << "Error in case uint64_int32: ";
            cerr << hex << setw(16) << setfill('0') << uint64_int32[i].x << ", ";
            cerr << hex << setw(8) << setfill('0') << uint64_int32[i].y << ", ";
            cerr << "expected = " << uint64_int32[i].fExpected << endl;
          }

        // Now test throwing version
        bool fSuccess = true;
        try
          {
            SafeInt<unsigned __int64> si(uint64_int32[i].x);
            si -= (__int32)uint64_int32[i].y;
          }
        catch(...)
          {
            fSuccess = false;
          }

        if( fSuccess != uint64_int32[i].fExpected )
          {
            cerr << "Error in case uint64_int32 throw (1): ";
            cerr << hex << setw(16) << setfill('0') << uint64_int32[i].x << ", ";
            cerr << hex << setw(8) << setfill('0') << uint64_int32[i].y << ", ";
            cerr << "expected = " << uint64_int32[i].fExpected << endl;
          }

        // Also need to test the version that assigns back out
        // to a plain int, as it has different logic
        fSuccess = true;
        try
          {
            unsigned __int64 x(uint64_int32[i].x);
            x -= SafeInt<__int32>(uint64_int32[i].y);
          }
        catch(...)
          {
            fSuccess = false;
          }

        if( fSuccess != uint64_int32[i].fExpected )
          {
            cerr << "Error in case uint64_int32 throw (2): ";
            cerr << hex << setw(16) << setfill('0') << uint64_int32[i].x << ", ";
            cerr << hex << setw(8) << setfill('0') << uint64_int32[i].y << ", ";
            cerr << "expected = " << uint64_int32[i].fExpected << endl;
          }
      }
  }

  static const SubTest< unsigned __int64, __int16 > uint64_int16[] =
    {
      { 0x0000000000000000ULL, 0x0000, true},
      { 0x0000000000000001ULL, 0x0000, true},
      { 0x0000000000000002ULL, 0x0000, true},
      { 0x000000007ffffffeULL, 0x0000, true},
      { 0x000000007fffffffULL, 0x0000, true},
      { 0x0000000080000000ULL, 0x0000, true},
      { 0x0000000080000001ULL, 0x0000, true},
      { 0x00000000fffffffeULL, 0x0000, true},
      { 0x00000000ffffffffULL, 0x0000, true},
      { 0x0000000100000000ULL, 0x0000, true},
      { 0x0000000200000000ULL, 0x0000, true},
      { 0x7ffffffffffffffeULL, 0x0000, true},
      { 0x7fffffffffffffffULL, 0x0000, true},
      { 0x8000000000000000ULL, 0x0000, true},
      { 0x8000000000000001ULL, 0x0000, true},
      { 0xfffffffffffffffeULL, 0x0000, true},
      { 0xffffffffffffffffULL, 0x0000, true},

      { 0x0000000000000000ULL, 0x0001, false},
      { 0x0000000000000001ULL, 0x0001, true},
      { 0x0000000000000002ULL, 0x0001, true},
      { 0x000000007ffffffeULL, 0x0001, true},
      { 0x000000007fffffffULL, 0x0001, true},
      { 0x0000000080000000ULL, 0x0001, true},
      { 0x0000000080000001ULL, 0x0001, true},
      { 0x00000000fffffffeULL, 0x0001, true},
      { 0x00000000ffffffffULL, 0x0001, true},
      { 0x0000000100000000ULL, 0x0001, true},
      { 0x0000000200000000ULL, 0x0001, true},
      { 0x7ffffffffffffffeULL, 0x0001, true},
      { 0x7fffffffffffffffULL, 0x0001, true},
      { 0x8000000000000000ULL, 0x0001, true},
      { 0x8000000000000001ULL, 0x0001, true},
      { 0xfffffffffffffffeULL, 0x0001, true},
      { 0xffffffffffffffffULL, 0x0001, true},

      { 0x0000000000000000ULL, 0x0002, false},
      { 0x0000000000000001ULL, 0x0002, false},
      { 0x0000000000000002ULL, 0x0002, true},
      { 0x000000007ffffffeULL, 0x0002, true},
      { 0x000000007fffffffULL, 0x0002, true},
      { 0x0000000080000000ULL, 0x0002, true},
      { 0x0000000080000001ULL, 0x0002, true},
      { 0x00000000fffffffeULL, 0x0002, true},
      { 0x00000000ffffffffULL, 0x0002, true},
      { 0x0000000100000000ULL, 0x0002, true},
      { 0x0000000200000000ULL, 0x0002, true},
      { 0x7ffffffffffffffeULL, 0x0002, true},
      { 0x7fffffffffffffffULL, 0x0002, true},
      { 0x8000000000000000ULL, 0x0002, true},
      { 0x8000000000000001ULL, 0x0002, true},
      { 0xfffffffffffffffeULL, 0x0002, true},
      { 0xffffffffffffffffULL, 0x0002, true},

      { 0x0000000000000000ULL, 0x7ffe, false},
      { 0x0000000000000001ULL, 0x7ffe, false},
      { 0x0000000000000002ULL, 0x7ffe, false},
      { 0x000000007ffffffeULL, 0x7ffe, true},
      { 0x000000007fffffffULL, 0x7ffe, true},
      { 0x0000000080000000ULL, 0x7ffe, true},
      { 0x0000000080000001ULL, 0x7ffe, true},
      { 0x00000000fffffffeULL, 0x7ffe, true},
      { 0x00000000ffffffffULL, 0x7ffe, true},
      { 0x0000000100000000ULL, 0x7ffe, true},
      { 0x0000000200000000ULL, 0x7ffe, true},
      { 0x7ffffffffffffffeULL, 0x7ffe, true},
      { 0x7fffffffffffffffULL, 0x7ffe, true},
      { 0x8000000000000000ULL, 0x7ffe, true},
      { 0x8000000000000001ULL, 0x7ffe, true},
      { 0xfffffffffffffffeULL, 0x7ffe, true},
      { 0xffffffffffffffffULL, 0x7ffe, true},

      { 0x0000000000000000ULL, 0x7fff, false},
      { 0x0000000000000001ULL, 0x7fff, false},
      { 0x0000000000000002ULL, 0x7fff, false},
      { 0x000000007ffffffeULL, 0x7fff, true},
      { 0x000000007fffffffULL, 0x7fff, true},
      { 0x0000000080000000ULL, 0x7fff, true},
      { 0x0000000080000001ULL, 0x7fff, true},
      { 0x00000000fffffffeULL, 0x7fff, true},
      { 0x00000000ffffffffULL, 0x7fff, true},
      { 0x0000000100000000ULL, 0x7fff, true},
      { 0x0000000200000000ULL, 0x7fff, true},
      { 0x7ffffffffffffffeULL, 0x7fff, true},
      { 0x7fffffffffffffffULL, 0x7fff, true},
      { 0x8000000000000000ULL, 0x7fff, true},
      { 0x8000000000000001ULL, 0x7fff, true},
      { 0xfffffffffffffffeULL, 0x7fff, true},
      { 0xffffffffffffffffULL, 0x7fff, true},

      { 0x0000000000000000ULL, 0x8000, true},
      { 0x0000000000000001ULL, 0x8000, true},
      { 0x0000000000000002ULL, 0x8000, true},
      { 0x000000007ffffffeULL, 0x8000, true},
      { 0x000000007fffffffULL, 0x8000, true},
      { 0x0000000080000000ULL, 0x8000, true},
      { 0x0000000080000001ULL, 0x8000, true},
      { 0x00000000fffffffeULL, 0x8000, true},
      { 0x00000000ffffffffULL, 0x8000, true},
      { 0x0000000100000000ULL, 0x8000, true},
      { 0x0000000200000000ULL, 0x8000, true},
      { 0x7ffffffffffffffeULL, 0x8000, true},
      { 0x7fffffffffffffffULL, 0x8000, true},
      { 0x8000000000000000ULL, 0x8000, true},
      { 0x8000000000000001ULL, 0x8000, true},
      { 0xfffffffffffffffeULL, 0x8000, false},
      { 0xffffffffffffffffULL, 0x8000, false},

      { 0x0000000000000000ULL, 0x8001, true},
      { 0x0000000000000001ULL, 0x8001, true},
      { 0x0000000000000002ULL, 0x8001, true},
      { 0x000000007ffffffeULL, 0x8001, true},
      { 0x000000007fffffffULL, 0x8001, true},
      { 0x0000000080000000ULL, 0x8001, true},
      { 0x0000000080000001ULL, 0x8001, true},
      { 0x00000000fffffffeULL, 0x8001, true},
      { 0x00000000ffffffffULL, 0x8001, true},
      { 0x0000000100000000ULL, 0x8001, true},
      { 0x0000000200000000ULL, 0x8001, true},
      { 0x7ffffffffffffffeULL, 0x8001, true},
      { 0x7fffffffffffffffULL, 0x8001, true},
      { 0x8000000000000000ULL, 0x8001, true},
      { 0x8000000000000001ULL, 0x8001, true},
      { 0xfffffffffffffffeULL, 0x8001, false},
      { 0xffffffffffffffffULL, 0x8001, false},

      { 0x0000000000000000ULL, 0xfffe, true},
      { 0x0000000000000001ULL, 0xfffe, true},
      { 0x0000000000000002ULL, 0xfffe, true},
      { 0x000000007ffffffeULL, 0xfffe, true},
      { 0x000000007fffffffULL, 0xfffe, true},
      { 0x0000000080000000ULL, 0xfffe, true},
      { 0x0000000080000001ULL, 0xfffe, true},
      { 0x00000000fffffffeULL, 0xfffe, true},
      { 0x00000000ffffffffULL, 0xfffe, true},
      { 0x0000000100000000ULL, 0xfffe, true},
      { 0x0000000200000000ULL, 0xfffe, true},
      { 0x7ffffffffffffffeULL, 0xfffe, true},
      { 0x7fffffffffffffffULL, 0xfffe, true},
      { 0x8000000000000000ULL, 0xfffe, true},
      { 0x8000000000000001ULL, 0xfffe, true},
      { 0xfffffffffffffffeULL, 0xfffe, false},
      { 0xffffffffffffffffULL, 0xfffe, false},

      { 0x0000000000000000ULL, 0xffff, true},
      { 0x0000000000000001ULL, 0xffff, true},
      { 0x0000000000000002ULL, 0xffff, true},
      { 0x000000007ffffffeULL, 0xffff, true},
      { 0x000000007fffffffULL, 0xffff, true},
      { 0x0000000080000000ULL, 0xffff, true},
      { 0x0000000080000001ULL, 0xffff, true},
      { 0x00000000fffffffeULL, 0xffff, true},
      { 0x00000000ffffffffULL, 0xffff, true},
      { 0x0000000100000000ULL, 0xffff, true},
      { 0x0000000200000000ULL, 0xffff, true},
      { 0x7ffffffffffffffeULL, 0xffff, true},
      { 0x7fffffffffffffffULL, 0xffff, true},
      { 0x8000000000000000ULL, 0xffff, true},
      { 0x8000000000000001ULL, 0xffff, true},
      { 0xfffffffffffffffeULL, 0xffff, true},
      { 0xffffffffffffffffULL, 0xffff, false},
    };

  void SubVerifyUint64Int16()
  {
    size_t i;

    for( i = 0; i < COUNTOF(uint64_int16); ++i )
      {
        unsigned __int64 ret;
        if( SafeSubtract(uint64_int16[i].x, uint64_int16[i].y, ret) != uint64_int16[i].fExpected )
          {
            cerr << "Error in case uint64_int16: ";
            cerr << hex << setw(16) << setfill('0') << uint64_int16[i].x << ", ";
            cerr << hex << setw(4) << setfill('0') << uint64_int16[i].y << ", ";
            cerr << "expected = " << uint64_int16[i].fExpected << endl;
          }

        // Now test throwing version
        bool fSuccess = true;
        try
          {
            SafeInt<unsigned __int64> si(uint64_int16[i].x);
            si -= (__int16)uint64_int16[i].y;
          }
        catch(...)
          {
            fSuccess = false;
          }

        if( fSuccess != uint64_int16[i].fExpected )
          {
            cerr << "Error in case uint64_int16 throw (1): ";
            cerr << hex << setw(16) << setfill('0') << uint64_int16[i].x << ", ";
            cerr << hex << setw(4) << setfill('0') << uint64_int16[i].y << ", ";
            cerr << "expected = " << uint64_int16[i].fExpected << endl;
          }

        // Also need to test the version that assigns back out
        // to a plain int, as it has different logic
        fSuccess = true;
        try
          {
            unsigned __int64 x(uint64_int16[i].x);
            x -= SafeInt<__int16>(uint64_int16[i].y);
          }
        catch(...)
          {
            fSuccess = false;
          }

        if( fSuccess != uint64_int16[i].fExpected )
          {
            cerr << "Error in case uint64_int16 throw (2): ";
            cerr << hex << setw(16) << setfill('0') << uint64_int16[i].x << ", ";
            cerr << hex << setw(4) << setfill('0') << uint64_int16[i].y << ", ";
            cerr << "expected = " << uint64_int16[i].fExpected << endl;
          }
      }
  }

  static const SubTest< unsigned __int64, __int8 > uint64_int8[] =
    {
      { 0x0000000000000000ULL, 0x00, true},
      { 0x0000000000000001ULL, 0x00, true},
      { 0x0000000000000002ULL, 0x00, true},
      { 0x000000007ffffffeULL, 0x00, true},
      { 0x000000007fffffffULL, 0x00, true},
      { 0x0000000080000000ULL, 0x00, true},
      { 0x0000000080000001ULL, 0x00, true},
      { 0x00000000fffffffeULL, 0x00, true},
      { 0x00000000ffffffffULL, 0x00, true},
      { 0x0000000100000000ULL, 0x00, true},
      { 0x0000000200000000ULL, 0x00, true},
      { 0x7ffffffffffffffeULL, 0x00, true},
      { 0x7fffffffffffffffULL, 0x00, true},
      { 0x8000000000000000ULL, 0x00, true},
      { 0x8000000000000001ULL, 0x00, true},
      { 0xfffffffffffffffeULL, 0x00, true},
      { 0xffffffffffffffffULL, 0x00, true},

      { 0x0000000000000000ULL, 0x01, false},
      { 0x0000000000000001ULL, 0x01, true},
      { 0x0000000000000002ULL, 0x01, true},
      { 0x000000007ffffffeULL, 0x01, true},
      { 0x000000007fffffffULL, 0x01, true},
      { 0x0000000080000000ULL, 0x01, true},
      { 0x0000000080000001ULL, 0x01, true},
      { 0x00000000fffffffeULL, 0x01, true},
      { 0x00000000ffffffffULL, 0x01, true},
      { 0x0000000100000000ULL, 0x01, true},
      { 0x0000000200000000ULL, 0x01, true},
      { 0x7ffffffffffffffeULL, 0x01, true},
      { 0x7fffffffffffffffULL, 0x01, true},
      { 0x8000000000000000ULL, 0x01, true},
      { 0x8000000000000001ULL, 0x01, true},
      { 0xfffffffffffffffeULL, 0x01, true},
      { 0xffffffffffffffffULL, 0x01, true},

      { 0x0000000000000000ULL, 0x02, false},
      { 0x0000000000000001ULL, 0x02, false},
      { 0x0000000000000002ULL, 0x02, true},
      { 0x000000007ffffffeULL, 0x02, true},
      { 0x000000007fffffffULL, 0x02, true},
      { 0x0000000080000000ULL, 0x02, true},
      { 0x0000000080000001ULL, 0x02, true},
      { 0x00000000fffffffeULL, 0x02, true},
      { 0x00000000ffffffffULL, 0x02, true},
      { 0x0000000100000000ULL, 0x02, true},
      { 0x0000000200000000ULL, 0x02, true},
      { 0x7ffffffffffffffeULL, 0x02, true},
      { 0x7fffffffffffffffULL, 0x02, true},
      { 0x8000000000000000ULL, 0x02, true},
      { 0x8000000000000001ULL, 0x02, true},
      { 0xfffffffffffffffeULL, 0x02, true},
      { 0xffffffffffffffffULL, 0x02, true},

      { 0x0000000000000000ULL, 0x7e, false},
      { 0x0000000000000001ULL, 0x7e, false},
      { 0x0000000000000002ULL, 0x7e, false},
      { 0x000000007ffffffeULL, 0x7e, true},
      { 0x000000007fffffffULL, 0x7e, true},
      { 0x0000000080000000ULL, 0x7e, true},
      { 0x0000000080000001ULL, 0x7e, true},
      { 0x00000000fffffffeULL, 0x7e, true},
      { 0x00000000ffffffffULL, 0x7e, true},
      { 0x0000000100000000ULL, 0x7e, true},
      { 0x0000000200000000ULL, 0x7e, true},
      { 0x7ffffffffffffffeULL, 0x7e, true},
      { 0x7fffffffffffffffULL, 0x7e, true},
      { 0x8000000000000000ULL, 0x7e, true},
      { 0x8000000000000001ULL, 0x7e, true},
      { 0xfffffffffffffffeULL, 0x7e, true},
      { 0xffffffffffffffffULL, 0x7e, true},

      { 0x0000000000000000ULL, 0x7f, false},
      { 0x0000000000000001ULL, 0x7f, false},
      { 0x0000000000000002ULL, 0x7f, false},
      { 0x000000007ffffffeULL, 0x7f, true},
      { 0x000000007fffffffULL, 0x7f, true},
      { 0x0000000080000000ULL, 0x7f, true},
      { 0x0000000080000001ULL, 0x7f, true},
      { 0x00000000fffffffeULL, 0x7f, true},
      { 0x00000000ffffffffULL, 0x7f, true},
      { 0x0000000100000000ULL, 0x7f, true},
      { 0x0000000200000000ULL, 0x7f, true},
      { 0x7ffffffffffffffeULL, 0x7f, true},
      { 0x7fffffffffffffffULL, 0x7f, true},
      { 0x8000000000000000ULL, 0x7f, true},
      { 0x8000000000000001ULL, 0x7f, true},
      { 0xfffffffffffffffeULL, 0x7f, true},
      { 0xffffffffffffffffULL, 0x7f, true},

      { 0x0000000000000000ULL, 0x80, true},
      { 0x0000000000000001ULL, 0x80, true},
      { 0x0000000000000002ULL, 0x80, true},
      { 0x000000007ffffffeULL, 0x80, true},
      { 0x000000007fffffffULL, 0x80, true},
      { 0x0000000080000000ULL, 0x80, true},
      { 0x0000000080000001ULL, 0x80, true},
      { 0x00000000fffffffeULL, 0x80, true},
      { 0x00000000ffffffffULL, 0x80, true},
      { 0x0000000100000000ULL, 0x80, true},
      { 0x0000000200000000ULL, 0x80, true},
      { 0x7ffffffffffffffeULL, 0x80, true},
      { 0x7fffffffffffffffULL, 0x80, true},
      { 0x8000000000000000ULL, 0x80, true},
      { 0x8000000000000001ULL, 0x80, true},
      { 0xfffffffffffffffeULL, 0x80, false},
      { 0xffffffffffffffffULL, 0x80, false},

      { 0x0000000000000000ULL, 0x81, true},
      { 0x0000000000000001ULL, 0x81, true},
      { 0x0000000000000002ULL, 0x81, true},
      { 0x000000007ffffffeULL, 0x81, true},
      { 0x000000007fffffffULL, 0x81, true},
      { 0x0000000080000000ULL, 0x81, true},
      { 0x0000000080000001ULL, 0x81, true},
      { 0x00000000fffffffeULL, 0x81, true},
      { 0x00000000ffffffffULL, 0x81, true},
      { 0x0000000100000000ULL, 0x81, true},
      { 0x0000000200000000ULL, 0x81, true},
      { 0x7ffffffffffffffeULL, 0x81, true},
      { 0x7fffffffffffffffULL, 0x81, true},
      { 0x8000000000000000ULL, 0x81, true},
      { 0x8000000000000001ULL, 0x81, true},
      { 0xfffffffffffffffeULL, 0x81, false},
      { 0xffffffffffffffffULL, 0x81, false},

      { 0x0000000000000000ULL, 0xfe, true},
      { 0x0000000000000001ULL, 0xfe, true},
      { 0x0000000000000002ULL, 0xfe, true},
      { 0x000000007ffffffeULL, 0xfe, true},
      { 0x000000007fffffffULL, 0xfe, true},
      { 0x0000000080000000ULL, 0xfe, true},
      { 0x0000000080000001ULL, 0xfe, true},
      { 0x00000000fffffffeULL, 0xfe, true},
      { 0x00000000ffffffffULL, 0xfe, true},
      { 0x0000000100000000ULL, 0xfe, true},
      { 0x0000000200000000ULL, 0xfe, true},
      { 0x7ffffffffffffffeULL, 0xfe, true},
      { 0x7fffffffffffffffULL, 0xfe, true},
      { 0x8000000000000000ULL, 0xfe, true},
      { 0x8000000000000001ULL, 0xfe, true},
      { 0xfffffffffffffffeULL, 0xfe, false},
      { 0xffffffffffffffffULL, 0xfe, false},

      { 0x0000000000000000ULL, 0xff, true},
      { 0x0000000000000001ULL, 0xff, true},
      { 0x0000000000000002ULL, 0xff, true},
      { 0x000000007ffffffeULL, 0xff, true},
      { 0x000000007fffffffULL, 0xff, true},
      { 0x0000000080000000ULL, 0xff, true},
      { 0x0000000080000001ULL, 0xff, true},
      { 0x00000000fffffffeULL, 0xff, true},
      { 0x00000000ffffffffULL, 0xff, true},
      { 0x0000000100000000ULL, 0xff, true},
      { 0x0000000200000000ULL, 0xff, true},
      { 0x7ffffffffffffffeULL, 0xff, true},
      { 0x7fffffffffffffffULL, 0xff, true},
      { 0x8000000000000000ULL, 0xff, true},
      { 0x8000000000000001ULL, 0xff, true},
      { 0xfffffffffffffffeULL, 0xff, true},
      { 0xffffffffffffffffULL, 0xff, false},
    };

  void SubVerifyUint64Int8()
  {
    size_t i;

    for( i = 0; i < COUNTOF(uint64_int8); ++i )
      {
        unsigned __int64 ret;
        if( SafeSubtract(uint64_int8[i].x, uint64_int8[i].y, ret) != uint64_int8[i].fExpected )
          {
            cerr << "Error in case uint64_int8: ";
            cerr << hex << setw(16) << setfill('0') << uint64_int8[i].x << ", ";
            cerr << hex << setw(2) << setfill('0') << (0xFF & (int)uint64_int8[i].y) << ", ";
            cerr << "expected = " << uint64_int8[i].fExpected << endl;
          }

        // Now test throwing version
        bool fSuccess = true;
        try
          {
            SafeInt<unsigned __int64> si(uint64_int8[i].x);
            si -= (__int8)uint64_int8[i].y;
          }
        catch(...)
          {
            fSuccess = false;
          }

        if( fSuccess != uint64_int8[i].fExpected )
          {
            cerr << "Error in case uint64_int8 throw (1): ";
            cerr << hex << setw(16) << setfill('0') << uint64_int8[i].x << ", ";
            cerr << hex << setw(2) << setfill('0') << (0xFF & (int)uint64_int8[i].y) << ", ";
            cerr << "expected = " << uint64_int8[i].fExpected << endl;
          }

        // Also need to test the version that assigns back out
        // to a plain int, as it has different logic
        fSuccess = true;
        try
          {
            unsigned __int64 x(uint64_int8[i].x);
            x -= SafeInt<__int8>(uint64_int8[i].y);
          }
        catch(...)
          {
            fSuccess = false;
          }

        if( fSuccess != uint64_int8[i].fExpected )
          {
            cerr << "Error in case uint64_int8 throw (2): ";
            cerr << hex << setw(16) << setfill('0') << uint64_int8[i].x << ", ";
            cerr << hex << setw(2) << setfill('0') << (0xFF & (int)uint64_int8[i].y) << ", ";
            cerr << "expected = " << uint64_int8[i].fExpected << endl;
          }
      }
  }

  static const SubTest< unsigned __int8, __int64 > uint8_int64[] =
    {
      { 0x00, 0x0000000000000000LL, true},
      { 0x01, 0x0000000000000000LL, true},
      { 0x02, 0x0000000000000000LL, true},
      { 0x7e, 0x0000000000000000LL, true},
      { 0x7f, 0x0000000000000000LL, true},
      { 0x80, 0x0000000000000000LL, true},
      { 0x81, 0x0000000000000000LL, true},
      { 0xfe, 0x0000000000000000LL, true},
      { 0xff, 0x0000000000000000LL, true},

      { 0x00, 0x0000000000000001LL, false},
      { 0x01, 0x0000000000000001LL, true},
      { 0x02, 0x0000000000000001LL, true},
      { 0x7e, 0x0000000000000001LL, true},
      { 0x7f, 0x0000000000000001LL, true},
      { 0x80, 0x0000000000000001LL, true},
      { 0x81, 0x0000000000000001LL, true},
      { 0xfe, 0x0000000000000001LL, true},
      { 0xff, 0x0000000000000001LL, true},

      { 0x00, 0x0000000000000002LL, false},
      { 0x01, 0x0000000000000002LL, false},
      { 0x02, 0x0000000000000002LL, true},
      { 0x7e, 0x0000000000000002LL, true},
      { 0x7f, 0x0000000000000002LL, true},
      { 0x80, 0x0000000000000002LL, true},
      { 0x81, 0x0000000000000002LL, true},
      { 0xfe, 0x0000000000000002LL, true},
      { 0xff, 0x0000000000000002LL, true},

      { 0x00, 0x000000007ffffffeLL, false},
      { 0x01, 0x000000007ffffffeLL, false},
      { 0x02, 0x000000007ffffffeLL, false},
      { 0x7e, 0x000000007ffffffeLL, false},
      { 0x7f, 0x000000007ffffffeLL, false},
      { 0x80, 0x000000007ffffffeLL, false},
      { 0x81, 0x000000007ffffffeLL, false},
      { 0xfe, 0x000000007ffffffeLL, false},
      { 0xff, 0x000000007ffffffeLL, false},

      { 0x00, 0x000000007fffffffLL, false},
      { 0x01, 0x000000007fffffffLL, false},
      { 0x02, 0x000000007fffffffLL, false},
      { 0x7e, 0x000000007fffffffLL, false},
      { 0x7f, 0x000000007fffffffLL, false},
      { 0x80, 0x000000007fffffffLL, false},
      { 0x81, 0x000000007fffffffLL, false},
      { 0xfe, 0x000000007fffffffLL, false},
      { 0xff, 0x000000007fffffffLL, false},

      { 0x00, 0x0000000080000000LL, false},
      { 0x01, 0x0000000080000000LL, false},
      { 0x02, 0x0000000080000000LL, false},
      { 0x7e, 0x0000000080000000LL, false},
      { 0x7f, 0x0000000080000000LL, false},
      { 0x80, 0x0000000080000000LL, false},
      { 0x81, 0x0000000080000000LL, false},
      { 0xfe, 0x0000000080000000LL, false},
      { 0xff, 0x0000000080000000LL, false},

      { 0x00, 0x0000000080000001LL, false},
      { 0x01, 0x0000000080000001LL, false},
      { 0x02, 0x0000000080000001LL, false},
      { 0x7e, 0x0000000080000001LL, false},
      { 0x7f, 0x0000000080000001LL, false},
      { 0x80, 0x0000000080000001LL, false},
      { 0x81, 0x0000000080000001LL, false},
      { 0xfe, 0x0000000080000001LL, false},
      { 0xff, 0x0000000080000001LL, false},

      { 0x00, 0x00000000fffffffeLL, false},
      { 0x01, 0x00000000fffffffeLL, false},
      { 0x02, 0x00000000fffffffeLL, false},
      { 0x7e, 0x00000000fffffffeLL, false},
      { 0x7f, 0x00000000fffffffeLL, false},
      { 0x80, 0x00000000fffffffeLL, false},
      { 0x81, 0x00000000fffffffeLL, false},
      { 0xfe, 0x00000000fffffffeLL, false},
      { 0xff, 0x00000000fffffffeLL, false},

      { 0x00, 0x00000000ffffffffLL, false},
      { 0x01, 0x00000000ffffffffLL, false},
      { 0x02, 0x00000000ffffffffLL, false},
      { 0x7e, 0x00000000ffffffffLL, false},
      { 0x7f, 0x00000000ffffffffLL, false},
      { 0x80, 0x00000000ffffffffLL, false},
      { 0x81, 0x00000000ffffffffLL, false},
      { 0xfe, 0x00000000ffffffffLL, false},
      { 0xff, 0x00000000ffffffffLL, false},

      { 0x00, 0x0000000100000000LL, false},
      { 0x01, 0x0000000100000000LL, false},
      { 0x02, 0x0000000100000000LL, false},
      { 0x7e, 0x0000000100000000LL, false},
      { 0x7f, 0x0000000100000000LL, false},
      { 0x80, 0x0000000100000000LL, false},
      { 0x81, 0x0000000100000000LL, false},
      { 0xfe, 0x0000000100000000LL, false},
      { 0xff, 0x0000000100000000LL, false},

      { 0x00, 0x0000000200000000LL, false},
      { 0x01, 0x0000000200000000LL, false},
      { 0x02, 0x0000000200000000LL, false},
      { 0x7e, 0x0000000200000000LL, false},
      { 0x7f, 0x0000000200000000LL, false},
      { 0x80, 0x0000000200000000LL, false},
      { 0x81, 0x0000000200000000LL, false},
      { 0xfe, 0x0000000200000000LL, false},
      { 0xff, 0x0000000200000000LL, false},

      { 0x00, 0x7ffffffffffffffeLL, false},
      { 0x01, 0x7ffffffffffffffeLL, false},
      { 0x02, 0x7ffffffffffffffeLL, false},
      { 0x7e, 0x7ffffffffffffffeLL, false},
      { 0x7f, 0x7ffffffffffffffeLL, false},
      { 0x80, 0x7ffffffffffffffeLL, false},
      { 0x81, 0x7ffffffffffffffeLL, false},
      { 0xfe, 0x7ffffffffffffffeLL, false},
      { 0xff, 0x7ffffffffffffffeLL, false},

      { 0x00, 0x7fffffffffffffffLL, false},
      { 0x01, 0x7fffffffffffffffLL, false},
      { 0x02, 0x7fffffffffffffffLL, false},
      { 0x7e, 0x7fffffffffffffffLL, false},
      { 0x7f, 0x7fffffffffffffffLL, false},
      { 0x80, 0x7fffffffffffffffLL, false},
      { 0x81, 0x7fffffffffffffffLL, false},
      { 0xfe, 0x7fffffffffffffffLL, false},
      { 0xff, 0x7fffffffffffffffLL, false},

      { 0x00, 0x8000000000000000LL, false},
      { 0x01, 0x8000000000000000LL, false},
      { 0x02, 0x8000000000000000LL, false},
      { 0x7e, 0x8000000000000000LL, false},
      { 0x7f, 0x8000000000000000LL, false},
      { 0x80, 0x8000000000000000LL, false},
      { 0x81, 0x8000000000000000LL, false},
      { 0xfe, 0x8000000000000000LL, false},
      { 0xff, 0x8000000000000000LL, false},

      { 0x00, 0x8000000000000001LL, false},
      { 0x01, 0x8000000000000001LL, false},
      { 0x02, 0x8000000000000001LL, false},
      { 0x7e, 0x8000000000000001LL, false},
      { 0x7f, 0x8000000000000001LL, false},
      { 0x80, 0x8000000000000001LL, false},
      { 0x81, 0x8000000000000001LL, false},
      { 0xfe, 0x8000000000000001LL, false},
      { 0xff, 0x8000000000000001LL, false},

      { 0x00, 0xfffffffffffffffeLL, true},
      { 0x01, 0xfffffffffffffffeLL, true},
      { 0x02, 0xfffffffffffffffeLL, true},
      { 0x7e, 0xfffffffffffffffeLL, true},
      { 0x7f, 0xfffffffffffffffeLL, true},
      { 0x80, 0xfffffffffffffffeLL, true},
      { 0x81, 0xfffffffffffffffeLL, true},
      { 0xfe, 0xfffffffffffffffeLL, false},
      { 0xff, 0xfffffffffffffffeLL, false},

      { 0x00, 0xffffffffffffffffLL, true},
      { 0x01, 0xffffffffffffffffLL, true},
      { 0x02, 0xffffffffffffffffLL, true},
      { 0x7e, 0xffffffffffffffffLL, true},
      { 0x7f, 0xffffffffffffffffLL, true},
      { 0x80, 0xffffffffffffffffLL, true},
      { 0x81, 0xffffffffffffffffLL, true},
      { 0xfe, 0xffffffffffffffffLL, true},
      { 0xff, 0xffffffffffffffffLL, false},
    };

  void SubVerifyUint8Int64()
  {
    size_t i;

    for( i = 0; i < COUNTOF(uint8_int64); ++i )
      {
        unsigned __int8 ret;
        if( SafeSubtract(uint8_int64[i].x, uint8_int64[i].y, ret) != uint8_int64[i].fExpected )
          {
            cerr << "Error in case uint8_int64: ";
            cerr << hex << setw(2) << setfill('0') << (0xFF & (int)uint8_int64[i].x) << ", ";
            cerr << hex << setw(16) << setfill('0') << uint8_int64[i].y << ", ";
            cerr << "expected = " << uint8_int64[i].fExpected << endl;
          }

        // Now test throwing version
        bool fSuccess = true;
        try
          {
            SafeInt<unsigned __int8> si(uint8_int64[i].x);
            si -= uint8_int64[i].y;
          }
        catch(...)
          {
            fSuccess = false;
          }

        if( fSuccess != uint8_int64[i].fExpected )
          {
            cerr << "Error in case uint8_int64 throw (1): ";
            cerr << hex << setw(2) << setfill('0') << (0xFF & (int)uint8_int64[i].x) << ", ";
            cerr << hex << setw(16) << setfill('0') << uint8_int64[i].y << ", ";
            cerr << "expected = " << uint8_int64[i].fExpected << endl;
          }

        // Also need to test the version that assigns back out
        // to a plain int, as it has different logic
        fSuccess = true;
        try
          {
            unsigned __int8 x(uint8_int64[i].x);
            x -= SafeInt<__int64>(uint8_int64[i].y);
          }
        catch(...)
          {
            fSuccess = false;
          }

        if( fSuccess != uint8_int64[i].fExpected )
          {
            cerr << "Error in case uint8_int64 throw (2): ";
            cerr << hex << setw(2) << setfill('0') << (0xFF & (int)uint8_int64[i].x) << ", ";
            cerr << hex << setw(16) << setfill('0') << uint8_int64[i].y << ", ";
            cerr << "expected = " << uint8_int64[i].fExpected << endl;
          }
      }
  }

  static const SubTest< unsigned __int8, __int32 > uint8_int32[] =
    {
      { 0x00, 0x00000000LL, true},
      { 0x01, 0x00000000LL, true},
      { 0x02, 0x00000000LL, true},
      { 0x7e, 0x00000000LL, true},
      { 0x7f, 0x00000000LL, true},
      { 0x80, 0x00000000LL, true},
      { 0x81, 0x00000000LL, true},
      { 0xfe, 0x00000000LL, true},
      { 0xff, 0x00000000LL, true},

      { 0x00, 0x00000001LL, false},
      { 0x01, 0x00000001LL, true},
      { 0x02, 0x00000001LL, true},
      { 0x7e, 0x00000001LL, true},
      { 0x7f, 0x00000001LL, true},
      { 0x80, 0x00000001LL, true},
      { 0x81, 0x00000001LL, true},
      { 0xfe, 0x00000001LL, true},
      { 0xff, 0x00000001LL, true},

      { 0x00, 0x00000002LL, false},
      { 0x01, 0x00000002LL, false},
      { 0x02, 0x00000002LL, true},
      { 0x7e, 0x00000002LL, true},
      { 0x7f, 0x00000002LL, true},
      { 0x80, 0x00000002LL, true},
      { 0x81, 0x00000002LL, true},
      { 0xfe, 0x00000002LL, true},
      { 0xff, 0x00000002LL, true},

      { 0x00, 0x7ffffffeLL, false},
      { 0x01, 0x7ffffffeLL, false},
      { 0x02, 0x7ffffffeLL, false},
      { 0x7e, 0x7ffffffeLL, false},
      { 0x7f, 0x7ffffffeLL, false},
      { 0x80, 0x7ffffffeLL, false},
      { 0x81, 0x7ffffffeLL, false},
      { 0xfe, 0x7ffffffeLL, false},
      { 0xff, 0x7ffffffeLL, false},

      { 0x00, 0x7fffffffLL, false},
      { 0x01, 0x7fffffffLL, false},
      { 0x02, 0x7fffffffLL, false},
      { 0x7e, 0x7fffffffLL, false},
      { 0x7f, 0x7fffffffLL, false},
      { 0x80, 0x7fffffffLL, false},
      { 0x81, 0x7fffffffLL, false},
      { 0xfe, 0x7fffffffLL, false},
      { 0xff, 0x7fffffffLL, false},

      { 0x00, 0x80000000LL, false},
      { 0x01, 0x80000000LL, false},
      { 0x02, 0x80000000LL, false},
      { 0x7e, 0x80000000LL, false},
      { 0x7f, 0x80000000LL, false},
      { 0x80, 0x80000000LL, false},
      { 0x81, 0x80000000LL, false},
      { 0xfe, 0x80000000LL, false},
      { 0xff, 0x80000000LL, false},

      { 0x00, 0x80000001LL, false},
      { 0x01, 0x80000001LL, false},
      { 0x02, 0x80000001LL, false},
      { 0x7e, 0x80000001LL, false},
      { 0x7f, 0x80000001LL, false},
      { 0x80, 0x80000001LL, false},
      { 0x81, 0x80000001LL, false},
      { 0xfe, 0x80000001LL, false},
      { 0xff, 0x80000001LL, false},

      { 0x00, 0xfffffffeLL, true},
      { 0x01, 0xfffffffeLL, true},
      { 0x02, 0xfffffffeLL, true},
      { 0x7e, 0xfffffffeLL, true},
      { 0x7f, 0xfffffffeLL, true},
      { 0x80, 0xfffffffeLL, true},
      { 0x81, 0xfffffffeLL, true},
      { 0xfe, 0xfffffffeLL, false},
      { 0xff, 0xfffffffeLL, false},

      { 0x00, 0xffffffffLL, true},
      { 0x01, 0xffffffffLL, true},
      { 0x02, 0xffffffffLL, true},
      { 0x7e, 0xffffffffLL, true},
      { 0x7f, 0xffffffffLL, true},
      { 0x80, 0xffffffffLL, true},
      { 0x81, 0xffffffffLL, true},
      { 0xfe, 0xffffffffLL, true},
      { 0xff, 0xffffffffLL, false},
    };

  void SubVerifyUint8Int32()
  {
    size_t i;

    for( i = 0; i < COUNTOF(uint8_int32); ++i )
      {
        unsigned __int8 ret;
        if( SafeSubtract(uint8_int32[i].x, uint8_int32[i].y, ret) != uint8_int32[i].fExpected )
          {
            cerr << "Error in case uint8_int32: ";
            cerr << hex << setw(2) << setfill('0') << (0xFF & (int)uint8_int32[i].x) << ", ";
            cerr << hex << setw(8) << setfill('0') << uint8_int32[i].y << ", ";
            cerr << "expected = " << uint8_int32[i].fExpected << endl;
          }

        // Now test throwing version
        bool fSuccess = true;
        try
          {
            SafeInt<unsigned __int8> si(uint8_int32[i].x);
            si -= uint8_int32[i].y;
          }
        catch(...)
          {
            fSuccess = false;
          }

        if( fSuccess != uint8_int32[i].fExpected )
          {
            cerr << "Error in case uint8_int32 throw (1): ";
            cerr << hex << setw(2) << setfill('0') << (0xFF & (int)uint8_int32[i].x) << ", ";
            cerr << hex << setw(8) << setfill('0') << uint8_int32[i].y << ", ";
            cerr << "expected = " << uint8_int32[i].fExpected << endl;
          }

        // Also need to test the version that assigns back out
        // to a plain int, as it has different logic
        fSuccess = true;
        try
          {
            unsigned __int8 x(uint8_int32[i].x);
            x -= SafeInt<__int32>(uint8_int32[i].y);
          }
        catch(...)
          {
            fSuccess = false;
          }

        if( fSuccess != uint8_int32[i].fExpected )
          {
            cerr << "Error in case uint8_int32 throw (2): ";
            cerr << hex << setw(2) << setfill('0') << (0xFF & (int)uint8_int32[i].x) << ", ";
            cerr << hex << setw(8) << setfill('0') << uint8_int32[i].y << ", ";
            cerr << "expected = " << uint8_int32[i].fExpected << endl;
          }
      }
  }

  static const SubTest< unsigned __int8, __int16 > uint8_int16[] =
    {
      { 0x00, 0x0000LL, true},
      { 0x01, 0x0000LL, true},
      { 0x02, 0x0000LL, true},
      { 0x7e, 0x0000LL, true},
      { 0x7f, 0x0000LL, true},
      { 0x80, 0x0000LL, true},
      { 0x81, 0x0000LL, true},
      { 0xfe, 0x0000LL, true},
      { 0xff, 0x0000LL, true},

      { 0x00, 0x0001LL, false},
      { 0x01, 0x0001LL, true},
      { 0x02, 0x0001LL, true},
      { 0x7e, 0x0001LL, true},
      { 0x7f, 0x0001LL, true},
      { 0x80, 0x0001LL, true},
      { 0x81, 0x0001LL, true},
      { 0xfe, 0x0001LL, true},
      { 0xff, 0x0001LL, true},

      { 0x00, 0x0002LL, false},
      { 0x01, 0x0002LL, false},
      { 0x02, 0x0002LL, true},
      { 0x7e, 0x0002LL, true},
      { 0x7f, 0x0002LL, true},
      { 0x80, 0x0002LL, true},
      { 0x81, 0x0002LL, true},
      { 0xfe, 0x0002LL, true},
      { 0xff, 0x0002LL, true},

      { 0x00, 0x7ffeLL, false},
      { 0x01, 0x7ffeLL, false},
      { 0x02, 0x7ffeLL, false},
      { 0x7e, 0x7ffeLL, false},
      { 0x7f, 0x7ffeLL, false},
      { 0x80, 0x7ffeLL, false},
      { 0x81, 0x7ffeLL, false},
      { 0xfe, 0x7ffeLL, false},
      { 0xff, 0x7ffeLL, false},

      { 0x00, 0x7fffLL, false},
      { 0x01, 0x7fffLL, false},
      { 0x02, 0x7fffLL, false},
      { 0x7e, 0x7fffLL, false},
      { 0x7f, 0x7fffLL, false},
      { 0x80, 0x7fffLL, false},
      { 0x81, 0x7fffLL, false},
      { 0xfe, 0x7fffLL, false},
      { 0xff, 0x7fffLL, false},

      { 0x00, 0x8000LL, false},
      { 0x01, 0x8000LL, false},
      { 0x02, 0x8000LL, false},
      { 0x7e, 0x8000LL, false},
      { 0x7f, 0x8000LL, false},
      { 0x80, 0x8000LL, false},
      { 0x81, 0x8000LL, false},
      { 0xfe, 0x8000LL, false},
      { 0xff, 0x8000LL, false},

      { 0x00, 0x8001LL, false},
      { 0x01, 0x8001LL, false},
      { 0x02, 0x8001LL, false},
      { 0x7e, 0x8001LL, false},
      { 0x7f, 0x8001LL, false},
      { 0x80, 0x8001LL, false},
      { 0x81, 0x8001LL, false},
      { 0xfe, 0x8001LL, false},
      { 0xff, 0x8001LL, false},

      { 0x00, 0xfffeLL, true},
      { 0x01, 0xfffeLL, true},
      { 0x02, 0xfffeLL, true},
      { 0x7e, 0xfffeLL, true},
      { 0x7f, 0xfffeLL, true},
      { 0x80, 0xfffeLL, true},
      { 0x81, 0xfffeLL, true},
      { 0xfe, 0xfffeLL, false},
      { 0xff, 0xfffeLL, false},

      { 0x00, 0xffffLL, true},
      { 0x01, 0xffffLL, true},
      { 0x02, 0xffffLL, true},
      { 0x7e, 0xffffLL, true},
      { 0x7f, 0xffffLL, true},
      { 0x80, 0xffffLL, true},
      { 0x81, 0xffffLL, true},
      { 0xfe, 0xffffLL, true},
      { 0xff, 0xffffLL, false},
    };

  void SubVerifyUint8Int16()
  {
    size_t i;

    for( i = 0; i < COUNTOF(uint8_int16); ++i )
      {
        unsigned __int8 ret;
        if( SafeSubtract(uint8_int16[i].x, uint8_int16[i].y, ret) != uint8_int16[i].fExpected )
          {
            cerr << "Error in case uint8_int16: ";
            cerr << hex << setw(2) << setfill('0') << (0xFF & (int)uint8_int16[i].x) << ", ";
            cerr << hex << setw(4) << setfill('0') << uint8_int16[i].y << ", ";
            cerr << "expected = " << uint8_int16[i].fExpected << endl;
          }

        // Now test throwing version
        bool fSuccess = true;
        try
          {
            SafeInt<unsigned __int8> si(uint8_int16[i].x);
            si -= uint8_int16[i].y;
          }
        catch(...)
          {
            fSuccess = false;
          }

        if( fSuccess != uint8_int16[i].fExpected )
          {
            cerr << "Error in case uint8_int16 throw (1): ";
            cerr << hex << setw(2) << setfill('0') << (0xFF & (int)uint8_int16[i].x) << ", ";
            cerr << hex << setw(4) << setfill('0') << uint8_int16[i].y << ", ";
            cerr << "expected = " << uint8_int16[i].fExpected << endl;
          }

        // Also need to test the version that assigns back out
        // to a plain int, as it has different logic
        fSuccess = true;
        try
          {
            unsigned __int8 x(uint8_int16[i].x);
            x -= SafeInt<__int16>(uint8_int16[i].y);
          }
        catch(...)
          {
            fSuccess = false;
          }

        if( fSuccess != uint8_int16[i].fExpected )
          {
            cerr << "Error in case uint8_int16 throw (2): ";
            cerr << hex << setw(2) << setfill('0') << (0xFF & (int)uint8_int16[i].x) << ", ";
            cerr << hex << setw(4) << setfill('0') << uint8_int16[i].y << ", ";
            cerr << "expected = " << uint8_int16[i].fExpected << endl;
          }
      }
  }

  static const SubTest< unsigned __int8, __int8 > uint8_int8[] =
    {
      { 0x00, 0x00LL, true},
      { 0x01, 0x00LL, true},
      { 0x02, 0x00LL, true},
      { 0x7e, 0x00LL, true},
      { 0x7f, 0x00LL, true},
      { 0x80, 0x00LL, true},
      { 0x81, 0x00LL, true},
      { 0xfe, 0x00LL, true},
      { 0xff, 0x00LL, true},

      { 0x00, 0x01LL, false},
      { 0x01, 0x01LL, true},
      { 0x02, 0x01LL, true},
      { 0x7e, 0x01LL, true},
      { 0x7f, 0x01LL, true},
      { 0x80, 0x01LL, true},
      { 0x81, 0x01LL, true},
      { 0xfe, 0x01LL, true},
      { 0xff, 0x01LL, true},

      { 0x00, 0x02LL, false},
      { 0x01, 0x02LL, false},
      { 0x02, 0x02LL, true},
      { 0x7e, 0x02LL, true},
      { 0x7f, 0x02LL, true},
      { 0x80, 0x02LL, true},
      { 0x81, 0x02LL, true},
      { 0xfe, 0x02LL, true},
      { 0xff, 0x02LL, true},

      { 0x00, 0x7eLL, false},
      { 0x01, 0x7eLL, false},
      { 0x02, 0x7eLL, false},
      { 0x7e, 0x7eLL, true},
      { 0x7f, 0x7eLL, true},
      { 0x80, 0x7eLL, true},
      { 0x81, 0x7eLL, true},
      { 0xfe, 0x7eLL, true},
      { 0xff, 0x7eLL, true},

      { 0x00, 0x7fLL, false},
      { 0x01, 0x7fLL, false},
      { 0x02, 0x7fLL, false},
      { 0x7e, 0x7fLL, false},
      { 0x7f, 0x7fLL, true},
      { 0x80, 0x7fLL, true},
      { 0x81, 0x7fLL, true},
      { 0xfe, 0x7fLL, true},
      { 0xff, 0x7fLL, true},

      { 0x00, 0x80LL, true},
      { 0x01, 0x80LL, true},
      { 0x02, 0x80LL, true},
      { 0x7e, 0x80LL, true},
      { 0x7f, 0x80LL, true},
      { 0x80, 0x80LL, false},
      { 0x81, 0x80LL, false},
      { 0xfe, 0x80LL, false},
      { 0xff, 0x80LL, false},

      { 0x00, 0x81LL, true},
      { 0x01, 0x81LL, true},
      { 0x02, 0x81LL, true},
      { 0x7e, 0x81LL, true},
      { 0x7f, 0x81LL, true},
      { 0x80, 0x81LL, true},
      { 0x81, 0x81LL, false},
      { 0xfe, 0x81LL, false},
      { 0xff, 0x81LL, false},

      { 0x00, 0xfeLL, true},
      { 0x01, 0xfeLL, true},
      { 0x02, 0xfeLL, true},
      { 0x7e, 0xfeLL, true},
      { 0x7f, 0xfeLL, true},
      { 0x80, 0xfeLL, true},
      { 0x81, 0xfeLL, true},
      { 0xfe, 0xfeLL, false},
      { 0xff, 0xfeLL, false},

      { 0x00, 0xffLL, true},
      { 0x01, 0xffLL, true},
      { 0x02, 0xffLL, true},
      { 0x7e, 0xffLL, true},
      { 0x7f, 0xffLL, true},
      { 0x80, 0xffLL, true},
      { 0x81, 0xffLL, true},
      { 0xfe, 0xffLL, true},
      { 0xff, 0xffLL, false},
    };

  void SubVerifyUint8Int8()
  {
    size_t i;

    for( i = 0; i < COUNTOF(uint8_int8); ++i )
      {
        unsigned __int8 ret;
        if( SafeSubtract(uint8_int8[i].x, uint8_int8[i].y, ret) != uint8_int8[i].fExpected )
          {
            cerr << "Error in case uint8_int8: ";
            cerr << hex << setw(2) << setfill('0') << (0xFF & (int)uint8_int8[i].x) << ", ";
            cerr << hex << setw(2) << setfill('0') << (0xFF & (int)uint8_int8[i].y) << ", ";
            cerr << "expected = " << uint8_int8[i].fExpected << endl;
          }

        // Now test throwing version
        bool fSuccess = true;
        try
          {
            SafeInt<unsigned __int8> si(uint8_int8[i].x);
            si -= uint8_int8[i].y;
          }
        catch(...)
          {
            fSuccess = false;
          }

        if( fSuccess != uint8_int8[i].fExpected )
          {
            cerr << "Error in case uint8_int8 throw (1): ";
            cerr << hex << setw(2) << setfill('0') << (0xFF & (int)uint8_int8[i].x) << ", ";
            cerr << hex << setw(2) << setfill('0') << (0xFF & (int)uint8_int8[i].y) << ", ";
            cerr << "expected = " << uint8_int8[i].fExpected << endl;
          }

        // Also need to test the version that assigns back out
        // to a plain int, as it has different logic
        fSuccess = true;
        try
          {
            unsigned __int8 x(uint8_int8[i].x);
            x -= SafeInt<__int8>(uint8_int8[i].y);
          }
        catch(...)
          {
            fSuccess = false;
          }

        if( fSuccess != uint8_int8[i].fExpected )
          {
            cerr << "Error in case uint8_int8 throw (2): ";
            cerr << hex << setw(2) << setfill('0') << (0xFF & (int)uint8_int8[i].x) << ", ";
            cerr << hex << setw(2) << setfill('0') << (0xFF & (int)uint8_int8[i].y) << ", ";
            cerr << "expected = " << uint8_int8[i].fExpected << endl;
          }
      }
  }

  static const SubTest< __int64, unsigned __int64 > int64_uint64[] =
    {
      { 0x0000000000000000LL, 0x0000000000000000ULL, true},
      { 0x0000000000000001LL, 0x0000000000000000ULL, true},
      { 0x0000000000000002LL, 0x0000000000000000ULL, true},
      { 0x000000007ffffffeLL, 0x0000000000000000ULL, true},
      { 0x000000007fffffffLL, 0x0000000000000000ULL, true},
      { 0x0000000080000000LL, 0x0000000000000000ULL, true},
      { 0x0000000080000001LL, 0x0000000000000000ULL, true},
      { 0x00000000fffffffeLL, 0x0000000000000000ULL, true},
      { 0x00000000ffffffffLL, 0x0000000000000000ULL, true},
      { 0x0000000100000000LL, 0x0000000000000000ULL, true},
      { 0x0000000200000000LL, 0x0000000000000000ULL, true},
      { 0x7ffffffffffffffeLL, 0x0000000000000000ULL, true},
      { 0x7fffffffffffffffLL, 0x0000000000000000ULL, true},
      { 0x8000000000000000LL, 0x0000000000000000ULL, true},
      { 0x8000000000000001LL, 0x0000000000000000ULL, true},
      { 0xfffffffffffffffeLL, 0x0000000000000000ULL, true},
      { 0xffffffffffffffffLL, 0x0000000000000000ULL, true},

      { 0x0000000000000000LL, 0x0000000000000001ULL, true},
      { 0x0000000000000001LL, 0x0000000000000001ULL, true},
      { 0x0000000000000002LL, 0x0000000000000001ULL, true},
      { 0x000000007ffffffeLL, 0x0000000000000001ULL, true},
      { 0x000000007fffffffLL, 0x0000000000000001ULL, true},
      { 0x0000000080000000LL, 0x0000000000000001ULL, true},
      { 0x0000000080000001LL, 0x0000000000000001ULL, true},
      { 0x00000000fffffffeLL, 0x0000000000000001ULL, true},
      { 0x00000000ffffffffLL, 0x0000000000000001ULL, true},
      { 0x0000000100000000LL, 0x0000000000000001ULL, true},
      { 0x0000000200000000LL, 0x0000000000000001ULL, true},
      { 0x7ffffffffffffffeLL, 0x0000000000000001ULL, true},
      { 0x7fffffffffffffffLL, 0x0000000000000001ULL, true},
      { 0x8000000000000000LL, 0x0000000000000001ULL, false},
      { 0x8000000000000001LL, 0x0000000000000001ULL, true},
      { 0xfffffffffffffffeLL, 0x0000000000000001ULL, true},
      { 0xffffffffffffffffLL, 0x0000000000000001ULL, true},

      { 0x0000000000000000LL, 0x0000000000000002ULL, true},
      { 0x0000000000000001LL, 0x0000000000000002ULL, true},
      { 0x0000000000000002LL, 0x0000000000000002ULL, true},
      { 0x000000007ffffffeLL, 0x0000000000000002ULL, true},
      { 0x000000007fffffffLL, 0x0000000000000002ULL, true},
      { 0x0000000080000000LL, 0x0000000000000002ULL, true},
      { 0x0000000080000001LL, 0x0000000000000002ULL, true},
      { 0x00000000fffffffeLL, 0x0000000000000002ULL, true},
      { 0x00000000ffffffffLL, 0x0000000000000002ULL, true},
      { 0x0000000100000000LL, 0x0000000000000002ULL, true},
      { 0x0000000200000000LL, 0x0000000000000002ULL, true},
      { 0x7ffffffffffffffeLL, 0x0000000000000002ULL, true},
      { 0x7fffffffffffffffLL, 0x0000000000000002ULL, true},
      { 0x8000000000000000LL, 0x0000000000000002ULL, false},
      { 0x8000000000000001LL, 0x0000000000000002ULL, false},
      { 0xfffffffffffffffeLL, 0x0000000000000002ULL, true},
      { 0xffffffffffffffffLL, 0x0000000000000002ULL, true},

      { 0x0000000000000000LL, 0x000000007ffffffeULL, true},
      { 0x0000000000000001LL, 0x000000007ffffffeULL, true},
      { 0x0000000000000002LL, 0x000000007ffffffeULL, true},
      { 0x000000007ffffffeLL, 0x000000007ffffffeULL, true},
      { 0x000000007fffffffLL, 0x000000007ffffffeULL, true},
      { 0x0000000080000000LL, 0x000000007ffffffeULL, true},
      { 0x0000000080000001LL, 0x000000007ffffffeULL, true},
      { 0x00000000fffffffeLL, 0x000000007ffffffeULL, true},
      { 0x00000000ffffffffLL, 0x000000007ffffffeULL, true},
      { 0x0000000100000000LL, 0x000000007ffffffeULL, true},
      { 0x0000000200000000LL, 0x000000007ffffffeULL, true},
      { 0x7ffffffffffffffeLL, 0x000000007ffffffeULL, true},
      { 0x7fffffffffffffffLL, 0x000000007ffffffeULL, true},
      { 0x8000000000000000LL, 0x000000007ffffffeULL, false},
      { 0x8000000000000001LL, 0x000000007ffffffeULL, false},
      { 0xfffffffffffffffeLL, 0x000000007ffffffeULL, true},
      { 0xffffffffffffffffLL, 0x000000007ffffffeULL, true},

      { 0x0000000000000000LL, 0x000000007fffffffULL, true},
      { 0x0000000000000001LL, 0x000000007fffffffULL, true},
      { 0x0000000000000002LL, 0x000000007fffffffULL, true},
      { 0x000000007ffffffeLL, 0x000000007fffffffULL, true},
      { 0x000000007fffffffLL, 0x000000007fffffffULL, true},
      { 0x0000000080000000LL, 0x000000007fffffffULL, true},
      { 0x0000000080000001LL, 0x000000007fffffffULL, true},
      { 0x00000000fffffffeLL, 0x000000007fffffffULL, true},
      { 0x00000000ffffffffLL, 0x000000007fffffffULL, true},
      { 0x0000000100000000LL, 0x000000007fffffffULL, true},
      { 0x0000000200000000LL, 0x000000007fffffffULL, true},
      { 0x7ffffffffffffffeLL, 0x000000007fffffffULL, true},
      { 0x7fffffffffffffffLL, 0x000000007fffffffULL, true},
      { 0x8000000000000000LL, 0x000000007fffffffULL, false},
      { 0x8000000000000001LL, 0x000000007fffffffULL, false},
      { 0xfffffffffffffffeLL, 0x000000007fffffffULL, true},
      { 0xffffffffffffffffLL, 0x000000007fffffffULL, true},

      { 0x0000000000000000LL, 0x0000000080000000ULL, true},
      { 0x0000000000000001LL, 0x0000000080000000ULL, true},
      { 0x0000000000000002LL, 0x0000000080000000ULL, true},
      { 0x000000007ffffffeLL, 0x0000000080000000ULL, true},
      { 0x000000007fffffffLL, 0x0000000080000000ULL, true},
      { 0x0000000080000000LL, 0x0000000080000000ULL, true},
      { 0x0000000080000001LL, 0x0000000080000000ULL, true},
      { 0x00000000fffffffeLL, 0x0000000080000000ULL, true},
      { 0x00000000ffffffffLL, 0x0000000080000000ULL, true},
      { 0x0000000100000000LL, 0x0000000080000000ULL, true},
      { 0x0000000200000000LL, 0x0000000080000000ULL, true},
      { 0x7ffffffffffffffeLL, 0x0000000080000000ULL, true},
      { 0x7fffffffffffffffLL, 0x0000000080000000ULL, true},
      { 0x8000000000000000LL, 0x0000000080000000ULL, false},
      { 0x8000000000000001LL, 0x0000000080000000ULL, false},
      { 0xfffffffffffffffeLL, 0x0000000080000000ULL, true},
      { 0xffffffffffffffffLL, 0x0000000080000000ULL, true},

      { 0x0000000000000000LL, 0x0000000080000001ULL, true},
      { 0x0000000000000001LL, 0x0000000080000001ULL, true},
      { 0x0000000000000002LL, 0x0000000080000001ULL, true},
      { 0x000000007ffffffeLL, 0x0000000080000001ULL, true},
      { 0x000000007fffffffLL, 0x0000000080000001ULL, true},
      { 0x0000000080000000LL, 0x0000000080000001ULL, true},
      { 0x0000000080000001LL, 0x0000000080000001ULL, true},
      { 0x00000000fffffffeLL, 0x0000000080000001ULL, true},
      { 0x00000000ffffffffLL, 0x0000000080000001ULL, true},
      { 0x0000000100000000LL, 0x0000000080000001ULL, true},
      { 0x0000000200000000LL, 0x0000000080000001ULL, true},
      { 0x7ffffffffffffffeLL, 0x0000000080000001ULL, true},
      { 0x7fffffffffffffffLL, 0x0000000080000001ULL, true},
      { 0x8000000000000000LL, 0x0000000080000001ULL, false},
      { 0x8000000000000001LL, 0x0000000080000001ULL, false},
      { 0xfffffffffffffffeLL, 0x0000000080000001ULL, true},
      { 0xffffffffffffffffLL, 0x0000000080000001ULL, true},

      { 0x0000000000000000LL, 0x00000000fffffffeULL, true},
      { 0x0000000000000001LL, 0x00000000fffffffeULL, true},
      { 0x0000000000000002LL, 0x00000000fffffffeULL, true},
      { 0x000000007ffffffeLL, 0x00000000fffffffeULL, true},
      { 0x000000007fffffffLL, 0x00000000fffffffeULL, true},
      { 0x0000000080000000LL, 0x00000000fffffffeULL, true},
      { 0x0000000080000001LL, 0x00000000fffffffeULL, true},
      { 0x00000000fffffffeLL, 0x00000000fffffffeULL, true},
      { 0x00000000ffffffffLL, 0x00000000fffffffeULL, true},
      { 0x0000000100000000LL, 0x00000000fffffffeULL, true},
      { 0x0000000200000000LL, 0x00000000fffffffeULL, true},
      { 0x7ffffffffffffffeLL, 0x00000000fffffffeULL, true},
      { 0x7fffffffffffffffLL, 0x00000000fffffffeULL, true},
      { 0x8000000000000000LL, 0x00000000fffffffeULL, false},
      { 0x8000000000000001LL, 0x00000000fffffffeULL, false},
      { 0xfffffffffffffffeLL, 0x00000000fffffffeULL, true},
      { 0xffffffffffffffffLL, 0x00000000fffffffeULL, true},

      { 0x0000000000000000LL, 0x00000000ffffffffULL, true},
      { 0x0000000000000001LL, 0x00000000ffffffffULL, true},
      { 0x0000000000000002LL, 0x00000000ffffffffULL, true},
      { 0x000000007ffffffeLL, 0x00000000ffffffffULL, true},
      { 0x000000007fffffffLL, 0x00000000ffffffffULL, true},
      { 0x0000000080000000LL, 0x00000000ffffffffULL, true},
      { 0x0000000080000001LL, 0x00000000ffffffffULL, true},
      { 0x00000000fffffffeLL, 0x00000000ffffffffULL, true},
      { 0x00000000ffffffffLL, 0x00000000ffffffffULL, true},
      { 0x0000000100000000LL, 0x00000000ffffffffULL, true},
      { 0x0000000200000000LL, 0x00000000ffffffffULL, true},
      { 0x7ffffffffffffffeLL, 0x00000000ffffffffULL, true},
      { 0x7fffffffffffffffLL, 0x00000000ffffffffULL, true},
      { 0x8000000000000000LL, 0x00000000ffffffffULL, false},
      { 0x8000000000000001LL, 0x00000000ffffffffULL, false},
      { 0xfffffffffffffffeLL, 0x00000000ffffffffULL, true},
      { 0xffffffffffffffffLL, 0x00000000ffffffffULL, true},

      { 0x0000000000000000LL, 0x0000000100000000ULL, true},
      { 0x0000000000000001LL, 0x0000000100000000ULL, true},
      { 0x0000000000000002LL, 0x0000000100000000ULL, true},
      { 0x000000007ffffffeLL, 0x0000000100000000ULL, true},
      { 0x000000007fffffffLL, 0x0000000100000000ULL, true},
      { 0x0000000080000000LL, 0x0000000100000000ULL, true},
      { 0x0000000080000001LL, 0x0000000100000000ULL, true},
      { 0x00000000fffffffeLL, 0x0000000100000000ULL, true},
      { 0x00000000ffffffffLL, 0x0000000100000000ULL, true},
      { 0x0000000100000000LL, 0x0000000100000000ULL, true},
      { 0x0000000200000000LL, 0x0000000100000000ULL, true},
      { 0x7ffffffffffffffeLL, 0x0000000100000000ULL, true},
      { 0x7fffffffffffffffLL, 0x0000000100000000ULL, true},
      { 0x8000000000000000LL, 0x0000000100000000ULL, false},
      { 0x8000000000000001LL, 0x0000000100000000ULL, false},
      { 0xfffffffffffffffeLL, 0x0000000100000000ULL, true},
      { 0xffffffffffffffffLL, 0x0000000100000000ULL, true},

      { 0x0000000000000000LL, 0x0000000200000000ULL, true},
      { 0x0000000000000001LL, 0x0000000200000000ULL, true},
      { 0x0000000000000002LL, 0x0000000200000000ULL, true},
      { 0x000000007ffffffeLL, 0x0000000200000000ULL, true},
      { 0x000000007fffffffLL, 0x0000000200000000ULL, true},
      { 0x0000000080000000LL, 0x0000000200000000ULL, true},
      { 0x0000000080000001LL, 0x0000000200000000ULL, true},
      { 0x00000000fffffffeLL, 0x0000000200000000ULL, true},
      { 0x00000000ffffffffLL, 0x0000000200000000ULL, true},
      { 0x0000000100000000LL, 0x0000000200000000ULL, true},
      { 0x0000000200000000LL, 0x0000000200000000ULL, true},
      { 0x7ffffffffffffffeLL, 0x0000000200000000ULL, true},
      { 0x7fffffffffffffffLL, 0x0000000200000000ULL, true},
      { 0x8000000000000000LL, 0x0000000200000000ULL, false},
      { 0x8000000000000001LL, 0x0000000200000000ULL, false},
      { 0xfffffffffffffffeLL, 0x0000000200000000ULL, true},
      { 0xffffffffffffffffLL, 0x0000000200000000ULL, true},

      { 0x0000000000000000LL, 0x7ffffffffffffffeULL, true},
      { 0x0000000000000001LL, 0x7ffffffffffffffeULL, true},
      { 0x0000000000000002LL, 0x7ffffffffffffffeULL, true},
      { 0x000000007ffffffeLL, 0x7ffffffffffffffeULL, true},
      { 0x000000007fffffffLL, 0x7ffffffffffffffeULL, true},
      { 0x0000000080000000LL, 0x7ffffffffffffffeULL, true},
      { 0x0000000080000001LL, 0x7ffffffffffffffeULL, true},
      { 0x00000000fffffffeLL, 0x7ffffffffffffffeULL, true},
      { 0x00000000ffffffffLL, 0x7ffffffffffffffeULL, true},
      { 0x0000000100000000LL, 0x7ffffffffffffffeULL, true},
      { 0x0000000200000000LL, 0x7ffffffffffffffeULL, true},
      { 0x7ffffffffffffffeLL, 0x7ffffffffffffffeULL, true},
      { 0x7fffffffffffffffLL, 0x7ffffffffffffffeULL, true},
      { 0x8000000000000000LL, 0x7ffffffffffffffeULL, false},
      { 0x8000000000000001LL, 0x7ffffffffffffffeULL, false},
      { 0xfffffffffffffffeLL, 0x7ffffffffffffffeULL, true},
      { 0xffffffffffffffffLL, 0x7ffffffffffffffeULL, true},

      { 0x0000000000000000LL, 0x7fffffffffffffffULL, true},
      { 0x0000000000000001LL, 0x7fffffffffffffffULL, true},
      { 0x0000000000000002LL, 0x7fffffffffffffffULL, true},
      { 0x000000007ffffffeLL, 0x7fffffffffffffffULL, true},
      { 0x000000007fffffffLL, 0x7fffffffffffffffULL, true},
      { 0x0000000080000000LL, 0x7fffffffffffffffULL, true},
      { 0x0000000080000001LL, 0x7fffffffffffffffULL, true},
      { 0x00000000fffffffeLL, 0x7fffffffffffffffULL, true},
      { 0x00000000ffffffffLL, 0x7fffffffffffffffULL, true},
      { 0x0000000100000000LL, 0x7fffffffffffffffULL, true},
      { 0x0000000200000000LL, 0x7fffffffffffffffULL, true},
      { 0x7ffffffffffffffeLL, 0x7fffffffffffffffULL, true},
      { 0x7fffffffffffffffLL, 0x7fffffffffffffffULL, true},
      { 0x8000000000000000LL, 0x7fffffffffffffffULL, false},
      { 0x8000000000000001LL, 0x7fffffffffffffffULL, false},
      { 0xfffffffffffffffeLL, 0x7fffffffffffffffULL, false},
      { 0xffffffffffffffffLL, 0x7fffffffffffffffULL, true},

      { 0x0000000000000000LL, 0x8000000000000000ULL, true},
      { 0x0000000000000001LL, 0x8000000000000000ULL, true},
      { 0x0000000000000002LL, 0x8000000000000000ULL, true},
      { 0x000000007ffffffeLL, 0x8000000000000000ULL, true},
      { 0x000000007fffffffLL, 0x8000000000000000ULL, true},
      { 0x0000000080000000LL, 0x8000000000000000ULL, true},
      { 0x0000000080000001LL, 0x8000000000000000ULL, true},
      { 0x00000000fffffffeLL, 0x8000000000000000ULL, true},
      { 0x00000000ffffffffLL, 0x8000000000000000ULL, true},
      { 0x0000000100000000LL, 0x8000000000000000ULL, true},
      { 0x0000000200000000LL, 0x8000000000000000ULL, true},
      { 0x7ffffffffffffffeLL, 0x8000000000000000ULL, true},
      { 0x7fffffffffffffffLL, 0x8000000000000000ULL, true},
      { 0x8000000000000000LL, 0x8000000000000000ULL, false},
      { 0x8000000000000001LL, 0x8000000000000000ULL, false},
      { 0xfffffffffffffffeLL, 0x8000000000000000ULL, false},
      { 0xffffffffffffffffLL, 0x8000000000000000ULL, false},

      { 0x0000000000000000LL, 0x8000000000000001ULL, false},
      { 0x0000000000000001LL, 0x8000000000000001ULL, true},
      { 0x0000000000000002LL, 0x8000000000000001ULL, true},
      { 0x000000007ffffffeLL, 0x8000000000000001ULL, true},
      { 0x000000007fffffffLL, 0x8000000000000001ULL, true},
      { 0x0000000080000000LL, 0x8000000000000001ULL, true},
      { 0x0000000080000001LL, 0x8000000000000001ULL, true},
      { 0x00000000fffffffeLL, 0x8000000000000001ULL, true},
      { 0x00000000ffffffffLL, 0x8000000000000001ULL, true},
      { 0x0000000100000000LL, 0x8000000000000001ULL, true},
      { 0x0000000200000000LL, 0x8000000000000001ULL, true},
      { 0x7ffffffffffffffeLL, 0x8000000000000001ULL, true},
      { 0x7fffffffffffffffLL, 0x8000000000000001ULL, true},
      { 0x8000000000000000LL, 0x8000000000000001ULL, false},
      { 0x8000000000000001LL, 0x8000000000000001ULL, false},
      { 0xfffffffffffffffeLL, 0x8000000000000001ULL, false},
      { 0xffffffffffffffffLL, 0x8000000000000001ULL, false},

      { 0x0000000000000000LL, 0xfffffffffffffffeULL, false},
      { 0x0000000000000001LL, 0xfffffffffffffffeULL, false},
      { 0x0000000000000002LL, 0xfffffffffffffffeULL, false},
      { 0x000000007ffffffeLL, 0xfffffffffffffffeULL, false},
      { 0x000000007fffffffLL, 0xfffffffffffffffeULL, false},
      { 0x0000000080000000LL, 0xfffffffffffffffeULL, false},
      { 0x0000000080000001LL, 0xfffffffffffffffeULL, false},
      { 0x00000000fffffffeLL, 0xfffffffffffffffeULL, false},
      { 0x00000000ffffffffLL, 0xfffffffffffffffeULL, false},
      { 0x0000000100000000LL, 0xfffffffffffffffeULL, false},
      { 0x0000000200000000LL, 0xfffffffffffffffeULL, false},
      { 0x7ffffffffffffffeLL, 0xfffffffffffffffeULL, true},
      { 0x7fffffffffffffffLL, 0xfffffffffffffffeULL, true},
      { 0x8000000000000000LL, 0xfffffffffffffffeULL, false},
      { 0x8000000000000001LL, 0xfffffffffffffffeULL, false},
      { 0xfffffffffffffffeLL, 0xfffffffffffffffeULL, false},
      { 0xffffffffffffffffLL, 0xfffffffffffffffeULL, false},

      { 0x0000000000000000LL, 0xffffffffffffffffULL, false},
      { 0x0000000000000001LL, 0xffffffffffffffffULL, false},
      { 0x0000000000000002LL, 0xffffffffffffffffULL, false},
      { 0x000000007ffffffeLL, 0xffffffffffffffffULL, false},
      { 0x000000007fffffffLL, 0xffffffffffffffffULL, false},
      { 0x0000000080000000LL, 0xffffffffffffffffULL, false},
      { 0x0000000080000001LL, 0xffffffffffffffffULL, false},
      { 0x00000000fffffffeLL, 0xffffffffffffffffULL, false},
      { 0x00000000ffffffffLL, 0xffffffffffffffffULL, false},
      { 0x0000000100000000LL, 0xffffffffffffffffULL, false},
      { 0x0000000200000000LL, 0xffffffffffffffffULL, false},
      { 0x7ffffffffffffffeLL, 0xffffffffffffffffULL, false},
      { 0x7fffffffffffffffLL, 0xffffffffffffffffULL, true},
      { 0x8000000000000000LL, 0xffffffffffffffffULL, false},
      { 0x8000000000000001LL, 0xffffffffffffffffULL, false},
      { 0xfffffffffffffffeLL, 0xffffffffffffffffULL, false},
      { 0xffffffffffffffffLL, 0xffffffffffffffffULL, false},
    };

  void SubVerifyInt64Uint64()
  {
    size_t i;

    for( i = 0; i < COUNTOF(int64_uint64); ++i )
      {
        __int64 ret;
        if( SafeSubtract(int64_uint64[i].x, int64_uint64[i].y, ret) != int64_uint64[i].fExpected )
          {
            cerr << "Error in case int64_uint64: ";
            cerr << hex << setw(16) << setfill('0') << int64_uint64[i].x << ", ";
            cerr << hex << setw(16) << setfill('0') << int64_uint64[i].y << ", ";
            cerr << "expected = " << int64_uint64[i].fExpected << endl;
          }

        // Now test throwing version
        bool fSuccess = true;
        try
          {
            SafeInt<__int64> si(int64_uint64[i].x);
            si -= int64_uint64[i].y;
          }
        catch(...)
          {
            fSuccess = false;
          }

        if( fSuccess != int64_uint64[i].fExpected )
          {
            cerr << "Error in case int64_uint64 throw (1): ";
            cerr << hex << setw(16) << setfill('0') << int64_uint64[i].x << ", ";
            cerr << hex << setw(16) << setfill('0') << int64_uint64[i].y << ", ";
            cerr << "expected = " << int64_uint64[i].fExpected << endl;
          }

        // Also need to test the version that assigns back out
        // to a plain int, as it has different logic
        fSuccess = true;
        try
          {
            __int64 x(int64_uint64[i].x);
            x -= SafeInt<unsigned __int64>(int64_uint64[i].y);
          }
        catch(...)
          {
            fSuccess = false;
          }

        if( fSuccess != int64_uint64[i].fExpected )
          {
            cerr << "Error in case int64_uint64 throw (2): ";
            cerr << hex << setw(16) << setfill('0') << int64_uint64[i].x << ", ";
            cerr << hex << setw(16) << setfill('0') << int64_uint64[i].y << ", ";
            cerr << "expected = " << int64_uint64[i].fExpected << endl;
          }
      }
  }

  static const SubTest< __int64, unsigned __int32 > int64_uint32[] =
    {
      { 0x0000000000000000LL, 0x00000000, true},
      { 0x0000000000000001LL, 0x00000000, true},
      { 0x0000000000000002LL, 0x00000000, true},
      { 0x000000007ffffffeLL, 0x00000000, true},
      { 0x000000007fffffffLL, 0x00000000, true},
      { 0x0000000080000000LL, 0x00000000, true},
      { 0x0000000080000001LL, 0x00000000, true},
      { 0x00000000fffffffeLL, 0x00000000, true},
      { 0x00000000ffffffffLL, 0x00000000, true},
      { 0x0000000100000000LL, 0x00000000, true},
      { 0x0000000200000000LL, 0x00000000, true},
      { 0x7ffffffffffffffeLL, 0x00000000, true},
      { 0x7fffffffffffffffLL, 0x00000000, true},
      { 0x8000000000000000LL, 0x00000000, true},
      { 0x8000000000000001LL, 0x00000000, true},
      { 0xfffffffffffffffeLL, 0x00000000, true},
      { 0xffffffffffffffffLL, 0x00000000, true},

      { 0x0000000000000000LL, 0x00000001, true},
      { 0x0000000000000001LL, 0x00000001, true},
      { 0x0000000000000002LL, 0x00000001, true},
      { 0x000000007ffffffeLL, 0x00000001, true},
      { 0x000000007fffffffLL, 0x00000001, true},
      { 0x0000000080000000LL, 0x00000001, true},
      { 0x0000000080000001LL, 0x00000001, true},
      { 0x00000000fffffffeLL, 0x00000001, true},
      { 0x00000000ffffffffLL, 0x00000001, true},
      { 0x0000000100000000LL, 0x00000001, true},
      { 0x0000000200000000LL, 0x00000001, true},
      { 0x7ffffffffffffffeLL, 0x00000001, true},
      { 0x7fffffffffffffffLL, 0x00000001, true},
      { 0x8000000000000000LL, 0x00000001, false},
      { 0x8000000000000001LL, 0x00000001, true},
      { 0xfffffffffffffffeLL, 0x00000001, true},
      { 0xffffffffffffffffLL, 0x00000001, true},

      { 0x0000000000000000LL, 0x00000002, true},
      { 0x0000000000000001LL, 0x00000002, true},
      { 0x0000000000000002LL, 0x00000002, true},
      { 0x000000007ffffffeLL, 0x00000002, true},
      { 0x000000007fffffffLL, 0x00000002, true},
      { 0x0000000080000000LL, 0x00000002, true},
      { 0x0000000080000001LL, 0x00000002, true},
      { 0x00000000fffffffeLL, 0x00000002, true},
      { 0x00000000ffffffffLL, 0x00000002, true},
      { 0x0000000100000000LL, 0x00000002, true},
      { 0x0000000200000000LL, 0x00000002, true},
      { 0x7ffffffffffffffeLL, 0x00000002, true},
      { 0x7fffffffffffffffLL, 0x00000002, true},
      { 0x8000000000000000LL, 0x00000002, false},
      { 0x8000000000000001LL, 0x00000002, false},
      { 0xfffffffffffffffeLL, 0x00000002, true},
      { 0xffffffffffffffffLL, 0x00000002, true},

      { 0x0000000000000000LL, 0x7ffffffe, true},
      { 0x0000000000000001LL, 0x7ffffffe, true},
      { 0x0000000000000002LL, 0x7ffffffe, true},
      { 0x000000007ffffffeLL, 0x7ffffffe, true},
      { 0x000000007fffffffLL, 0x7ffffffe, true},
      { 0x0000000080000000LL, 0x7ffffffe, true},
      { 0x0000000080000001LL, 0x7ffffffe, true},
      { 0x00000000fffffffeLL, 0x7ffffffe, true},
      { 0x00000000ffffffffLL, 0x7ffffffe, true},
      { 0x0000000100000000LL, 0x7ffffffe, true},
      { 0x0000000200000000LL, 0x7ffffffe, true},
      { 0x7ffffffffffffffeLL, 0x7ffffffe, true},
      { 0x7fffffffffffffffLL, 0x7ffffffe, true},
      { 0x8000000000000000LL, 0x7ffffffe, false},
      { 0x8000000000000001LL, 0x7ffffffe, false},
      { 0xfffffffffffffffeLL, 0x7ffffffe, true},
      { 0xffffffffffffffffLL, 0x7ffffffe, true},

      { 0x0000000000000000LL, 0x7fffffff, true},
      { 0x0000000000000001LL, 0x7fffffff, true},
      { 0x0000000000000002LL, 0x7fffffff, true},
      { 0x000000007ffffffeLL, 0x7fffffff, true},
      { 0x000000007fffffffLL, 0x7fffffff, true},
      { 0x0000000080000000LL, 0x7fffffff, true},
      { 0x0000000080000001LL, 0x7fffffff, true},
      { 0x00000000fffffffeLL, 0x7fffffff, true},
      { 0x00000000ffffffffLL, 0x7fffffff, true},
      { 0x0000000100000000LL, 0x7fffffff, true},
      { 0x0000000200000000LL, 0x7fffffff, true},
      { 0x7ffffffffffffffeLL, 0x7fffffff, true},
      { 0x7fffffffffffffffLL, 0x7fffffff, true},
      { 0x8000000000000000LL, 0x7fffffff, false},
      { 0x8000000000000001LL, 0x7fffffff, false},
      { 0xfffffffffffffffeLL, 0x7fffffff, true},
      { 0xffffffffffffffffLL, 0x7fffffff, true},

      { 0x0000000000000000LL, 0x80000000, true},
      { 0x0000000000000001LL, 0x80000000, true},
      { 0x0000000000000002LL, 0x80000000, true},
      { 0x000000007ffffffeLL, 0x80000000, true},
      { 0x000000007fffffffLL, 0x80000000, true},
      { 0x0000000080000000LL, 0x80000000, true},
      { 0x0000000080000001LL, 0x80000000, true},
      { 0x00000000fffffffeLL, 0x80000000, true},
      { 0x00000000ffffffffLL, 0x80000000, true},
      { 0x0000000100000000LL, 0x80000000, true},
      { 0x0000000200000000LL, 0x80000000, true},
      { 0x7ffffffffffffffeLL, 0x80000000, true},
      { 0x7fffffffffffffffLL, 0x80000000, true},
      { 0x8000000000000000LL, 0x80000000, false},
      { 0x8000000000000001LL, 0x80000000, false},
      { 0xfffffffffffffffeLL, 0x80000000, true},
      { 0xffffffffffffffffLL, 0x80000000, true},

      { 0x0000000000000000LL, 0x80000001, true},
      { 0x0000000000000001LL, 0x80000001, true},
      { 0x0000000000000002LL, 0x80000001, true},
      { 0x000000007ffffffeLL, 0x80000001, true},
      { 0x000000007fffffffLL, 0x80000001, true},
      { 0x0000000080000000LL, 0x80000001, true},
      { 0x0000000080000001LL, 0x80000001, true},
      { 0x00000000fffffffeLL, 0x80000001, true},
      { 0x00000000ffffffffLL, 0x80000001, true},
      { 0x0000000100000000LL, 0x80000001, true},
      { 0x0000000200000000LL, 0x80000001, true},
      { 0x7ffffffffffffffeLL, 0x80000001, true},
      { 0x7fffffffffffffffLL, 0x80000001, true},
      { 0x8000000000000000LL, 0x80000001, false},
      { 0x8000000000000001LL, 0x80000001, false},
      { 0xfffffffffffffffeLL, 0x80000001, true},
      { 0xffffffffffffffffLL, 0x80000001, true},

      { 0x0000000000000000LL, 0xfffffffe, true},
      { 0x0000000000000001LL, 0xfffffffe, true},
      { 0x0000000000000002LL, 0xfffffffe, true},
      { 0x000000007ffffffeLL, 0xfffffffe, true},
      { 0x000000007fffffffLL, 0xfffffffe, true},
      { 0x0000000080000000LL, 0xfffffffe, true},
      { 0x0000000080000001LL, 0xfffffffe, true},
      { 0x00000000fffffffeLL, 0xfffffffe, true},
      { 0x00000000ffffffffLL, 0xfffffffe, true},
      { 0x0000000100000000LL, 0xfffffffe, true},
      { 0x0000000200000000LL, 0xfffffffe, true},
      { 0x7ffffffffffffffeLL, 0xfffffffe, true},
      { 0x7fffffffffffffffLL, 0xfffffffe, true},
      { 0x8000000000000000LL, 0xfffffffe, false},
      { 0x8000000000000001LL, 0xfffffffe, false},
      { 0xfffffffffffffffeLL, 0xfffffffe, true},
      { 0xffffffffffffffffLL, 0xfffffffe, true},

      { 0x0000000000000000LL, 0xffffffff, true},
      { 0x0000000000000001LL, 0xffffffff, true},
      { 0x0000000000000002LL, 0xffffffff, true},
      { 0x000000007ffffffeLL, 0xffffffff, true},
      { 0x000000007fffffffLL, 0xffffffff, true},
      { 0x0000000080000000LL, 0xffffffff, true},
      { 0x0000000080000001LL, 0xffffffff, true},
      { 0x00000000fffffffeLL, 0xffffffff, true},
      { 0x00000000ffffffffLL, 0xffffffff, true},
      { 0x0000000100000000LL, 0xffffffff, true},
      { 0x0000000200000000LL, 0xffffffff, true},
      { 0x7ffffffffffffffeLL, 0xffffffff, true},
      { 0x7fffffffffffffffLL, 0xffffffff, true},
      { 0x8000000000000000LL, 0xffffffff, false},
      { 0x8000000000000001LL, 0xffffffff, false},
      { 0xfffffffffffffffeLL, 0xffffffff, true},
      { 0xffffffffffffffffLL, 0xffffffff, true},
    };

  void SubVerifyInt64Uint32()
  {
    size_t i;

    for( i = 0; i < COUNTOF(int64_uint32); ++i )
      {
        __int64 ret;
        if( SafeSubtract(int64_uint32[i].x, int64_uint32[i].y, ret) != int64_uint32[i].fExpected )
          {
            cerr << "Error in case int64_uint32: ";
            cerr << hex << setw(16) << setfill('0') << int64_uint32[i].x << ", ";
            cerr << hex << setw(8) << setfill('0') << int64_uint32[i].y << ", ";
            cerr << "expected = " << int64_uint32[i].fExpected << endl;
          }

        // Now test throwing version
        bool fSuccess = true;
        try
          {
            SafeInt<__int64> si(int64_uint32[i].x);
            si -= int64_uint32[i].y;
          }
        catch(...)
          {
            fSuccess = false;
          }

        if( fSuccess != int64_uint32[i].fExpected )
          {
            cerr << "Error in case int64_uint32 throw (1): ";
            cerr << hex << setw(16) << setfill('0') << int64_uint32[i].x << ", ";
            cerr << hex << setw(8) << setfill('0') << int64_uint32[i].y << ", ";
            cerr << "expected = " << int64_uint32[i].fExpected << endl;
          }

        // Also need to test the version that assigns back out
        // to a plain int, as it has different logic
        fSuccess = true;
        try
          {
            __int64 x(int64_uint32[i].x);
            x -= SafeInt<unsigned __int32>(int64_uint32[i].y);
          }
        catch(...)
          {
            fSuccess = false;
          }

        if( fSuccess != int64_uint32[i].fExpected )
          {
            cerr << "Error in case int64_uint32 throw (2): ";
            cerr << hex << setw(16) << setfill('0') << int64_uint32[i].x << ", ";
            cerr << hex << setw(8) << setfill('0') << int64_uint32[i].y << ", ";
            cerr << "expected = " << int64_uint32[i].fExpected << endl;
          }
      }
  }

  static const SubTest< __int64, unsigned __int16 > int64_uint16[] =
    {
      { 0x0000000000000000LL, 0x0000, true},
      { 0x0000000000000001LL, 0x0000, true},
      { 0x0000000000000002LL, 0x0000, true},
      { 0x000000007ffffffeLL, 0x0000, true},
      { 0x000000007fffffffLL, 0x0000, true},
      { 0x0000000080000000LL, 0x0000, true},
      { 0x0000000080000001LL, 0x0000, true},
      { 0x00000000fffffffeLL, 0x0000, true},
      { 0x00000000ffffffffLL, 0x0000, true},
      { 0x0000000100000000LL, 0x0000, true},
      { 0x0000000200000000LL, 0x0000, true},
      { 0x7ffffffffffffffeLL, 0x0000, true},
      { 0x7fffffffffffffffLL, 0x0000, true},
      { 0x8000000000000000LL, 0x0000, true},
      { 0x8000000000000001LL, 0x0000, true},
      { 0xfffffffffffffffeLL, 0x0000, true},
      { 0xffffffffffffffffLL, 0x0000, true},

      { 0x0000000000000000LL, 0x0001, true},
      { 0x0000000000000001LL, 0x0001, true},
      { 0x0000000000000002LL, 0x0001, true},
      { 0x000000007ffffffeLL, 0x0001, true},
      { 0x000000007fffffffLL, 0x0001, true},
      { 0x0000000080000000LL, 0x0001, true},
      { 0x0000000080000001LL, 0x0001, true},
      { 0x00000000fffffffeLL, 0x0001, true},
      { 0x00000000ffffffffLL, 0x0001, true},
      { 0x0000000100000000LL, 0x0001, true},
      { 0x0000000200000000LL, 0x0001, true},
      { 0x7ffffffffffffffeLL, 0x0001, true},
      { 0x7fffffffffffffffLL, 0x0001, true},
      { 0x8000000000000000LL, 0x0001, false},
      { 0x8000000000000001LL, 0x0001, true},
      { 0xfffffffffffffffeLL, 0x0001, true},
      { 0xffffffffffffffffLL, 0x0001, true},

      { 0x0000000000000000LL, 0x0002, true},
      { 0x0000000000000001LL, 0x0002, true},
      { 0x0000000000000002LL, 0x0002, true},
      { 0x000000007ffffffeLL, 0x0002, true},
      { 0x000000007fffffffLL, 0x0002, true},
      { 0x0000000080000000LL, 0x0002, true},
      { 0x0000000080000001LL, 0x0002, true},
      { 0x00000000fffffffeLL, 0x0002, true},
      { 0x00000000ffffffffLL, 0x0002, true},
      { 0x0000000100000000LL, 0x0002, true},
      { 0x0000000200000000LL, 0x0002, true},
      { 0x7ffffffffffffffeLL, 0x0002, true},
      { 0x7fffffffffffffffLL, 0x0002, true},
      { 0x8000000000000000LL, 0x0002, false},
      { 0x8000000000000001LL, 0x0002, false},
      { 0xfffffffffffffffeLL, 0x0002, true},
      { 0xffffffffffffffffLL, 0x0002, true},

      { 0x0000000000000000LL, 0x7ffe, true},
      { 0x0000000000000001LL, 0x7ffe, true},
      { 0x0000000000000002LL, 0x7ffe, true},
      { 0x000000007ffffffeLL, 0x7ffe, true},
      { 0x000000007fffffffLL, 0x7ffe, true},
      { 0x0000000080000000LL, 0x7ffe, true},
      { 0x0000000080000001LL, 0x7ffe, true},
      { 0x00000000fffffffeLL, 0x7ffe, true},
      { 0x00000000ffffffffLL, 0x7ffe, true},
      { 0x0000000100000000LL, 0x7ffe, true},
      { 0x0000000200000000LL, 0x7ffe, true},
      { 0x7ffffffffffffffeLL, 0x7ffe, true},
      { 0x7fffffffffffffffLL, 0x7ffe, true},
      { 0x8000000000000000LL, 0x7ffe, false},
      { 0x8000000000000001LL, 0x7ffe, false},
      { 0xfffffffffffffffeLL, 0x7ffe, true},
      { 0xffffffffffffffffLL, 0x7ffe, true},

      { 0x0000000000000000LL, 0x7fff, true},
      { 0x0000000000000001LL, 0x7fff, true},
      { 0x0000000000000002LL, 0x7fff, true},
      { 0x000000007ffffffeLL, 0x7fff, true},
      { 0x000000007fffffffLL, 0x7fff, true},
      { 0x0000000080000000LL, 0x7fff, true},
      { 0x0000000080000001LL, 0x7fff, true},
      { 0x00000000fffffffeLL, 0x7fff, true},
      { 0x00000000ffffffffLL, 0x7fff, true},
      { 0x0000000100000000LL, 0x7fff, true},
      { 0x0000000200000000LL, 0x7fff, true},
      { 0x7ffffffffffffffeLL, 0x7fff, true},
      { 0x7fffffffffffffffLL, 0x7fff, true},
      { 0x8000000000000000LL, 0x7fff, false},
      { 0x8000000000000001LL, 0x7fff, false},
      { 0xfffffffffffffffeLL, 0x7fff, true},
      { 0xffffffffffffffffLL, 0x7fff, true},

      { 0x0000000000000000LL, 0x8000, true},
      { 0x0000000000000001LL, 0x8000, true},
      { 0x0000000000000002LL, 0x8000, true},
      { 0x000000007ffffffeLL, 0x8000, true},
      { 0x000000007fffffffLL, 0x8000, true},
      { 0x0000000080000000LL, 0x8000, true},
      { 0x0000000080000001LL, 0x8000, true},
      { 0x00000000fffffffeLL, 0x8000, true},
      { 0x00000000ffffffffLL, 0x8000, true},
      { 0x0000000100000000LL, 0x8000, true},
      { 0x0000000200000000LL, 0x8000, true},
      { 0x7ffffffffffffffeLL, 0x8000, true},
      { 0x7fffffffffffffffLL, 0x8000, true},
      { 0x8000000000000000LL, 0x8000, false},
      { 0x8000000000000001LL, 0x8000, false},
      { 0xfffffffffffffffeLL, 0x8000, true},
      { 0xffffffffffffffffLL, 0x8000, true},

      { 0x0000000000000000LL, 0x8001, true},
      { 0x0000000000000001LL, 0x8001, true},
      { 0x0000000000000002LL, 0x8001, true},
      { 0x000000007ffffffeLL, 0x8001, true},
      { 0x000000007fffffffLL, 0x8001, true},
      { 0x0000000080000000LL, 0x8001, true},
      { 0x0000000080000001LL, 0x8001, true},
      { 0x00000000fffffffeLL, 0x8001, true},
      { 0x00000000ffffffffLL, 0x8001, true},
      { 0x0000000100000000LL, 0x8001, true},
      { 0x0000000200000000LL, 0x8001, true},
      { 0x7ffffffffffffffeLL, 0x8001, true},
      { 0x7fffffffffffffffLL, 0x8001, true},
      { 0x8000000000000000LL, 0x8001, false},
      { 0x8000000000000001LL, 0x8001, false},
      { 0xfffffffffffffffeLL, 0x8001, true},
      { 0xffffffffffffffffLL, 0x8001, true},

      { 0x0000000000000000LL, 0xfffe, true},
      { 0x0000000000000001LL, 0xfffe, true},
      { 0x0000000000000002LL, 0xfffe, true},
      { 0x000000007ffffffeLL, 0xfffe, true},
      { 0x000000007fffffffLL, 0xfffe, true},
      { 0x0000000080000000LL, 0xfffe, true},
      { 0x0000000080000001LL, 0xfffe, true},
      { 0x00000000fffffffeLL, 0xfffe, true},
      { 0x00000000ffffffffLL, 0xfffe, true},
      { 0x0000000100000000LL, 0xfffe, true},
      { 0x0000000200000000LL, 0xfffe, true},
      { 0x7ffffffffffffffeLL, 0xfffe, true},
      { 0x7fffffffffffffffLL, 0xfffe, true},
      { 0x8000000000000000LL, 0xfffe, false},
      { 0x8000000000000001LL, 0xfffe, false},
      { 0xfffffffffffffffeLL, 0xfffe, true},
      { 0xffffffffffffffffLL, 0xfffe, true},

      { 0x0000000000000000LL, 0xffff, true},
      { 0x0000000000000001LL, 0xffff, true},
      { 0x0000000000000002LL, 0xffff, true},
      { 0x000000007ffffffeLL, 0xffff, true},
      { 0x000000007fffffffLL, 0xffff, true},
      { 0x0000000080000000LL, 0xffff, true},
      { 0x0000000080000001LL, 0xffff, true},
      { 0x00000000fffffffeLL, 0xffff, true},
      { 0x00000000ffffffffLL, 0xffff, true},
      { 0x0000000100000000LL, 0xffff, true},
      { 0x0000000200000000LL, 0xffff, true},
      { 0x7ffffffffffffffeLL, 0xffff, true},
      { 0x7fffffffffffffffLL, 0xffff, true},
      { 0x8000000000000000LL, 0xffff, false},
      { 0x8000000000000001LL, 0xffff, false},
      { 0xfffffffffffffffeLL, 0xffff, true},
      { 0xffffffffffffffffLL, 0xffff, true},
    };

  void SubVerifyInt64Uint16()
  {
    size_t i;

    for( i = 0; i < COUNTOF(int64_uint16); ++i )
      {
        __int64 ret;
        if( SafeSubtract(int64_uint16[i].x, int64_uint16[i].y, ret) != int64_uint16[i].fExpected )
          {
            cerr << "Error in case int64_uint16: ";
            cerr << hex << setw(16) << setfill('0') << int64_uint16[i].x << ", ";
            cerr << hex << setw(4) << setfill('0') << int64_uint16[i].y << ", ";
            cerr << "expected = " << int64_uint16[i].fExpected << endl;
          }

        // Now test throwing version
        bool fSuccess = true;
        try
          {
            SafeInt<__int64> si(int64_uint16[i].x);
            si -= int64_uint16[i].y;
          }
        catch(...)
          {
            fSuccess = false;
          }

        if( fSuccess != int64_uint16[i].fExpected )
          {
            cerr << "Error in case int64_uint16 throw (1): ";
            cerr << hex << setw(16) << setfill('0') << int64_uint16[i].x << ", ";
            cerr << hex << setw(4) << setfill('0') << int64_uint16[i].y << ", ";
            cerr << "expected = " << int64_uint16[i].fExpected << endl;
          }

        // Also need to test the version that assigns back out
        // to a plain int, as it has different logic
        fSuccess = true;
        try
          {
            __int64 x(int64_uint16[i].x);
            x -= SafeInt<unsigned __int16>(int64_uint16[i].y);
          }
        catch(...)
          {
            fSuccess = false;
          }

        if( fSuccess != int64_uint16[i].fExpected )
          {
            cerr << "Error in case int64_uint16 throw (2): ";
            cerr << hex << setw(16) << setfill('0') << int64_uint16[i].x << ", ";
            cerr << hex << setw(4) << setfill('0') << int64_uint16[i].y << ", ";
            cerr << "expected = " << int64_uint16[i].fExpected << endl;
          }
      }
  }

  static const SubTest< __int64, unsigned __int8 > int64_uint8[] =
    {
      { 0x0000000000000000LL, 0x00, true},
      { 0x0000000000000001LL, 0x00, true},
      { 0x0000000000000002LL, 0x00, true},
      { 0x000000007ffffffeLL, 0x00, true},
      { 0x000000007fffffffLL, 0x00, true},
      { 0x0000000080000000LL, 0x00, true},
      { 0x0000000080000001LL, 0x00, true},
      { 0x00000000fffffffeLL, 0x00, true},
      { 0x00000000ffffffffLL, 0x00, true},
      { 0x0000000100000000LL, 0x00, true},
      { 0x0000000200000000LL, 0x00, true},
      { 0x7ffffffffffffffeLL, 0x00, true},
      { 0x7fffffffffffffffLL, 0x00, true},
      { 0x8000000000000000LL, 0x00, true},
      { 0x8000000000000001LL, 0x00, true},
      { 0xfffffffffffffffeLL, 0x00, true},
      { 0xffffffffffffffffLL, 0x00, true},

      { 0x0000000000000000LL, 0x01, true},
      { 0x0000000000000001LL, 0x01, true},
      { 0x0000000000000002LL, 0x01, true},
      { 0x000000007ffffffeLL, 0x01, true},
      { 0x000000007fffffffLL, 0x01, true},
      { 0x0000000080000000LL, 0x01, true},
      { 0x0000000080000001LL, 0x01, true},
      { 0x00000000fffffffeLL, 0x01, true},
      { 0x00000000ffffffffLL, 0x01, true},
      { 0x0000000100000000LL, 0x01, true},
      { 0x0000000200000000LL, 0x01, true},
      { 0x7ffffffffffffffeLL, 0x01, true},
      { 0x7fffffffffffffffLL, 0x01, true},
      { 0x8000000000000000LL, 0x01, false},
      { 0x8000000000000001LL, 0x01, true},
      { 0xfffffffffffffffeLL, 0x01, true},
      { 0xffffffffffffffffLL, 0x01, true},

      { 0x0000000000000000LL, 0x02, true},
      { 0x0000000000000001LL, 0x02, true},
      { 0x0000000000000002LL, 0x02, true},
      { 0x000000007ffffffeLL, 0x02, true},
      { 0x000000007fffffffLL, 0x02, true},
      { 0x0000000080000000LL, 0x02, true},
      { 0x0000000080000001LL, 0x02, true},
      { 0x00000000fffffffeLL, 0x02, true},
      { 0x00000000ffffffffLL, 0x02, true},
      { 0x0000000100000000LL, 0x02, true},
      { 0x0000000200000000LL, 0x02, true},
      { 0x7ffffffffffffffeLL, 0x02, true},
      { 0x7fffffffffffffffLL, 0x02, true},
      { 0x8000000000000000LL, 0x02, false},
      { 0x8000000000000001LL, 0x02, false},
      { 0xfffffffffffffffeLL, 0x02, true},
      { 0xffffffffffffffffLL, 0x02, true},

      { 0x0000000000000000LL, 0x7e, true},
      { 0x0000000000000001LL, 0x7e, true},
      { 0x0000000000000002LL, 0x7e, true},
      { 0x000000007ffffffeLL, 0x7e, true},
      { 0x000000007fffffffLL, 0x7e, true},
      { 0x0000000080000000LL, 0x7e, true},
      { 0x0000000080000001LL, 0x7e, true},
      { 0x00000000fffffffeLL, 0x7e, true},
      { 0x00000000ffffffffLL, 0x7e, true},
      { 0x0000000100000000LL, 0x7e, true},
      { 0x0000000200000000LL, 0x7e, true},
      { 0x7ffffffffffffffeLL, 0x7e, true},
      { 0x7fffffffffffffffLL, 0x7e, true},
      { 0x8000000000000000LL, 0x7e, false},
      { 0x8000000000000001LL, 0x7e, false},
      { 0xfffffffffffffffeLL, 0x7e, true},
      { 0xffffffffffffffffLL, 0x7e, true},

      { 0x0000000000000000LL, 0x7f, true},
      { 0x0000000000000001LL, 0x7f, true},
      { 0x0000000000000002LL, 0x7f, true},
      { 0x000000007ffffffeLL, 0x7f, true},
      { 0x000000007fffffffLL, 0x7f, true},
      { 0x0000000080000000LL, 0x7f, true},
      { 0x0000000080000001LL, 0x7f, true},
      { 0x00000000fffffffeLL, 0x7f, true},
      { 0x00000000ffffffffLL, 0x7f, true},
      { 0x0000000100000000LL, 0x7f, true},
      { 0x0000000200000000LL, 0x7f, true},
      { 0x7ffffffffffffffeLL, 0x7f, true},
      { 0x7fffffffffffffffLL, 0x7f, true},
      { 0x8000000000000000LL, 0x7f, false},
      { 0x8000000000000001LL, 0x7f, false},
      { 0xfffffffffffffffeLL, 0x7f, true},
      { 0xffffffffffffffffLL, 0x7f, true},

      { 0x0000000000000000LL, 0x80, true},
      { 0x0000000000000001LL, 0x80, true},
      { 0x0000000000000002LL, 0x80, true},
      { 0x000000007ffffffeLL, 0x80, true},
      { 0x000000007fffffffLL, 0x80, true},
      { 0x0000000080000000LL, 0x80, true},
      { 0x0000000080000001LL, 0x80, true},
      { 0x00000000fffffffeLL, 0x80, true},
      { 0x00000000ffffffffLL, 0x80, true},
      { 0x0000000100000000LL, 0x80, true},
      { 0x0000000200000000LL, 0x80, true},
      { 0x7ffffffffffffffeLL, 0x80, true},
      { 0x7fffffffffffffffLL, 0x80, true},
      { 0x8000000000000000LL, 0x80, false},
      { 0x8000000000000001LL, 0x80, false},
      { 0xfffffffffffffffeLL, 0x80, true},
      { 0xffffffffffffffffLL, 0x80, true},

      { 0x0000000000000000LL, 0x81, true},
      { 0x0000000000000001LL, 0x81, true},
      { 0x0000000000000002LL, 0x81, true},
      { 0x000000007ffffffeLL, 0x81, true},
      { 0x000000007fffffffLL, 0x81, true},
      { 0x0000000080000000LL, 0x81, true},
      { 0x0000000080000001LL, 0x81, true},
      { 0x00000000fffffffeLL, 0x81, true},
      { 0x00000000ffffffffLL, 0x81, true},
      { 0x0000000100000000LL, 0x81, true},
      { 0x0000000200000000LL, 0x81, true},
      { 0x7ffffffffffffffeLL, 0x81, true},
      { 0x7fffffffffffffffLL, 0x81, true},
      { 0x8000000000000000LL, 0x81, false},
      { 0x8000000000000001LL, 0x81, false},
      { 0xfffffffffffffffeLL, 0x81, true},
      { 0xffffffffffffffffLL, 0x81, true},

      { 0x0000000000000000LL, 0xfe, true},
      { 0x0000000000000001LL, 0xfe, true},
      { 0x0000000000000002LL, 0xfe, true},
      { 0x000000007ffffffeLL, 0xfe, true},
      { 0x000000007fffffffLL, 0xfe, true},
      { 0x0000000080000000LL, 0xfe, true},
      { 0x0000000080000001LL, 0xfe, true},
      { 0x00000000fffffffeLL, 0xfe, true},
      { 0x00000000ffffffffLL, 0xfe, true},
      { 0x0000000100000000LL, 0xfe, true},
      { 0x0000000200000000LL, 0xfe, true},
      { 0x7ffffffffffffffeLL, 0xfe, true},
      { 0x7fffffffffffffffLL, 0xfe, true},
      { 0x8000000000000000LL, 0xfe, false},
      { 0x8000000000000001LL, 0xfe, false},
      { 0xfffffffffffffffeLL, 0xfe, true},
      { 0xffffffffffffffffLL, 0xfe, true},

      { 0x0000000000000000LL, 0xff, true},
      { 0x0000000000000001LL, 0xff, true},
      { 0x0000000000000002LL, 0xff, true},
      { 0x000000007ffffffeLL, 0xff, true},
      { 0x000000007fffffffLL, 0xff, true},
      { 0x0000000080000000LL, 0xff, true},
      { 0x0000000080000001LL, 0xff, true},
      { 0x00000000fffffffeLL, 0xff, true},
      { 0x00000000ffffffffLL, 0xff, true},
      { 0x0000000100000000LL, 0xff, true},
      { 0x0000000200000000LL, 0xff, true},
      { 0x7ffffffffffffffeLL, 0xff, true},
      { 0x7fffffffffffffffLL, 0xff, true},
      { 0x8000000000000000LL, 0xff, false},
      { 0x8000000000000001LL, 0xff, false},
      { 0xfffffffffffffffeLL, 0xff, true},
      { 0xffffffffffffffffLL, 0xff, true},
    };

  void SubVerifyInt64Uint8()
  {
    size_t i;

    for( i = 0; i < COUNTOF(int64_uint8); ++i )
      {
        __int64 ret;
        if( SafeSubtract(int64_uint8[i].x, int64_uint8[i].y, ret) != int64_uint8[i].fExpected )
          {
            cerr << "Error in case int64_uint8: ";
            cerr << hex << setw(16) << setfill('0') << int64_uint8[i].x << ", ";
            cerr << hex << setw(2) << setfill('0') << (0xFF & (int)int64_uint8[i].y) << ", ";
            cerr << "expected = " << int64_uint8[i].fExpected << endl;
          }

        // Now test throwing version
        bool fSuccess = true;
        try
          {
            SafeInt<__int64> si(int64_uint8[i].x);
            si -= int64_uint8[i].y;
          }
        catch(...)
          {
            fSuccess = false;
          }

        if( fSuccess != int64_uint8[i].fExpected )
          {
            cerr << "Error in case int64_uint8 throw (1): ";
            cerr << hex << setw(16) << setfill('0') << int64_uint8[i].x << ", ";
            cerr << hex << setw(2) << setfill('0') << (0xFF & (int)int64_uint8[i].y) << ", ";
            cerr << "expected = " << int64_uint8[i].fExpected << endl;
          }

        // Also need to test the version that assigns back out
        // to a plain int, as it has different logic
        fSuccess = true;
        try
          {
            __int64 x(int64_uint8[i].x);
            x -= SafeInt<unsigned __int8>(int64_uint8[i].y);
          }
        catch(...)
          {
            fSuccess = false;
          }

        if( fSuccess != int64_uint8[i].fExpected )
          {
            cerr << "Error in case int64_uint8 throw (2): ";
            cerr << hex << setw(16) << setfill('0') << int64_uint8[i].x << ", ";
            cerr << hex << setw(2) << setfill('0') << (0xFF & (int)int64_uint8[i].y) << ", ";
            cerr << "expected = " << int64_uint8[i].fExpected << endl;
          }
      }
  }

  static const SubTest< __int8, unsigned __int64 > int8_uint64[] =
    {
      { 0x00, 0x0000000000000000ULL, true},
      { 0x01, 0x0000000000000000ULL, true},
      { 0x02, 0x0000000000000000ULL, true},
      { 0x7e, 0x0000000000000000ULL, true},
      { 0x7f, 0x0000000000000000ULL, true},
      { 0x80, 0x0000000000000000ULL, true},
      { 0x81, 0x0000000000000000ULL, true},
      { 0xfe, 0x0000000000000000ULL, true},
      { 0xff, 0x0000000000000000ULL, true},

      { 0x00, 0x0000000000000001ULL, true},
      { 0x01, 0x0000000000000001ULL, true},
      { 0x02, 0x0000000000000001ULL, true},
      { 0x7e, 0x0000000000000001ULL, true},
      { 0x7f, 0x0000000000000001ULL, true},
      { 0x80, 0x0000000000000001ULL, false},
      { 0x81, 0x0000000000000001ULL, true},
      { 0xfe, 0x0000000000000001ULL, true},
      { 0xff, 0x0000000000000001ULL, true},

      { 0x00, 0x0000000000000002ULL, true},
      { 0x01, 0x0000000000000002ULL, true},
      { 0x02, 0x0000000000000002ULL, true},
      { 0x7e, 0x0000000000000002ULL, true},
      { 0x7f, 0x0000000000000002ULL, true},
      { 0x80, 0x0000000000000002ULL, false},
      { 0x81, 0x0000000000000002ULL, false},
      { 0xfe, 0x0000000000000002ULL, true},
      { 0xff, 0x0000000000000002ULL, true},

      { 0x00, 0x000000007ffffffeULL, false},
      { 0x01, 0x000000007ffffffeULL, false},
      { 0x02, 0x000000007ffffffeULL, false},
      { 0x7e, 0x000000007ffffffeULL, false},
      { 0x7f, 0x000000007ffffffeULL, false},
      { 0x80, 0x000000007ffffffeULL, false},
      { 0x81, 0x000000007ffffffeULL, false},
      { 0xfe, 0x000000007ffffffeULL, false},
      { 0xff, 0x000000007ffffffeULL, false},

      { 0x00, 0x000000007fffffffULL, false},
      { 0x01, 0x000000007fffffffULL, false},
      { 0x02, 0x000000007fffffffULL, false},
      { 0x7e, 0x000000007fffffffULL, false},
      { 0x7f, 0x000000007fffffffULL, false},
      { 0x80, 0x000000007fffffffULL, false},
      { 0x81, 0x000000007fffffffULL, false},
      { 0xfe, 0x000000007fffffffULL, false},
      { 0xff, 0x000000007fffffffULL, false},

      { 0x00, 0x0000000080000000ULL, false},
      { 0x01, 0x0000000080000000ULL, false},
      { 0x02, 0x0000000080000000ULL, false},
      { 0x7e, 0x0000000080000000ULL, false},
      { 0x7f, 0x0000000080000000ULL, false},
      { 0x80, 0x0000000080000000ULL, false},
      { 0x81, 0x0000000080000000ULL, false},
      { 0xfe, 0x0000000080000000ULL, false},
      { 0xff, 0x0000000080000000ULL, false},

      { 0x00, 0x0000000080000001ULL, false},
      { 0x01, 0x0000000080000001ULL, false},
      { 0x02, 0x0000000080000001ULL, false},
      { 0x7e, 0x0000000080000001ULL, false},
      { 0x7f, 0x0000000080000001ULL, false},
      { 0x80, 0x0000000080000001ULL, false},
      { 0x81, 0x0000000080000001ULL, false},
      { 0xfe, 0x0000000080000001ULL, false},
      { 0xff, 0x0000000080000001ULL, false},

      { 0x00, 0x00000000fffffffeULL, false},
      { 0x01, 0x00000000fffffffeULL, false},
      { 0x02, 0x00000000fffffffeULL, false},
      { 0x7e, 0x00000000fffffffeULL, false},
      { 0x7f, 0x00000000fffffffeULL, false},
      { 0x80, 0x00000000fffffffeULL, false},
      { 0x81, 0x00000000fffffffeULL, false},
      { 0xfe, 0x00000000fffffffeULL, false},
      { 0xff, 0x00000000fffffffeULL, false},

      { 0x00, 0x00000000ffffffffULL, false},
      { 0x01, 0x00000000ffffffffULL, false},
      { 0x02, 0x00000000ffffffffULL, false},
      { 0x7e, 0x00000000ffffffffULL, false},
      { 0x7f, 0x00000000ffffffffULL, false},
      { 0x80, 0x00000000ffffffffULL, false},
      { 0x81, 0x00000000ffffffffULL, false},
      { 0xfe, 0x00000000ffffffffULL, false},
      { 0xff, 0x00000000ffffffffULL, false},

      { 0x00, 0x0000000100000000ULL, false},
      { 0x01, 0x0000000100000000ULL, false},
      { 0x02, 0x0000000100000000ULL, false},
      { 0x7e, 0x0000000100000000ULL, false},
      { 0x7f, 0x0000000100000000ULL, false},
      { 0x80, 0x0000000100000000ULL, false},
      { 0x81, 0x0000000100000000ULL, false},
      { 0xfe, 0x0000000100000000ULL, false},
      { 0xff, 0x0000000100000000ULL, false},

      { 0x00, 0x0000000200000000ULL, false},
      { 0x01, 0x0000000200000000ULL, false},
      { 0x02, 0x0000000200000000ULL, false},
      { 0x7e, 0x0000000200000000ULL, false},
      { 0x7f, 0x0000000200000000ULL, false},
      { 0x80, 0x0000000200000000ULL, false},
      { 0x81, 0x0000000200000000ULL, false},
      { 0xfe, 0x0000000200000000ULL, false},
      { 0xff, 0x0000000200000000ULL, false},

      { 0x00, 0x7ffffffffffffffeULL, false},
      { 0x01, 0x7ffffffffffffffeULL, false},
      { 0x02, 0x7ffffffffffffffeULL, false},
      { 0x7e, 0x7ffffffffffffffeULL, false},
      { 0x7f, 0x7ffffffffffffffeULL, false},
      { 0x80, 0x7ffffffffffffffeULL, false},
      { 0x81, 0x7ffffffffffffffeULL, false},
      { 0xfe, 0x7ffffffffffffffeULL, false},
      { 0xff, 0x7ffffffffffffffeULL, false},

      { 0x00, 0x7fffffffffffffffULL, false},
      { 0x01, 0x7fffffffffffffffULL, false},
      { 0x02, 0x7fffffffffffffffULL, false},
      { 0x7e, 0x7fffffffffffffffULL, false},
      { 0x7f, 0x7fffffffffffffffULL, false},
      { 0x80, 0x7fffffffffffffffULL, false},
      { 0x81, 0x7fffffffffffffffULL, false},
      { 0xfe, 0x7fffffffffffffffULL, false},
      { 0xff, 0x7fffffffffffffffULL, false},

      { 0x00, 0x8000000000000000ULL, false},
      { 0x01, 0x8000000000000000ULL, false},
      { 0x02, 0x8000000000000000ULL, false},
      { 0x7e, 0x8000000000000000ULL, false},
      { 0x7f, 0x8000000000000000ULL, false},
      { 0x80, 0x8000000000000000ULL, false},
      { 0x81, 0x8000000000000000ULL, false},
      { 0xfe, 0x8000000000000000ULL, false},
      { 0xff, 0x8000000000000000ULL, false},

      { 0x00, 0x8000000000000001ULL, false},
      { 0x01, 0x8000000000000001ULL, false},
      { 0x02, 0x8000000000000001ULL, false},
      { 0x7e, 0x8000000000000001ULL, false},
      { 0x7f, 0x8000000000000001ULL, false},
      { 0x80, 0x8000000000000001ULL, false},
      { 0x81, 0x8000000000000001ULL, false},
      { 0xfe, 0x8000000000000001ULL, false},
      { 0xff, 0x8000000000000001ULL, false},

      { 0x00, 0xfffffffffffffffeULL, false},
      { 0x01, 0xfffffffffffffffeULL, false},
      { 0x02, 0xfffffffffffffffeULL, false},
      { 0x7e, 0xfffffffffffffffeULL, false},
      { 0x7f, 0xfffffffffffffffeULL, false},
      { 0x80, 0xfffffffffffffffeULL, false},
      { 0x81, 0xfffffffffffffffeULL, false},
      { 0xfe, 0xfffffffffffffffeULL, false},
      { 0xff, 0xfffffffffffffffeULL, false},

      { 0x00, 0xffffffffffffffffULL, false},
      { 0x01, 0xffffffffffffffffULL, false},
      { 0x02, 0xffffffffffffffffULL, false},
      { 0x7e, 0xffffffffffffffffULL, false},
      { 0x7f, 0xffffffffffffffffULL, false},
      { 0x80, 0xffffffffffffffffULL, false},
      { 0x81, 0xffffffffffffffffULL, false},
      { 0xfe, 0xffffffffffffffffULL, false},
      { 0xff, 0xffffffffffffffffULL, false},
    };

  void SubVerifyInt8Uint64()
  {
    size_t i;

    for( i = 0; i < COUNTOF(int8_uint64); ++i )
      {
        __int8 ret;
        if( SafeSubtract(int8_uint64[i].x, int8_uint64[i].y, ret) != int8_uint64[i].fExpected )
          {
            cerr << "Error in case int8_uint64: ";
            cerr << hex << setw(2) << setfill('0') << (0xFF & (int)int8_uint64[i].x) << ", ";
            cerr << hex << setw(16) << setfill('0') << int8_uint64[i].y << ", ";
            cerr << "expected = " << int8_uint64[i].fExpected << endl;
          }

        // Now test throwing version
        bool fSuccess = true;
        try
          {
            SafeInt<__int8> si(int8_uint64[i].x);
            si -= int8_uint64[i].y;
          }
        catch(...)
          {
            fSuccess = false;
          }

        if( fSuccess != int8_uint64[i].fExpected )
          {
            cerr << "Error in case int8_uint64 throw (1): ";
            cerr << hex << setw(2) << setfill('0') << (0xFF & (int)int8_uint64[i].x) << ", ";
            cerr << hex << setw(16) << setfill('0') << int8_uint64[i].y << ", ";
            cerr << "expected = " << int8_uint64[i].fExpected << endl;
          }

        // Also need to test the version that assigns back out
        // to a plain int, as it has different logic
        fSuccess = true;
        try
          {
            __int8 x(int8_uint64[i].x);
            x -= SafeInt<unsigned __int64>(int8_uint64[i].y);
          }
        catch(...)
          {
            fSuccess = false;
          }

        if( fSuccess != int8_uint64[i].fExpected )
          {
            cerr << "Error in case int8_uint64 throw (2): ";
            cerr << hex << setw(2) << setfill('0') << (0xFF & (int)int8_uint64[i].x) << ", ";
            cerr << hex << setw(16) << setfill('0') << int8_uint64[i].y << ", ";
            cerr << "expected = " << int8_uint64[i].fExpected << endl;
          }
      }
  }

  static const SubTest< __int8, unsigned __int32 > int8_uint32[] =
    {
      { 0x00, 0x00000000ULL, true},
      { 0x01, 0x00000000ULL, true},
      { 0x02, 0x00000000ULL, true},
      { 0x7e, 0x00000000ULL, true},
      { 0x7f, 0x00000000ULL, true},
      { 0x80, 0x00000000ULL, true},
      { 0x81, 0x00000000ULL, true},
      { 0xfe, 0x00000000ULL, true},
      { 0xff, 0x00000000ULL, true},

      { 0x00, 0x00000001ULL, true},
      { 0x01, 0x00000001ULL, true},
      { 0x02, 0x00000001ULL, true},
      { 0x7e, 0x00000001ULL, true},
      { 0x7f, 0x00000001ULL, true},
      { 0x80, 0x00000001ULL, false},
      { 0x81, 0x00000001ULL, true},
      { 0xfe, 0x00000001ULL, true},
      { 0xff, 0x00000001ULL, true},

      { 0x00, 0x00000002ULL, true},
      { 0x01, 0x00000002ULL, true},
      { 0x02, 0x00000002ULL, true},
      { 0x7e, 0x00000002ULL, true},
      { 0x7f, 0x00000002ULL, true},
      { 0x80, 0x00000002ULL, false},
      { 0x81, 0x00000002ULL, false},
      { 0xfe, 0x00000002ULL, true},
      { 0xff, 0x00000002ULL, true},

      { 0x00, 0x7ffffffeULL, false},
      { 0x01, 0x7ffffffeULL, false},
      { 0x02, 0x7ffffffeULL, false},
      { 0x7e, 0x7ffffffeULL, false},
      { 0x7f, 0x7ffffffeULL, false},
      { 0x80, 0x7ffffffeULL, false},
      { 0x81, 0x7ffffffeULL, false},
      { 0xfe, 0x7ffffffeULL, false},
      { 0xff, 0x7ffffffeULL, false},

      { 0x00, 0x7fffffffULL, false},
      { 0x01, 0x7fffffffULL, false},
      { 0x02, 0x7fffffffULL, false},
      { 0x7e, 0x7fffffffULL, false},
      { 0x7f, 0x7fffffffULL, false},
      { 0x80, 0x7fffffffULL, false},
      { 0x81, 0x7fffffffULL, false},
      { 0xfe, 0x7fffffffULL, false},
      { 0xff, 0x7fffffffULL, false},

      { 0x00, 0x80000000ULL, false},
      { 0x01, 0x80000000ULL, false},
      { 0x02, 0x80000000ULL, false},
      { 0x7e, 0x80000000ULL, false},
      { 0x7f, 0x80000000ULL, false},
      { 0x80, 0x80000000ULL, false},
      { 0x81, 0x80000000ULL, false},
      { 0xfe, 0x80000000ULL, false},
      { 0xff, 0x80000000ULL, false},

      { 0x00, 0x80000001ULL, false},
      { 0x01, 0x80000001ULL, false},
      { 0x02, 0x80000001ULL, false},
      { 0x7e, 0x80000001ULL, false},
      { 0x7f, 0x80000001ULL, false},
      { 0x80, 0x80000001ULL, false},
      { 0x81, 0x80000001ULL, false},
      { 0xfe, 0x80000001ULL, false},
      { 0xff, 0x80000001ULL, false},

      { 0x00, 0xfffffffeULL, false},
      { 0x01, 0xfffffffeULL, false},
      { 0x02, 0xfffffffeULL, false},
      { 0x7e, 0xfffffffeULL, false},
      { 0x7f, 0xfffffffeULL, false},
      { 0x80, 0xfffffffeULL, false},
      { 0x81, 0xfffffffeULL, false},
      { 0xfe, 0xfffffffeULL, false},
      { 0xff, 0xfffffffeULL, false},

      { 0x00, 0xffffffffULL, false},
      { 0x01, 0xffffffffULL, false},
      { 0x02, 0xffffffffULL, false},
      { 0x7e, 0xffffffffULL, false},
      { 0x7f, 0xffffffffULL, false},
      { 0x80, 0xffffffffULL, false},
      { 0x81, 0xffffffffULL, false},
      { 0xfe, 0xffffffffULL, false},
      { 0xff, 0xffffffffULL, false},
    };

  void SubVerifyInt8Uint32()
  {
    size_t i;

    for( i = 0; i < COUNTOF(int8_uint32); ++i )
      {
        __int8 ret;
        if( SafeSubtract(int8_uint32[i].x, int8_uint32[i].y, ret) != int8_uint32[i].fExpected )
          {
            cerr << "Error in case int8_uint32: ";
            cerr << hex << setw(2) << setfill('0') << (0xFF & (int)int8_uint32[i].x) << ", ";
            cerr << hex << setw(8) << setfill('0') << int8_uint32[i].y << ", ";
            cerr << "expected = " << int8_uint32[i].fExpected << endl;
          }

        // Now test throwing version
        bool fSuccess = true;
        try
          {
            SafeInt<__int8> si(int8_uint32[i].x);
            si -= int8_uint32[i].y;
          }
        catch(...)
          {
            fSuccess = false;
          }

        if( fSuccess != int8_uint32[i].fExpected )
          {
            cerr << "Error in case int8_uint32 throw (1): ";
            cerr << hex << setw(2) << setfill('0') << (0xFF & (int)int8_uint32[i].x) << ", ";
            cerr << hex << setw(8) << setfill('0') << int8_uint32[i].y << ", ";
            cerr << "expected = " << int8_uint32[i].fExpected << endl;
          }

        // Also need to test the version that assigns back out
        // to a plain int, as it has different logic
        fSuccess = true;
        try
          {
            __int8 x(int8_uint32[i].x);
            x -= SafeInt<unsigned __int32>(int8_uint32[i].y);
          }
        catch(...)
          {
            fSuccess = false;
          }

        if( fSuccess != int8_uint32[i].fExpected )
          {
            cerr << "Error in case int8_uint32 throw (2): ";
            cerr << hex << setw(2) << setfill('0') << (0xFF & (int)int8_uint32[i].x) << ", ";
            cerr << hex << setw(8) << setfill('0') << int8_uint32[i].y << ", ";
            cerr << "expected = " << int8_uint32[i].fExpected << endl;
          }
      }
  }

  static const SubTest< __int8, unsigned __int16 > int8_uint16[] =
    {
      { 0x00, 0x0000ULL, true},
      { 0x01, 0x0000ULL, true},
      { 0x02, 0x0000ULL, true},
      { 0x7e, 0x0000ULL, true},
      { 0x7f, 0x0000ULL, true},
      { 0x80, 0x0000ULL, true},
      { 0x81, 0x0000ULL, true},
      { 0xfe, 0x0000ULL, true},
      { 0xff, 0x0000ULL, true},

      { 0x00, 0x0001ULL, true},
      { 0x01, 0x0001ULL, true},
      { 0x02, 0x0001ULL, true},
      { 0x7e, 0x0001ULL, true},
      { 0x7f, 0x0001ULL, true},
      { 0x80, 0x0001ULL, false},
      { 0x81, 0x0001ULL, true},
      { 0xfe, 0x0001ULL, true},
      { 0xff, 0x0001ULL, true},

      { 0x00, 0x0002ULL, true},
      { 0x01, 0x0002ULL, true},
      { 0x02, 0x0002ULL, true},
      { 0x7e, 0x0002ULL, true},
      { 0x7f, 0x0002ULL, true},
      { 0x80, 0x0002ULL, false},
      { 0x81, 0x0002ULL, false},
      { 0xfe, 0x0002ULL, true},
      { 0xff, 0x0002ULL, true},

      { 0x00, 0x7ffeULL, false},
      { 0x01, 0x7ffeULL, false},
      { 0x02, 0x7ffeULL, false},
      { 0x7e, 0x7ffeULL, false},
      { 0x7f, 0x7ffeULL, false},
      { 0x80, 0x7ffeULL, false},
      { 0x81, 0x7ffeULL, false},
      { 0xfe, 0x7ffeULL, false},
      { 0xff, 0x7ffeULL, false},

      { 0x00, 0x7fffULL, false},
      { 0x01, 0x7fffULL, false},
      { 0x02, 0x7fffULL, false},
      { 0x7e, 0x7fffULL, false},
      { 0x7f, 0x7fffULL, false},
      { 0x80, 0x7fffULL, false},
      { 0x81, 0x7fffULL, false},
      { 0xfe, 0x7fffULL, false},
      { 0xff, 0x7fffULL, false},

      { 0x00, 0x8000ULL, false},
      { 0x01, 0x8000ULL, false},
      { 0x02, 0x8000ULL, false},
      { 0x7e, 0x8000ULL, false},
      { 0x7f, 0x8000ULL, false},
      { 0x80, 0x8000ULL, false},
      { 0x81, 0x8000ULL, false},
      { 0xfe, 0x8000ULL, false},
      { 0xff, 0x8000ULL, false},

      { 0x00, 0x8001ULL, false},
      { 0x01, 0x8001ULL, false},
      { 0x02, 0x8001ULL, false},
      { 0x7e, 0x8001ULL, false},
      { 0x7f, 0x8001ULL, false},
      { 0x80, 0x8001ULL, false},
      { 0x81, 0x8001ULL, false},
      { 0xfe, 0x8001ULL, false},
      { 0xff, 0x8001ULL, false},

      { 0x00, 0xfffeULL, false},
      { 0x01, 0xfffeULL, false},
      { 0x02, 0xfffeULL, false},
      { 0x7e, 0xfffeULL, false},
      { 0x7f, 0xfffeULL, false},
      { 0x80, 0xfffeULL, false},
      { 0x81, 0xfffeULL, false},
      { 0xfe, 0xfffeULL, false},
      { 0xff, 0xfffeULL, false},

      { 0x00, 0xffffULL, false},
      { 0x01, 0xffffULL, false},
      { 0x02, 0xffffULL, false},
      { 0x7e, 0xffffULL, false},
      { 0x7f, 0xffffULL, false},
      { 0x80, 0xffffULL, false},
      { 0x81, 0xffffULL, false},
      { 0xfe, 0xffffULL, false},
      { 0xff, 0xffffULL, false},
    };

  void SubVerifyInt8Uint16()
  {
    size_t i;

    for( i = 0; i < COUNTOF(int8_uint16); ++i )
      {
        __int8 ret;
        if( SafeSubtract(int8_uint16[i].x, int8_uint16[i].y, ret) != int8_uint16[i].fExpected )
          {
            cerr << "Error in case int8_uint16: ";
            cerr << hex << setw(2) << setfill('0') << (0xFF & (int)int8_uint16[i].x) << ", ";
            cerr << hex << setw(4) << setfill('0') << int8_uint16[i].y << ", ";
            cerr << "expected = " << int8_uint16[i].fExpected << endl;
          }

        // Now test throwing version
        bool fSuccess = true;
        try
          {
            SafeInt<__int8> si(int8_uint16[i].x);
            si -= int8_uint16[i].y;
          }
        catch(...)
          {
            fSuccess = false;
          }

        if( fSuccess != int8_uint16[i].fExpected )
          {
            cerr << "Error in case int8_uint16 throw (1): ";
            cerr << hex << setw(2) << setfill('0') << (0xFF & (int)int8_uint16[i].x) << ", ";
            cerr << hex << setw(4) << setfill('0') << int8_uint16[i].y << ", ";
            cerr << "expected = " << int8_uint16[i].fExpected << endl;
          }

        // Also need to test the version that assigns back out
        // to a plain int, as it has different logic
        fSuccess = true;
        try
          {
            __int8 x(int8_uint16[i].x);
            x -= SafeInt<unsigned __int16>(int8_uint16[i].y);
          }
        catch(...)
          {
            fSuccess = false;
          }

        if( fSuccess != int8_uint16[i].fExpected )
          {
            cerr << "Error in case int8_uint16 throw (2): ";
            cerr << hex << setw(2) << setfill('0') << (0xFF & (int)int8_uint16[i].x) << ", ";
            cerr << hex << setw(4) << setfill('0') << int8_uint16[i].y << ", ";
            cerr << "expected = " << int8_uint16[i].fExpected << endl;
          }
      }
  }

  static const SubTest< __int8, unsigned __int8 > int8_uint8[] =
    {
      { 0x00, 0x00ULL, true},
      { 0x01, 0x00ULL, true},
      { 0x02, 0x00ULL, true},
      { 0x7e, 0x00ULL, true},
      { 0x7f, 0x00ULL, true},
      { 0x80, 0x00ULL, true},
      { 0x81, 0x00ULL, true},
      { 0xfe, 0x00ULL, true},
      { 0xff, 0x00ULL, true},

      { 0x00, 0x01ULL, true},
      { 0x01, 0x01ULL, true},
      { 0x02, 0x01ULL, true},
      { 0x7e, 0x01ULL, true},
      { 0x7f, 0x01ULL, true},
      { 0x80, 0x01ULL, false},
      { 0x81, 0x01ULL, true},
      { 0xfe, 0x01ULL, true},
      { 0xff, 0x01ULL, true},

      { 0x00, 0x02ULL, true},
      { 0x01, 0x02ULL, true},
      { 0x02, 0x02ULL, true},
      { 0x7e, 0x02ULL, true},
      { 0x7f, 0x02ULL, true},
      { 0x80, 0x02ULL, false},
      { 0x81, 0x02ULL, false},
      { 0xfe, 0x02ULL, true},
      { 0xff, 0x02ULL, true},

      { 0x00, 0x7eULL, true},
      { 0x01, 0x7eULL, true},
      { 0x02, 0x7eULL, true},
      { 0x7e, 0x7eULL, true},
      { 0x7f, 0x7eULL, true},
      { 0x80, 0x7eULL, false},
      { 0x81, 0x7eULL, false},
      { 0xfe, 0x7eULL, true},
      { 0xff, 0x7eULL, true},

      { 0x00, 0x7fULL, true},
      { 0x01, 0x7fULL, true},
      { 0x02, 0x7fULL, true},
      { 0x7e, 0x7fULL, true},
      { 0x7f, 0x7fULL, true},
      { 0x80, 0x7fULL, false},
      { 0x81, 0x7fULL, false},
      { 0xfe, 0x7fULL, false},
      { 0xff, 0x7fULL, true},

      { 0x00, 0x80ULL, true},
      { 0x01, 0x80ULL, true},
      { 0x02, 0x80ULL, true},
      { 0x7e, 0x80ULL, true},
      { 0x7f, 0x80ULL, true},
      { 0x80, 0x80ULL, false},
      { 0x81, 0x80ULL, false},
      { 0xfe, 0x80ULL, false},
      { 0xff, 0x80ULL, false},

      { 0x00, 0x81ULL, false},
      { 0x01, 0x81ULL, true},
      { 0x02, 0x81ULL, true},
      { 0x7e, 0x81ULL, true},
      { 0x7f, 0x81ULL, true},
      { 0x80, 0x81ULL, false},
      { 0x81, 0x81ULL, false},
      { 0xfe, 0x81ULL, false},
      { 0xff, 0x81ULL, false},

      { 0x00, 0xfeULL, false},
      { 0x01, 0xfeULL, false},
      { 0x02, 0xfeULL, false},
      { 0x7e, 0xfeULL, true},
      { 0x7f, 0xfeULL, true},
      { 0x80, 0xfeULL, false},
      { 0x81, 0xfeULL, false},
      { 0xfe, 0xfeULL, false},
      { 0xff, 0xfeULL, false},

      { 0x00, 0xffULL, false},
      { 0x01, 0xffULL, false},
      { 0x02, 0xffULL, false},
      { 0x7e, 0xffULL, false},
      { 0x7f, 0xffULL, true},
      { 0x80, 0xffULL, false},
      { 0x81, 0xffULL, false},
      { 0xfe, 0xffULL, false},
      { 0xff, 0xffULL, false},
    };

  void SubVerifyInt8Uint8()
  {
    size_t i;

    for( i = 0; i < COUNTOF(int8_uint8); ++i )
      {
        __int8 ret;
        if( SafeSubtract(int8_uint8[i].x, int8_uint8[i].y, ret) != int8_uint8[i].fExpected )
          {
            cerr << "Error in case int8_uint8: ";
            cerr << hex << setw(2) << setfill('0') << (0xFF & (int)int8_uint8[i].x) << ", ";
            cerr << hex << setw(2) << setfill('0') << (0xFF & (int)int8_uint8[i].y) << ", ";
            cerr << "expected = " << int8_uint8[i].fExpected << endl;
          }

        // Now test throwing version
        bool fSuccess = true;
        try
          {
            SafeInt<__int8> si(int8_uint8[i].x);
            si -= int8_uint8[i].y;
          }
        catch(...)
          {
            fSuccess = false;
          }

        if( fSuccess != int8_uint8[i].fExpected )
          {
            cerr << "Error in case int8_uint8 throw (1): ";
            cerr << hex << setw(2) << setfill('0') << (0xFF & (int)int8_uint8[i].x) << ", ";
            cerr << hex << setw(2) << setfill('0') << (0xFF & (int)int8_uint8[i].y) << ", ";
            cerr << "expected = " << int8_uint8[i].fExpected << endl;
          }

        // Also need to test the version that assigns back out
        // to a plain int, as it has different logic
        fSuccess = true;
        try
          {
            __int8 x(int8_uint8[i].x);
            x -= SafeInt<unsigned __int8>(int8_uint8[i].y);
          }
        catch(...)
          {
            fSuccess = false;
          }

        if( fSuccess != int8_uint8[i].fExpected )
          {
            cerr << "Error in case int8_uint8 throw (2): ";
            cerr << hex << setw(2) << setfill('0') << (0xFF & (int)int8_uint8[i].x) << ", ";
            cerr << hex << setw(2) << setfill('0') << (0xFF & (int)int8_uint8[i].y) << ", ";
            cerr << "expected = " << int8_uint8[i].fExpected << endl;
          }
      }
  }

  void SubVerify()
  {
    cout << "Verifying Subtraction:" << endl;

    // Unsigned int64, unsigned cases
    SubVerifyUint64Uint64();
    SubVerifyUint64Uint32();
    SubVerifyUint64Uint16();
    SubVerifyUint64Uint8();

    // Unsigned int64, signed cases
    SubVerifyUint64Int64();
    SubVerifyUint64Int32();
    SubVerifyUint64Int16();
    SubVerifyUint64Int8();

    /////////////////////////////////////

    // Unsigned int8, unsigned cases
    SubVerifyUint8Uint64();
    SubVerifyUint8Uint32();
    SubVerifyUint8Uint16();
    SubVerifyUint8Uint8();

    // Unsigned int8, signed cases
    SubVerifyUint8Int64();
    SubVerifyUint8Int32();
    SubVerifyUint8Int16();
    SubVerifyUint8Int8();

    /////////////////////////////////////

    // Signed int64, unsigned cases
    SubVerifyInt64Uint64();
    SubVerifyInt64Uint32();
    SubVerifyInt64Uint16();
    SubVerifyInt64Uint8();

    // Signed int64, signed cases
    SubVerifyInt64Int64();
    SubVerifyInt64Int32();
    SubVerifyInt64Int16();
    SubVerifyInt64Int8();

    /////////////////////////////////////

    // Signed int8, unsigned cases
    SubVerifyInt8Uint64();
    SubVerifyInt8Uint32();
    SubVerifyInt8Uint16();
    SubVerifyInt8Uint8();

    // Signed int8, signed cases
    SubVerifyInt8Int64();
    SubVerifyInt8Int32();
    SubVerifyInt8Int16();
    SubVerifyInt8Int8();
  }

}
