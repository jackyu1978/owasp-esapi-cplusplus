/**
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * http://www.owasp.org/index.php/ESAPI.
 *
 * Copyright (c) 2011 - The OWASP Foundation
 */

#include "EsapiCommon.h"
#include "EncoderConstants.h"

namespace esapi
{
  const Char EncoderConstants::CHAR_PASSWORD_SPECIALS[] = { L'!', L'$', L'*', L'-', L'.', L'=', L'?', L'@', L'_' };
  const std::set<Char> EncoderConstants::PASSWORD_SPECIALS (EncoderConstants::CHAR_PASSWORD_SPECIALS, EncoderConstants::CHAR_PASSWORD_SPECIALS+( sizeof(EncoderConstants::CHAR_PASSWORD_SPECIALS)/sizeof(Char) ) );

  const Char EncoderConstants::CHAR_LOWERS[] = { L'a', L'b', L'c', L'd', L'e', L'f', L'g', L'h', L'i', L'j', L'k', L'l', L'm', L'n', L'o', L'p', L'q', L'r', L's', L't', L'u', L'v', L'w', L'x', L'y', L'z' };
  const std::set<Char> EncoderConstants::LOWERS (EncoderConstants::CHAR_LOWERS, EncoderConstants::CHAR_LOWERS+( sizeof(EncoderConstants::CHAR_LOWERS)/sizeof(Char) ) );

  const Char EncoderConstants::CHAR_UPPERS[] = { L'A', L'B', L'C', L'D', L'E', L'F', L'G', L'H', L'I', L'J', L'K', L'L', L'M', L'N', L'O', L'P', L'Q', L'R', L'S', L'T', L'U', L'V', L'W', L'X', L'Y', L'Z' };
  const std::set<Char> EncoderConstants::UPPERS (EncoderConstants::CHAR_UPPERS, EncoderConstants::CHAR_UPPERS+( sizeof(EncoderConstants::CHAR_UPPERS)/sizeof(Char) ) );

  const Char EncoderConstants::CHAR_DIGITS[] = { L'0', L'1', L'2', L'3', L'4', L'5', L'6', L'7', L'8', L'9' };
  const std::set<Char> EncoderConstants::DIGITS (EncoderConstants::CHAR_DIGITS, EncoderConstants::CHAR_DIGITS+( sizeof(EncoderConstants::CHAR_DIGITS)/sizeof(Char) ) );

  const Char EncoderConstants::CHAR_SPECIALS[] = { L'!', L'$', L'*', L'+', L'-', L'.', L'=', L'?', L'@', L'^', L'_', L'|', L'~' };
  const std::set<Char> EncoderConstants::SPECIALS (EncoderConstants::CHAR_SPECIALS, EncoderConstants::CHAR_SPECIALS+( sizeof(EncoderConstants::CHAR_SPECIALS)/sizeof(Char) ) );

  const Char EncoderConstants::CHAR_LETTERS[] = { L'a', L'b', L'c', L'd', L'e', L'f', L'g', L'h', L'i', L'j', L'k', L'l', L'm', L'n', L'o', L'p', L'q', L'r', L's', L't', L'u', L'v', L'w', L'x', L'y', L'z', L'A', L'B', L'C', L'D', L'E', L'F', L'G', L'H', L'I', L'J', L'K', L'L', L'M', L'N', L'O', L'P', L'Q', L'R', L'S', L'T', L'U', L'V', L'W', L'X', L'Y', L'Z' };
  const std::set<Char> EncoderConstants::LETTERS (EncoderConstants::CHAR_LETTERS, EncoderConstants::CHAR_LETTERS+( sizeof(EncoderConstants::CHAR_LETTERS)/sizeof(Char) ) );

  const Char EncoderConstants::CHAR_ALPHANUMERICS[] = { L'a', L'b', L'c', L'd', L'e', L'f', L'g', L'h', L'i', L'j', L'k', L'l', L'm', L'n', L'o', L'p', L'q', L'r', L's', L't', L'u', L'v', L'w', L'x', L'y', L'z', L'A', L'B', L'C', L'D', L'E', L'F', L'G', L'H', L'I', L'J', L'K', L'L', L'M', L'N', L'O', L'P', L'Q', L'R', L'S', L'T', L'U', L'V', L'W', L'X', L'Y', L'Z', L'0', L'1', L'2', L'3', L'4', L'5', L'6', L'7', L'8', L'9' };
  const std::set<Char> EncoderConstants::ALPHANUMERICS (EncoderConstants::CHAR_ALPHANUMERICS, EncoderConstants::CHAR_ALPHANUMERICS+( sizeof(EncoderConstants::CHAR_ALPHANUMERICS)/sizeof(Char) ) );

  const Char EncoderConstants::CHAR_PASSWORD_LOWERS[] = { L'a', L'b', L'c', L'd', L'e', L'f', L'g', L'h', L'j', L'k', L'm', L'n', L'p', L'q', L'r', L's', L't', L'u', L'v', L'w', L'x', L'y', L'z' };
  const std::set<Char> EncoderConstants::PASSWORD_LOWERS (EncoderConstants::CHAR_PASSWORD_LOWERS, EncoderConstants::CHAR_PASSWORD_LOWERS+( sizeof(EncoderConstants::CHAR_PASSWORD_LOWERS)/sizeof(Char) ) );

  const Char EncoderConstants::CHAR_PASSWORD_UPPERS[] = { L'A', L'B', L'C', L'D', L'E', L'F', L'G', L'H', L'J', L'K', L'L', L'M', L'N', L'P', L'Q', L'R', L'S', L'T', L'U', L'V', L'W', L'X', L'Y', L'Z' };
  const std::set<Char> EncoderConstants::PASSWORD_UPPERS (EncoderConstants::CHAR_PASSWORD_UPPERS, EncoderConstants::CHAR_PASSWORD_UPPERS+( sizeof(EncoderConstants::CHAR_PASSWORD_UPPERS)/sizeof(Char) ) );

  const Char EncoderConstants::CHAR_PASSWORD_DIGITS[] = { L'2', L'3', L'4', L'5', L'6', L'7', L'8', L'9' };
  const std::set<Char> EncoderConstants::PASSWORD_DIGITS (EncoderConstants::CHAR_PASSWORD_DIGITS, EncoderConstants::CHAR_PASSWORD_DIGITS+( sizeof(EncoderConstants::CHAR_PASSWORD_DIGITS)/sizeof(Char) ) );

  const Char EncoderConstants::CHAR_PASSWORD_LETTERS[] = { L'a', L'b', L'c', L'd', L'e', L'f', L'g', L'h', L'j', L'k', L'm', L'n', L'p', L'q', L'r', L's', L't', L'u', L'v', L'w', L'x', L'y', L'z', L'A', L'B', L'C', L'D', L'E', L'F', L'G', L'H', L'J', L'K', L'L', L'M', L'N', L'P', L'Q', L'R', L'S', L'T', L'U', L'V', L'W', L'X', L'Y', L'Z' };
  const std::set<Char> EncoderConstants::PASSWORD_LETTERS (EncoderConstants::CHAR_PASSWORD_LETTERS, EncoderConstants::CHAR_PASSWORD_LETTERS+( sizeof(EncoderConstants::CHAR_PASSWORD_LETTERS)/sizeof(Char) ) );

} // esapi