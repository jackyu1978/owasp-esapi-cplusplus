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
const Char EncoderConstants::CHAR_PASSWORD_SPECIALS[] = { '!', '$', '*', '-', '.', '=', '?', '@', '_' };
const std::set<Char> EncoderConstants::PASSWORD_SPECIALS (EncoderConstants::CHAR_PASSWORD_SPECIALS, EncoderConstants::CHAR_PASSWORD_SPECIALS+( sizeof(EncoderConstants::CHAR_PASSWORD_SPECIALS)/sizeof(Char) ) );

const Char EncoderConstants::CHAR_LOWERS[] = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };
const std::set<Char> EncoderConstants::LOWERS (EncoderConstants::CHAR_LOWERS, EncoderConstants::CHAR_LOWERS+( sizeof(EncoderConstants::CHAR_LOWERS)/sizeof(Char) ) );

const Char EncoderConstants::CHAR_UPPERS[] = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z' };
const std::set<Char> EncoderConstants::UPPERS (EncoderConstants::CHAR_UPPERS, EncoderConstants::CHAR_UPPERS+( sizeof(EncoderConstants::CHAR_UPPERS)/sizeof(Char) ) );

const Char EncoderConstants::CHAR_DIGITS[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9' };
const std::set<Char> EncoderConstants::DIGITS (EncoderConstants::CHAR_DIGITS, EncoderConstants::CHAR_DIGITS+( sizeof(EncoderConstants::CHAR_DIGITS)/sizeof(Char) ) );

const Char EncoderConstants::CHAR_SPECIALS[] = { '!', '$', '*', '+', '-', '.', '=', '?', '@', '^', '_', '|', '~' };
const std::set<Char> EncoderConstants::SPECIALS (EncoderConstants::CHAR_SPECIALS, EncoderConstants::CHAR_SPECIALS+( sizeof(EncoderConstants::CHAR_SPECIALS)/sizeof(Char) ) );

const Char EncoderConstants::CHAR_LETTERS[] = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z' };
const std::set<Char> EncoderConstants::LETTERS (EncoderConstants::CHAR_LETTERS, EncoderConstants::CHAR_LETTERS+( sizeof(EncoderConstants::CHAR_LETTERS)/sizeof(Char) ) );

const Char EncoderConstants::CHAR_ALPHANUMERICS[] = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9' };
const std::set<Char> EncoderConstants::ALPHANUMERICS (EncoderConstants::CHAR_ALPHANUMERICS, EncoderConstants::CHAR_ALPHANUMERICS+( sizeof(EncoderConstants::CHAR_ALPHANUMERICS)/sizeof(Char) ) );

const Char EncoderConstants::CHAR_PASSWORD_LOWERS[] = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'j', 'k', 'm', 'n', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };
const std::set<Char> EncoderConstants::PASSWORD_LOWERS (EncoderConstants::CHAR_PASSWORD_LOWERS, EncoderConstants::CHAR_PASSWORD_LOWERS+( sizeof(EncoderConstants::CHAR_PASSWORD_LOWERS)/sizeof(Char) ) );

const Char EncoderConstants::CHAR_PASSWORD_UPPERS[] = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'J', 'K', 'L', 'M', 'N', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z' };
const std::set<Char> EncoderConstants::PASSWORD_UPPERS (EncoderConstants::CHAR_PASSWORD_UPPERS, EncoderConstants::CHAR_PASSWORD_UPPERS+( sizeof(EncoderConstants::CHAR_PASSWORD_UPPERS)/sizeof(Char) ) );

const Char EncoderConstants::CHAR_PASSWORD_DIGITS[] = { '2', '3', '4', '5', '6', '7', '8', '9' };
const std::set<Char> EncoderConstants::PASSWORD_DIGITS (EncoderConstants::CHAR_PASSWORD_DIGITS, EncoderConstants::CHAR_PASSWORD_DIGITS+( sizeof(EncoderConstants::CHAR_PASSWORD_DIGITS)/sizeof(Char) ) );

const Char EncoderConstants::CHAR_PASSWORD_LETTERS[] = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'j', 'k', 'm', 'n', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'J', 'K', 'L', 'M', 'N', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z' };
const std::set<Char> EncoderConstants::PASSWORD_LETTERS (EncoderConstants::CHAR_PASSWORD_LETTERS, EncoderConstants::CHAR_PASSWORD_LETTERS+( sizeof(EncoderConstants::CHAR_PASSWORD_LETTERS)/sizeof(Char) ) );

} // esapi