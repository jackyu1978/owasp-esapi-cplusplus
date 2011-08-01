#include "esapi/EncoderConstants.h"
#include <string>


const char esapi::EncoderConstants::CHAR_PASSWORD_SPECIALS[] = { '!', '$', '*', '-', '.', '=', '?', '@', '_' };
const std::set<char> esapi::EncoderConstants::PASSWORD_SPECIALS (esapi::EncoderConstants::CHAR_PASSWORD_SPECIALS, esapi::EncoderConstants::CHAR_PASSWORD_SPECIALS+( sizeof(esapi::EncoderConstants::CHAR_PASSWORD_SPECIALS)/sizeof(char) ) );

const char esapi::EncoderConstants::CHAR_LOWERS[] = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };
const std::set<char> esapi::EncoderConstants::LOWERS (esapi::EncoderConstants::CHAR_LOWERS, esapi::EncoderConstants::CHAR_LOWERS+( sizeof(esapi::EncoderConstants::CHAR_LOWERS)/sizeof(char) ) );

const char esapi::EncoderConstants::CHAR_UPPERS[] = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z' };
const std::set<char> esapi::EncoderConstants::UPPERS (esapi::EncoderConstants::CHAR_UPPERS, esapi::EncoderConstants::CHAR_UPPERS+( sizeof(esapi::EncoderConstants::CHAR_UPPERS)/sizeof(char) ) );

const char esapi::EncoderConstants::CHAR_DIGITS[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9' };
const std::set<char> esapi::EncoderConstants::DIGITS (esapi::EncoderConstants::CHAR_DIGITS, esapi::EncoderConstants::CHAR_DIGITS+( sizeof(esapi::EncoderConstants::CHAR_DIGITS)/sizeof(char) ) );

const char esapi::EncoderConstants::CHAR_SPECIALS[] = { '!', '$', '*', '+', '-', '.', '=', '?', '@', '^', '_', '|', '~' };
const std::set<char> esapi::EncoderConstants::SPECIALS (esapi::EncoderConstants::CHAR_SPECIALS, esapi::EncoderConstants::CHAR_SPECIALS+( sizeof(esapi::EncoderConstants::CHAR_SPECIALS)/sizeof(char) ) );

const char esapi::EncoderConstants::CHAR_LETTERS[] = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z' };
const std::set<char> esapi::EncoderConstants::LETTERS (esapi::EncoderConstants::CHAR_LETTERS, esapi::EncoderConstants::CHAR_LETTERS+( sizeof(esapi::EncoderConstants::CHAR_LETTERS)/sizeof(char) ) );

const char esapi::EncoderConstants::CHAR_ALPHANUMERICS[] = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9' };
const std::set<char> esapi::EncoderConstants::ALPHANUMERICS (esapi::EncoderConstants::CHAR_ALPHANUMERICS, esapi::EncoderConstants::CHAR_ALPHANUMERICS+( sizeof(esapi::EncoderConstants::CHAR_ALPHANUMERICS)/sizeof(char) ) );

const char esapi::EncoderConstants::CHAR_PASSWORD_LOWERS[] = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'j', 'k', 'm', 'n', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };
const std::set<char> esapi::EncoderConstants::PASSWORD_LOWERS (esapi::EncoderConstants::CHAR_PASSWORD_LOWERS, esapi::EncoderConstants::CHAR_PASSWORD_LOWERS+( sizeof(esapi::EncoderConstants::CHAR_PASSWORD_LOWERS)/sizeof(char) ) );

const char esapi::EncoderConstants::CHAR_PASSWORD_UPPERS[] = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'J', 'K', 'L', 'M', 'N', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z' };
const std::set<char> esapi::EncoderConstants::PASSWORD_UPPERS (esapi::EncoderConstants::CHAR_PASSWORD_UPPERS, esapi::EncoderConstants::CHAR_PASSWORD_UPPERS+( sizeof(esapi::EncoderConstants::CHAR_PASSWORD_UPPERS)/sizeof(char) ) );

const char esapi::EncoderConstants::CHAR_PASSWORD_DIGITS[] = { '2', '3', '4', '5', '6', '7', '8', '9' };
const std::set<char> esapi::EncoderConstants::PASSWORD_DIGITS (esapi::EncoderConstants::CHAR_PASSWORD_DIGITS, esapi::EncoderConstants::CHAR_PASSWORD_DIGITS+( sizeof(esapi::EncoderConstants::CHAR_PASSWORD_DIGITS)/sizeof(char) ) );

const char esapi::EncoderConstants::CHAR_PASSWORD_LETTERS[] = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'j', 'k', 'm', 'n', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'J', 'K', 'L', 'M', 'N', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z' };
const std::set<char> esapi::EncoderConstants::PASSWORD_LETTERS (esapi::EncoderConstants::CHAR_PASSWORD_LETTERS, esapi::EncoderConstants::CHAR_PASSWORD_LETTERS+( sizeof(esapi::EncoderConstants::CHAR_PASSWORD_LETTERS)/sizeof(char) ) );
