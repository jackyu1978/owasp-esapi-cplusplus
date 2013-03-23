/**
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * http://www.owasp.org/index.php/ESAPI.
 *
 * Copyright (c) 2011 - The OWASP Foundation
 *
 * @author Kevin Wall, kevin.w.wall@gmail.com
 * @author Jeffrey Walton, noloader@gmail.com
 * @author Daniel Amodio, dan.amodio@aspectsecurity.com
 * @author Andrew Durkin, atdurkin@gmail.com
 *
 */

#include <string>

namespace esapi
{
  typedef wchar_t WideChar;
  typedef std::wstring WideString;
  typedef std::wstringstream WideStringStream;

  typedef char NarrowChar;
  typedef std::string NarrowString;
  typedef std::stringstream NarrowStringStream;

  typedef NarrowChar Char;
  typedef NarrowString String;
  typedef NarrowStringStream StringStream;

  typedef std::vector<String> StringArray;
  typedef std::list<String> StringList;
  // typedef std::map<String> StringMap;

} // NAMESPACE

