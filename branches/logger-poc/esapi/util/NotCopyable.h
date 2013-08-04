/*
* OWASP Enterprise Security API (ESAPI)
*
* This file is part of the Open Web Application Security Project (OWASP)
* Enterprise Security API (ESAPI) project. For details, please see
* <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
*
* Copyright (c) 2011 - The OWASP Foundation
*
* @author Kevin Wall, kevin.w.wall@gmail.com
* @author Jeffrey Walton, noloader@gmail.com
*/

#pragma once

/**
* From Meyers' Effective C++ (3ed), Item 6, p.39. Diverge from
* a non-virtual destructor to keep warnings to a minimum.
*/
namespace esapi
{
  class NotCopyable
  {
  protected:
    NotCopyable() { };
    ~NotCopyable() { };
  private:
    NotCopyable(const NotCopyable&);
    NotCopyable& operator=(const NotCopyable&);
  };
}

