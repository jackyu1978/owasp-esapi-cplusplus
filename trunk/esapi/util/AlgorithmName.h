/**
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

// http://download.oracle.com/javase/1.4.2/docs/guide/security/jce/JCERefGuide.html#AppA
#include "EsapiCommon.h"

namespace esapi
{
  class ESAPI_EXPORT AlgorithmName
  {
  public:
    explicit AlgorithmName(const NarrowString& algorithm);
    explicit AlgorithmName(const WideString& algorithm);

    virtual ~AlgorithmName() { };

    AlgorithmName(const AlgorithmName& rhs);
    AlgorithmName& operator=(const AlgorithmName& rhs);

  public:
    void getOriginalAlgorithm(NarrowString& original) const;
    void getOriginalAlgorithm(WideString& original) const;

    void getNormalizedAlgorithm(NarrowString& normal) const;
    void getNormalizedAlgorithm(WideString& normal) const;

    bool getCipher(NarrowString& cipher) const;
    bool getCipher(WideString& cipher) const;

    bool getMode(NarrowString& mode) const;
    bool getMode(WideString& mode) const;

    bool getPadding(NarrowString& padding) const;
    bool getPadding(WideString& padding) const;

  protected:
    NarrowString normalizeAlgorithm(const NarrowString& algorithm) const;
    WideString normalizeAlgorithm(const WideString& algorithm) const;

  private:
    NarrowString m_original;
    NarrowString m_normal;
  };
} // NAMESPACE
