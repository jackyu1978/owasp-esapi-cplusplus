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

    /**
     * Normailize the algorithm name. If the algorithm is recognized, it is
     * returned conformant to JCE, Appendix A. If it is not recognized, a
     * NoSuchAlgorithmException is thrown.
     */
    static NarrowString normalizeAlgorithm(const NarrowString& algorithm);

    /**
     * Normailize the algorithm name. If the algorithm is recognized, it is
     * returned conformant to JCE, Appendix A. If it is not recognized, a
     * NoSuchAlgorithmException is thrown.
     */
    static WideString normalizeAlgorithm(const WideString& algorithm);

  public:

    /**
     * Construct an AlgorithmName object.
     */
    explicit AlgorithmName(const NarrowString& algorithm);

    /**
     * Construct an AlgorithmName object.
     */
    explicit AlgorithmName(const WideString& algorithm);

    /**
     * Destroy an AlgorithmName object.
     */
    virtual ~AlgorithmName() { };

    /**
     * Copy an AlgorithmName object.
     */
    AlgorithmName(const AlgorithmName& rhs);

    /**
     * Assign an AlgorithmName object.
     */
    AlgorithmName& operator=(const AlgorithmName& rhs);

    /**
     * Returns the normalized name per JCE, Appendix A.
     */
    NarrowString algorithm() const { return m_normal; }

  public:

    /**
     * Returns the normalized algorithm name per JCE, Appendix A.
     */
    void getNormalizedAlgorithm(NarrowString& normal) const;

    /**
     * Returns the normalized algorithm name per JCE, Appendix A.
     */
    void getNormalizedAlgorithm(WideString& normal) const;

    /**
     * Returns the cipher portion of the normalized algorithm name per JCE, Appendix A.
     */
    bool getCipher(NarrowString& cipher) const;

    /**
     * Returns the cipher portion of the normalized algorithm name per JCE, Appendix A.
     */
    bool getCipher(WideString& cipher) const;

    /**
     * Returns the mode portion of the normalized algorithm name per
     * JCE, Appendix A. If false is returned, the mode was not present
     * and an empty string is returned.
     */
    bool getMode(NarrowString& mode) const;

    /**
     * Returns the mode portion of the normalized algorithm name per
     * JCE, Appendix A. If false is returned, the mode was not present
     * and an empty string is returned.
     */
    bool getMode(WideString& mode) const;

    /**
     * Returns the padding portion of the normalized algorithm name per
     * JCE, Appendix A. If false is returned, the padding was not present
     * and an empty string is returned.
     */
    bool getPadding(NarrowString& padding) const;

    /**
     * Returns the padding portion of the normalized algorithm name per
     * JCE, Appendix A. If false is returned, the padding was not present
     * and an empty string is returned.
     */
    bool getPadding(WideString& padding) const;

  private:
    NarrowString m_normal;
  };
} // NAMESPACE
