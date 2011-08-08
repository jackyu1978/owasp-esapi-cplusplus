/*
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see * http://www.owasp.org/index.php/ESAPI.
 *
 * Copyright (c) 2011 - The OWASP Foundation
 *
 * @author Kevin Wall, kevin.w.wall@gmail.com
 * @author Jeffrey Walton, noloader@gmail.com
 *
 */

void VerifySecretKey();
void VerifyKeyGenerator();
void VerifyCryptoHelper();
void VerifySecureRandom();
void VerifyKeyDerivationFunction();

int main(int, char**)
{
	VerifySecretKey();
	VerifyKeyGenerator();
	VerifyCryptoHelper();
	VerifySecureRandom();
    VerifyKeyDerivationFunction();

    return 0;
}

