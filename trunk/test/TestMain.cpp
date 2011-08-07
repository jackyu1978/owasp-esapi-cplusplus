void VerifySecretKey();
void VerifyKeyGenerator();
void VerifyCryptoHelper();
void VerifyKeyDerivationFunction();

int main(int, char**)
{
	VerifySecretKey();
	VerifyKeyGenerator();
	VerifyCryptoHelper();
    VerifyKeyDerivationFunction();

    return 0;
}

