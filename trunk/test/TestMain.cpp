void VerifySecretKey();
void VerifyCryptoHelper();
void VerifyKeyDerivationFunction();

int main(int, char**)
{
	VerifySecretKey();
	VerifyCryptoHelper();
    VerifyKeyDerivationFunction();

    return 0;
}

