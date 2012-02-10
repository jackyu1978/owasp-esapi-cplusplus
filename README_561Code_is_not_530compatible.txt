In the process of creating the Visual Studio project files 
I found various pieces of the esapi code that used 5.6.1 features 
that were not compatible with 5.3.0.

I revised the code to maintain 5.3.0 compatabilty as noted below.


- jAHOLMES (starfyr@jholmesassociates.com) 2012.01.22

===========================================================================

DefaultEncryptor.cpp
	Line 83		Uses ArraySource instead of StringSource
	typedef equating them is defined only in 5.6.1  (filters.h)
Workaround:
	use StringSource directly instead of ArraySource

SecretKey.cpp
	Line 136	Uses ArraySource instead of StringSource
	Same as DefaultEncryptor above

MessageDigestImpl.cpp
	Line 32		Uses CryptoPP::Weak::MD5
	Line 401	Explicit template instantiation
	5.30  defines class MD5
	5.6.1 defines it inside the namespace Weak	(md5.h)
Workaround:
	use MD5 directly, rather than Weak::MD5


KeyDerivationFunction.cpp
	Line 219	Uses SecByteBloc::BytePtr
	5.30 	has no definition for BytePtr
	5.6.1   defines BytePtr				(secblock.h)

Workaround:
	Both 5.3.0  and 5.6.1 
	secblock.h defines typedef SecBlock<byte> SecByteBlock;

	SecBlock<T>  defines operator T *()  as returning a pointer of T, 
		which is equivalent to BytePtr, if not terribly explicit

SecretKey.cpp
	Line  34
	Line 118
	Line 119
	Same as KeyDerivationFunction above


Crypto++Common.h
	includes eax.h		does not exist in 5.3.0
	includes ccm.h		does not exist in 5.3.0
	includes gcm.h		does not exist in 5.3.0


Just so we don't lose anything if there was a real need to use the newer functions,
for now I'll mark the changes like so: 

#if ( CRYPTOPP_VERSION == 530 )
        
	//  do something 530 ish

#elif ( CRYPTOPP_VERSION == 561 )
        
	// do something 561 ish
#else

#error Need to define CRYPTOPP_VERSION (530 or 561 currently supported)

#endif


