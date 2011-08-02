#ifndef _EncryptionException_H_
#define _EncryptionException_H_

#include <stdexcept>

// TODO: Finish Porting from Java

class EncryptionException : public std::runtime_error
{
public:
	EncryptionException(): std::runtime_error( "EncryptionException" ) {}
};

#endif /* _EncryptionException_H_ */
