#ifndef _EncodingException_H_
#define _EncodingException_H_

#include <stdexcept>

// TODO: Finish Porting from Java

class EncodingException : public std::runtime_error
{
public:
	EncodingException(): std::runtime_error( "EncodingException" ) {}
};

#endif /* _EncodingException_H_ */
