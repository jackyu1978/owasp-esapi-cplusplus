#ifndef _IntegrityException_H_
#define _IntegrityException_H_

#include <stdexcept>

// TODO: Finish Porting from Java

class IntegrityException : public std::runtime_error
{
public:
	IntegrityException(): std::runtime_error( "IntegrityException" ) {}
};

#endif /* _IntegrityException_H_ */
