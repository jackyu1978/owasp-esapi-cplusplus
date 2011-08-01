#ifndef _IntrustionException_H_
#define _IntrustionException_H_

#include <stdexcept>

// TODO: Finish Porting from Java

class IntrusionException : public std::runtime_error
{
public:
	IntrusionException::IntrusionException(): std::runtime_error( "Intrusion Exception" ) {}
};

#endif /* _IntrustionException_H_ */
