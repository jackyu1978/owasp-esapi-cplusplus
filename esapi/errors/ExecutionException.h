#ifndef _ExecutionException_H_
#define _ExecutionException_H_

#include <stdexcept>

// TODO: Finish Porting from Java

class ExecutionException : public std::runtime_error
{
public:
	ExecutionException(): std::runtime_error( "ExecutionException" ) {}
};

#endif /* _ExecutionException_H_ */
