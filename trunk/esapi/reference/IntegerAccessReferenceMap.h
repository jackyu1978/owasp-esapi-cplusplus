#ifndef _IntegerAccessReferenceMap_h_
#define _IntegerAccessReferenceMap_h_

#include <string>

#include "AccessReferenceMap.h"

namespace esapi
{
	class IntegerAccessReferenceMap : AccessReferenceMap
	{
	protected:

		virtual std::string getUniqueReference() =0;

	private:
		int count = 1;

		virtual ~IntegerAccessReferenceMap() {};
	};
};

#endif /* _IntegerAccessReferenceMap_h_ */
