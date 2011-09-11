#ifndef _IntegerAccessReferenceMap_h_
#define _IntegerAccessReferenceMap_h_

#include <string>

#include "AccessReferenceMap.h"

namespace esapi
{
	class ESAPI_EXPORT IntegerAccessReferenceMap : AccessReferenceMap
	{
	protected:

		virtual std::string getUniqueReference() =0;

	private:
		int count;

		virtual ~IntegerAccessReferenceMap() {};
	};
};

#endif /** _IntegerAccessReferenceMap_h_ */

