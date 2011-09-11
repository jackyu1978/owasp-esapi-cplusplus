#ifndef _RandomAccessReferenceMap_h_
#define _RandomAccessReferenceMap_h_

#include <string>

#include "AccessReferenceMap.h"

namespace esapi
{
	class ESAPI_EXPORT RandomAccessReferenceMap : AccessReferenceMap
	{
	protected:

		virtual std::string getUniqueReference() =0;

	private:
		virtual ~RandomAccessReferenceMap() {};
	};
};

#endif /** _RandomAccessReferenceMap_h_ */

