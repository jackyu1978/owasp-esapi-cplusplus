/*
 *
 *
 */
#ifndef LOGFACTORY_H
#define LOGFACTORY_H

#include <vector>
#include <queue>
#include <string>
#include "util/Mutex.h"
#include "util/NotCopyable.h"
#include <sstream>
#include "util/LogChannelInterface.h"
#
namespace esapi
{

	class ESAPI_EXPORT LogFactory: private NotCopyable
	{
		public:
			~LogFactory();
			static LogFactory *getInstance();
			static void				 close();
	
			LogFactory &addChannel(LogChannel *);
			//LogFactory &removeChannel()
			void			 flush();
			std::vector<std::string>	*extractLog();
			void 			 queueLog(std::string);

		private:
			LogFactory();
			//LogFactory(LogFactory &) {};
			//LogFactory operator =(LogFactory &) {};
	
			std::vector<LogChannel *> ChannelList;
			std::queue<std::string> LogQueue;
			
			static LogFactory *FactoryInstance;
			static Mutex InstanceLock;
			//static Mutex ChannelLock;
			static bool	 Flushing;
			
	};

} //esapi namespace

#endif
