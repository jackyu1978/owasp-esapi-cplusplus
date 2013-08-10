/*
 *
 *
 */
#ifndef LOGFACTORY_H
#define LOGFACTORY_H

#include <vector>
#include <queue>
#include "util/Mutex.h"
#include "util/NotCopyable.h"
#include <stringstream>

namesapce esapi 
{

	class ESAPI_EXPORT LogFactory: private NotCopyable
	{
		public:
			~LogFactory()
			static LogFactory *getInstance();
			static void				 close();
	
			LogFactory &addChannel();
			//LogFactory &removeChannel()
			void			 flush();
			Logger		 *getLogger
			string		 extractLog();
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
