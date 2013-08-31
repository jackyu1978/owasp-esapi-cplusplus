#include "util/LogFactory.h"


namespace esapi {

LogFactory *LogFactory::FactoryInstance = NULL;
Mutex 		 LogFactory::InstanceLock;
bool 			 LogFactory::Flushing = false;

LogFactory::LogFactory()
{
	ChannelList.clear();

	return;
}
LogFactory::~LogFactory()
{
	//loop through the list of channels
	//flush data on channels
	//sets log factory instance to null
	//empty channels list
	
	//delect lock object
	
	ChannelList.clear();
	return;
}

void LogFactory::close()
{
	MutexLock  lock(InstanceLock);

	FactoryInstance->flush();
	delete FactoryInstance;
	FactoryInstance = NULL;

	//flush channels
	//sets log factory instance to null
	//empty channels list
	//delete lock object
	return;
}

LogFactory *LogFactory::getInstance()
{
	//obtains a lock
	//return factory instance if set
	//else create a new instance 
	//set it to factory instance
	//return factory instance
	
	MutexLock lock(InstanceLock);
	
	if (FactoryInstance == NULL) 
		FactoryInstance = new LogFactory();	
	
	return FactoryInstance;
}

LogFactory &LogFactory::addChannel(LogChannel *channel)
{
	//obtain a lock 
	//add the desired channel
	//remove lock	
	//MutexLock lock(InstanceLock.getMutex());
	ChannelList.push_back(channel);
	return *this;
}

/*
LogFactory &LogFactory::removeChannel()
{
	//obtain a lock 
	//add desired channel
	//remove lock
}
*/

void LogFactory::flush()
{
	if (LogFactory::Flushing) return;

	LogFactory::Flushing = true;

	std::vector<std::string> *logslice = extractLog();
	std::vector<LogChannel *>::const_iterator channel_iter = ChannelList.begin();
	
	while (channel_iter != ChannelList.end()) {
		if (!(*channel_iter)->channelOk()) {
			LogFactory::Flushing = false; 
			throw std::runtime_error("Corrupt log channel");
		}

		(*channel_iter)->writeLogs(*logslice);
		(*channel_iter)->flush();
		channel_iter++;
	}

	delete logslice;
	LogFactory::Flushing = false;

	return;

	//return if flush is in progress	
	//pop messages off the queue
	//buffer messages
	//iterate through all channels 
	//write logs to channels
	//return
	return;
}

std::vector<std::string> *LogFactory::extractLog()
{
	//get the size of the queue
	//slice of the head to the size
	//create a queue of the new size
	// return the new queue
	
	std::vector<std::string> *logslice = new std::vector<std::string>();
	//@Todo
	//change from the usage of size to the use end() iterator
	for (int x = (int)LogQueue.size(); x > 0; x--) {
		logslice->push_back(LogQueue.front());
		LogQueue.pop();
	}

	return logslice;
}

}
