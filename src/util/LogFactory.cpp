#include "LogFactory.h"


namespace esapi {

LogFactory::FactoryInstance = NULL;
LogFactory::InstanceLock:
LogFactory::InstanceLock;
LogFactory::Flushing = false;

LogFactory::LogFactory()
{
	LogQueue.clear();
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
	LogQueue.clear();
	return;
}

void LogFactory::close()
{
	flush();
	delete FactoryInstance;
	FactoryInstance = NULL;

	//flush channels
	//sets log factory instance to null
	//empty channels list
	//delete lock object
	return;
}

LogFactory &LogFactory::getInstance()
{
	//obtains a lock
	//return factory instance if set
	//else create a new instance 
	//set it to factory instance
	//return factory instance
	
	MutexLock lock(InstanceLock.getMutex());
	
	if (FactoryInstance == NULL) 
		FactoryInstance = new LogFactory();	
	
	return FactoryInstance;
}

LogFactory &LogFactory::addChannel(LogChannel &channel)
{
	//obtain a lock 
	//add the desired channel
	//remove lock	
	//MutexLock lock(InstanceLock.getMutex());
	ChannelList.push_back(channel);
	return;
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

	vector<std::string> *logslice = extractLog();
	std::vector<LogChannel *>::const_iterator channel_iter = ChannelList->begin();
	
	while (channel_iter != ChannelList->end()) {
		if (!channel_iter->channelOK()) {
			LogFactory::Flushing = false; 
			throw std::runtime_error("Corrupt log channel");
		}

		channel_iter->writeLogs(logslice);
		channel_iter->flush();
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

Logger &LogFactory::getLogger()
{
	
	//Creates a new log object connector to this factory
	//return the new log object
	return *(new Logger(this));
}

vector<std::string> *LogFactory:extractLog()
{
	//get the size of the queue
	//slice of the head to the size
	//create a queue of the new size
	// return the new queue
	
	vector<std::string> *logslice = new vector<std::string>();

	for (int x = LogQueue.size(); x > 0; x--) {
		logslice->push_back(LogQueue.pop());
	}

	return logslice;
}

}
