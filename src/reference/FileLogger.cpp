#include <stdexcept>
#include "reference/FileLogger.h"

namespace esapi {

FileChannel::FileChannel(std::string filename): FileName(filename)
{
	//throw an exception if file name is empty
	//create the file in append mode
	//store the stream reference
	//return
	if (FileName.empty()) throw std::invalid_argument("Empty file name");

	Outstream.open(FileName.c_str(), ios::app);
	if (!Outstream)
		throw std::runtime_error("Error creating log file");
	
	return;
}

FileChannel::~FileChannel()
{
	Outstream.flush();
	Outstream.close();
	return;
}

void FileChannel::writeLogs(std::vector<std::string> &logstr)
{
	if (!channelOk()) 
		throw std::runtime_error("Error on log channel");
	
	std::vector<std::string>::const_iterator iter;
	for (iter = logstr.begin(); iter != logstr.end(); iter++)
		Outstream << *iter;
	
		
	return;
}

}





