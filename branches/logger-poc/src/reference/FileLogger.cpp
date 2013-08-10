#include <stdexcept>
#include "FileLogger.h"

namespace esapi {

FileChannel::FileChannel(std::string filename): Filename(filename)
{
	//throw an exception if file name is empty
	//create the file in append mode
	//store the stream reference
	//return
	if (Filename.empty()) throw std::invalid_argument("Empty file name");

	Outstream.open(Filename.c_ptr(), ios::app);
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

void FileChannel::writeLogs(string &logstr)
{
	if (!channelOk()) 
		throw std::runtime_error("Error on log channel");

	Outstream << logstr;
		
	return;
}

}





