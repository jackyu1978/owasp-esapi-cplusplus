#ifndef FILELOGGER_H
#define FILELOGGER_H

#include <iostream>
#include <fstream>
#include <vector>
#include "util/LogChannelInterface.h"

using namespace std;

namespace esapi {

class FileChannel : public LogChannel
{
public:
	FileChannel(string filename);
	~FileChannel();

	virtual	bool channelOk() { return !(Outstream.bad() || Outstream.fail()); };
	virtual void flush()		 { Outstream.flush(); };	
	virtual void writeLogs(std::vector<std::string> &);

private:
	string 	 FileName;
	ofstream Outstream;
};


}

#endif 
