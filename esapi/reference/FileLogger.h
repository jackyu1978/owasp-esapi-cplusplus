#ifndef FILELOGGER_H
#define FILELOGGER_H

#include <iostream>
#include <ofstream>
#include "LogChannelInterface.h"

using namespace std;

namespace esapi {


class FileChannel : public LogChannel
{
public:
	FileChannel(string filename);
	~FileChannel();

	bool channelOk() { return !(Outstream.bad() || Outstream.fail()); };
	void flush()		 { return Outstream.flush(); };	
	void writeLogs(string &);

private:
	string 	 FileName;
	ofstream Outstream;
};


}

#endif 
