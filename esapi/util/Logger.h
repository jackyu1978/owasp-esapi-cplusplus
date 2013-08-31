#include <string>
#include <iostream>
#include <sstream>
#include <ctime>
#include "util/LogFactory.h"

#define TIMESTAMP_LEN 20

namespace esapi {

class Logger
{
public:
	enum 
	{
		EMERGENCY = 0,
		ALERT,
		CRITICAL,
		ERROR,
		WARNING,
		NOTICE,
		INFORMATIONAL,
		DEBUG
	};
	
	Logger(LogFactory &fac) :factory(fac) {};
	~Logger() { factory.flush(); };
	
	void log(std::string entry,   int level);
	void emerg(std::string entry);
	void alert(std::string entry);
	void crit(std::string entry);
	void error(std::string entry);
	void warn(std::string entryl);
	void notice(std::string entry);
	void info(std::string entry);
	void debug(std::string entry);
	void flush();
	
private:
	LogFactory &factory;
	std::string sanitize(std::string);
	std::string getTimestamp();
	const char *LogLevels[8] = {"EMERGENCY", "ALERT", "CRITICAL", "ERROR", "WARNING", "NOTICE", "INFORMATIONAL", "DEBUG"};
};

}
