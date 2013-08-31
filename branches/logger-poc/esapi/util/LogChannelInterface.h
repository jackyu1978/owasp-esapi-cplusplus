/**
 * abstract base class for all logging channel such as file loggers, syslogd loggers
 *
 */
#include <string>
#include <vector>

namespace esapi {

class LogChannel
{
public:
	virtual	bool channelOk() = 0;
	virtual void writeLogs(std::vector<std::string> &) = 0;
	virtual void flush() = 0;
};

}
