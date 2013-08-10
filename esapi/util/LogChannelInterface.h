/**
 * abstract base class for all logging channel such as file loggers, syslogd loggers
 *
 */

namespace esapi {

class LogChannel
{
	virtual	bool channelOk() = 0;
	virtual void writeLogs() = 0;
	virtual void flush() = 0;
};

}
