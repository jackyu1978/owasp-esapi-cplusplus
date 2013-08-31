#include "util/Logger.h"

namespace esapi {

void Logger::log(std::string entry, int level)
{
	std::ostringstream log_entry;
	log_entry << getTimestamp()   << " "
						<< LogLevels[level] << " "
						//<< "File: " << file << " "
						//<< "Line: " << line << " "
						<< sanitize(entry);
	factory.queueLog(log_entry.str());
	return;
}

void Logger::emerg(std::string entry)
{
	log(entry, Logger::EMERGENCY);
}

void Logger::alert(std::string entry)
{

	log(entry, Logger::ALERT);
}

void Logger::crit(std::string entry)
{
	log(entry, Logger::CRITICAL);

}

void Logger::error(std::string entry)
{
	log(entry, Logger::ERROR);

}

void Logger::warn(std::string entry)
{
	log(entry, Logger::WARNING);

}

void Logger::notice(std::string entry)
{
	log(entry, Logger::NOTICE);

}

void Logger::info(std::string entry)
{
	log(entry, Logger::INFORMATIONAL);

}

void Logger::debug(std::string entry)
{
	log(entry, Logger::DEBUG);

}

void Logger::flush()
{
	return;

}

std::string Logger::getTimestamp()
{
	time_t *Calendartime;
	tm		 *Timestruct;
	
	time(Calendartime);
	if ((Timestruct = gmtime(Calendartime)) == NULL)
		Timestruct = localtime(Calendartime);
	
	char Timestamp[TIMESTAMP_LEN];
	strftime(Timestamp, TIMESTAMP_LEN, "%Y-%m-%d %H:%M:%S", Timestruct);
	
	return std::string(Timestamp);
}

std::string Logger::sanitize(std::string entry)
{
	//replace the following characters with their hex equivalent
	//new line
	//carriage return
	//iterate throught the characters in the string
	//check for newline or carriage return
	//convert them to other caracter
	return entry;
}


} //esapi namespace
