/**
* OWASP Enterprise Security API (ESAPI)
*
* This file is part of the Open Web Application Security Project (OWASP)
* Enterprise Security API (ESAPI) project. For details, please see
* http://www.owasp.org/index.php/ESAPI.
*
* Copyright (c) 2011 - The OWASP Foundation
*/

#pragma once

#include <string>

namespace esapi
{
  /**
  * The Logger interface defines a set of methods that can be used to log
  * security events. It supports a hierarchy of logging levels which can be configured at runtime to determine
  * the severity of events that are logged, and those below the current threshold that are discarded.
  * Implementors should use a well established logging library
  * as it is quite difficult to create a high-performance logger.
  * <P>
  * The logging levels defined by this interface (in descending order) are:
  * <ul>
  * <li>fatal (highest value)</li>
  * <li>error</li>
  * <li>warning</li>
  * <li>info</li>
  * <li>debug</li>
  * <li>trace (lowest value)</li>
  * </ul>
  * There are also several variations of {@code always()} methods that will <i>always</i>
  * log a message regardless of the log level.
  * <p>
  * ESAPI also allows for the definition of the type of log event that is being generated.
  * The Logger interface predefines 6 types of Log events:
  * <ul>
  * <li>SECURITY_SUCCESS</li>
  * <li>SECURITY_FAILURE</li>
  * <li>SECURITY_AUDIT</li>
  * <li>EVENT_SUCCESS</li>
  * <li>EVENT_FAILURE</li>
  * <li>EVENT_UNSPECIFIED</li>
  * </ul>
  * <p>
  * Your implementation can extend or change this list if desired.
  * <p>
  * This Logger allows callers to determine which logging levels are enabled, and to submit events
  * at different severity levels.<br>
  * <br>Implementors of this interface should:
  *
  * <ol>
  * <li>provide a mechanism for setting the logging level threshold that is currently enabled. This usually works by logging all
  * events at and above that severity level, and discarding all events below that level.
  * This is usually done via configuration, but can also be made accessible programmatically.</li>
  * <li>ensure that dangerous HTML characters are encoded before they are logged to defend against malicious injection into logs
  * that might be viewed in an HTML based log viewer.</li>
  * <li>encode any CRLF characters included in log data in order to prevent log injection attacks.</li>
  * <li>avoid logging the user's session ID. Rather, they should log something equivalent like a
  * generated logging session ID, or a hashed value of the session ID so they can track session specific
  * events without risking the exposure of a live session's ID.</li>
  * <li>record the following information with each event:</li>
  *   <ol type="a">
  *   <li>identity of the user that caused the event,</li>
  *   <li>a description of the event (supplied by the caller),</li>
  *   <li>whether the event succeeded or failed (indicated by the caller),</li>
  *   <li>severity level of the event (indicated by the caller),</li>
  *   <li>that this is a security relevant event (indicated by the caller),</li>
  *   <li>hostname or IP where the event occurred (and ideally the user's source IP as well),</li>
  *   <li>a time stamp</li>
  *   </ol>
  * </ol>
  *
  * Custom logger implementations might also:
  * <ol start="6">
  * <li>filter out any sensitive data specific to the current application or organization, such as credit cards,
  * social security numbers, etc.</li>
  * </ol>
  *
  * There are both Log4j and native Java Logging default implementations. JavaLogger uses the java.util.logging package as the basis for its logging
  * implementation. Both default implementations implements requirements #1 thru #5 above.<br>
  * <br>
  * Customization: It is expected that most organizations will implement their own custom Logger class in
  * order to integrate ESAPI logging with their logging infrastructure. The ESAPI Reference Implementation
  * is intended to provide a simple functional example of an implementation.
  *
  * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
  * href="http://www.aspectsecurity.com">Aspect Security</a>
  * @author David Anderson (david.anderson@aspectsecurity.com)
  * @since June 1, 2007
  */
  class Logger
  {
  public:
    const EventType SECURITY_SUCCESS = new EventType( "SECURITY SUCCESS", true);
    const EventType SECURITY_FAILURE = new EventType( "SECURITY FAILURE", true);
    const EventType SECURITY_AUDIT = new EventType( "SECURITY AUDIT", true);
    const EventType EVENT_SUCCESS = new EventType( "EVENT SUCCESS", true);
    const EventType EVENT_FAILURE = new EventType( "EVENT FAILURE", true);
    const EventType EVENT_UNSPECIFIED = new EventType( "EVENT UNSPECIFIED", true);
    const int OFF = Integer.MAX_VALUE;
    const int FATAL = 1000;
    const int ERROR = 800;
    const int WARNING = 600;
    const int INFO = 400;
    const int DEBUG = 200;
    const int TRACE = 100;
    const int ALL = Integer.MIN_VALUE;

    virtual void setLevel(int) =0;
    virtual int getESAPILevel(void) =0;
    virtual void fatal(EventType, const std::string &) =0;
    virtual void fatal(EventType, const std::string &, Throwable) =0;
    virtual bool isFatalEnabled() =0;
    virtual void error(EventType, const std::string &) =0;
    virtual void error(EventType, const std::string &, Throwable) =0;
    virtual bool isErrorEnabled() =0;
    virtual void warning(EventType, const std::string &) =0;
    virtual void warning(EventType, const std::string &, Throwable) =0;
    virtual bool isWarningEnabled() =0;
    virtual void info(EventType, const std::string &) =0;
    virtual void info(EventType, const std::string &, Throwable) =0;
    virtual bool isInfoEnabled() =0;
    virtual void debug(EventType, const std::string &) =0;
    virtual void debug(EventType, const std::string &, Throwable) =0;
    virtual bool isDebugEnabled() =0;
    virtual void trace(EventType, const std::string &) =0;
    virtual void trace(EventType, const std::string &, Throwable) =0;
    virtual bool isTraceEnabled() =0;
    virtual void always(EventType, const std::string &) =0;
    virtual void always(EventType, const std::string &, Throwable) =0;

    virtual ~Logger() {};
  };

  class EventType {

    std::string type;
    Boolean success = null;

  public:
    EventType (const std::string & name, Boolean newSuccess)
    {
      this.type = name;
      this.success = newSuccess;
    }

    Boolean isSuccess()
    {
      return success;
    }

    /**
    * Convert the {@code EventType} to a string.
    * @return The event type name.
    */
    std::string toString()
    {
      return this.type;
    }
  };
};


