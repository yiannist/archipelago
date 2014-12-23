/*
 * Copyright (C) 2014 GRNET S.A.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <iostream>

#include <log4cplus/configurator.h>
#include <log4cplus/logger.h>

using namespace std;
using namespace log4cplus;

namespace archipelago {
    class Logger;
    class System;
}

class archipelago::Logger: public log4cplus::Logger {
    public:
        Logger(const string& conffile, const string& instance);

        void logerror(const string& msg);
        void logfatal(const string& msg);
        void loginfo(const string& msg);
        void logdebug(const string& msg);
        void logwarn(const string& msg);
        void logtrace(const string& msg);

    private:
        log4cplus::Logger logger;
        void logGeneric(int loglevel, const string& msg);
};

archipelago::Logger::Logger(const string& conffile, const string& instance)
{
    if (conffile.empty()) {
        BasicConfigurator config;
        config.configure();
    } else {
        PropertyConfigurator::doConfigure(conffile);
    }
    logger = getInstance(instance);
}

void archipelago::Logger::logGeneric(int loglevel, const string& msg)
{
    switch (loglevel) {
    case FATAL_LOG_LEVEL:
        if (logger.isEnabledFor(FATAL_LOG_LEVEL)) {
            LOG4CPLUS_FATAL(logger, msg);
        }
        break;
    case ERROR_LOG_LEVEL:
        if (logger.isEnabledFor(ERROR_LOG_LEVEL)) {
            LOG4CPLUS_ERROR(logger, msg);
        }
        break;
    case INFO_LOG_LEVEL:
        if (logger.isEnabledFor(INFO_LOG_LEVEL)) {
            LOG4CPLUS_INFO(logger, msg);
        }
        break;
    case DEBUG_LOG_LEVEL:
        if (logger.isEnabledFor(DEBUG_LOG_LEVEL)) {
            LOG4CPLUS_DEBUG(logger, msg);
        }
        break;
    case WARN_LOG_LEVEL:
        if (logger.isEnabledFor(WARN_LOG_LEVEL)) {
            LOG4CPLUS_WARN(logger, msg);
        }
        break;
    case TRACE_LOG_LEVEL:
        if (logger.isEnabledFor(TRACE_LOG_LEVEL)) {
            LOG4CPLUS_TRACE(logger, msg);
        }
        break;
    default:
        throw runtime_error("Unknown loglevel.");
    }
}

void archipelago::Logger::logerror(const string& msg)
{
    logGeneric(ERROR_LOG_LEVEL, msg);
}

void archipelago::Logger::logfatal(const string& msg)
{
    logGeneric(FATAL_LOG_LEVEL, msg);
}

void archipelago::Logger::loginfo(const string& msg)
{
    logGeneric(INFO_LOG_LEVEL, msg);
}

void archipelago::Logger::logdebug(const string& msg)
{
    logGeneric(DEBUG_LOG_LEVEL, msg);
}

void archipelago::Logger::logwarn(const string& msg)
{
    logGeneric(WARN_LOG_LEVEL, msg);
}

void archipelago::Logger::logtrace(const string& msg)
{
    logGeneric(TRACE_LOG_LEVEL, msg);
}

class archipelago::System: public Logger {
    private:
        int cur_uid;
        int cur_gid;
        char *username;

    public:
        System(const string& logconffile);

        int set_system(bool daemonize, int uid, int gid, mode_t mask,
                const string& pidfile);
        int read_pid(const string& pidfile);
        int check_pid(const string& pidfile);
        int write_pid(const string& pidfile);
        int remove_pid(const string& pidfile);
};

archipelago::System::System(const string& logconffile)
            : Logger(logconffile, "System")
{
    cur_uid = cur_gid = -1;
}
