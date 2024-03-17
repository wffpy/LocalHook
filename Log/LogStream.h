#ifndef LOGSTREAM_H
#define LOGSTREAM_H
#include <iostream>
#include <sstream>

namespace log_module {

enum class LogLevel { INFO, DEBUG, WARN, ERROR };

class Logger {
  public:
    Logger(std::string file_name, std::string func_name, int line);
    Logger(std::string file_name, std::string func_name, int line,
           LogLevel level);
    // Logger(LogLevel level);
    ~Logger();
    template <typename T> Logger &operator<<(const T &value) {
        os_stream_ << value;
        return *this;
    }

    void flush();

  private:
    std::string level_str();
    LogLevel level_;
    std::ostringstream os_stream_;
};
} // namespace log_module

#define WLOG()                                                                 \
    log_module::Logger(__FILE__, __FUNCTION__, __LINE__,                       \
                       log_module::LogLevel::INFO)

#endif
