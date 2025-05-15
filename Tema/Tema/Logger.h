#pragma once
#include <fstream>

using namespace std;

struct LogEntry {
	uint64_t timestamp;
	uint32_t entity_id;
	uint32_t action_len;
};

class Logger
{
	static Logger* instance;
	ofstream log_file;

	Logger() { log_file.open("info.log", ios::out | ios::binary); }
	Logger(const Logger&) = delete;
	Logger& operator=(const Logger&) = delete;
	uint64_t getCurrentDate();
public:
	~Logger();
	void log_action(string action,int entity_id);
	void close_file() { log_file.close(); }
	void readLogBlob();
	static Logger* getInstance();
};

