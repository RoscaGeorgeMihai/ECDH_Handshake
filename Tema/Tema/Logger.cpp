#define _CRT_SECURE_NO_WARNINGS
#include "Logger.h"
#include <ctime>
#include <sstream>
#include <iostream>
#include <iomanip>

Logger* Logger::instance = nullptr;

uint64_t Logger::getCurrentDate()
{
	return static_cast<uint64_t>(time(nullptr));
}

Logger::~Logger()
{
	if (this->instance != nullptr)
		delete this->instance;
	if (this->log_file.is_open())
		log_file.close();
}

void Logger::log_action(string action,int entity_id)
{
	if (log_file.is_open()) {
		LogEntry entry;
		entry.timestamp = getCurrentDate();
		entry.entity_id = static_cast<uint32_t>(entity_id);
		entry.action_len = static_cast<uint32_t>(action.length());

		log_file.write(reinterpret_cast<const char*>(&entry), sizeof(entry));

		log_file.write(action.c_str(), action.length());
	}
}

void Logger::readLogBlob()
{
	ifstream file("info.log", ios::binary);
	if (!file.is_open())
		return;
	while (true) {
		LogEntry entry;
		file.read(reinterpret_cast<char*>(&entry), sizeof(entry));
		if (file.gcount() != sizeof(entry))
			break;
		char* action = (char*)malloc(entry.action_len+1);
		file.read(action, entry.action_len);
		action[entry.action_len] = '\0';
		time_t time = static_cast<time_t>(entry.timestamp);
		tm* time_info = localtime(&time);

		cout << put_time(time_info, "%Y-%m-%d %H:%M:%S") << " " << entry.entity_id <<" " << action;
		free(action);
	}
}

Logger* Logger::getInstance()
{
	if (instance == nullptr) {
		instance = new Logger();
	}

	return instance;
}
