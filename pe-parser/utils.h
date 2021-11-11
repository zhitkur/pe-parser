#pragma once
#include "printa/printa.hpp"
#include <Windows.h>
#include <iostream>
#include <fstream>

#define SET_TITLE 	(printa->project())

class utils
{
private:
	std::string m_file;
	std::string m_option;
	char* m_buffer;

public:
	utils() {}
	~utils() { if (m_buffer) delete[] m_buffer; }
	utils(const char* file_name) { SET_TITLE; this->m_file = file_name; }
	utils(const char* file_name, const char* option) { SET_TITLE; this->m_file = file_name; this->m_option = option; }

	void pe_parser();
};