#pragma once
#include<string>
#include<iostream>
#include<fstream>
#include<vector>
#include "cryptlib.h"
#include "crc.h"
#include "generate_random.h"


enum file_type {txt,jpg,pdf,doc, xlsx};
using namespace CryptoPP;

class File_manager {
	static const int random_file_name_length = 16;
public:
	File_manager(std::string path_) : path(path_),text(""), file_name(""), orginal_file_size(0) {
		std::ifstream input_file(path, std::ios::in | std::ios::binary);
		input_file.unsetf(std::ios::skipws);
		std::streampos fileSize;
		input_file.seekg(0, std::ios::end);
		fileSize = input_file.tellg();
		input_file.seekg(0, std::ios::beg);
		buffer.reserve(fileSize);
		buffer.insert(buffer.begin(),
			std::istream_iterator<unsigned char>(input_file),
			std::istream_iterator<unsigned char>()
		);
	}
	File_manager(std::string path_, int& length) : path(path_), text(""), file_name(""), orginal_file_size(0) {
		std::ifstream input_file(path, std::ios::in);
		input_file.unsetf(std::ios::skipws);
		std::streampos fileSize;
		input_file.seekg(0, std::ios::end);
		fileSize = input_file.tellg();
		input_file.seekg(0, std::ios::beg);
		buffer.reserve(fileSize);
		buffer.insert(buffer.begin(),
			std::istream_iterator<unsigned char>(input_file),
			std::istream_iterator<unsigned char>()
		);
	}
	void make_text_for_encryption() {
		for (const auto& b : buffer) {
			text += b;
		}
		int char_index;
		for (char_index = path.size() - 1;char_index >= 0;--char_index) {
			if ((path[char_index] == ':') || (path[char_index] == '/')|| (path[char_index] == '\\')) {
				break;
			}
		}
		++char_index;
		while (char_index < path.size()) {
			file_name += path[char_index];
			++char_index;
		}
		//file_name += '\n';

		CRC32C crc;
		crc.Update((const byte*)&text[0], text.size());
		std::string digest;
		digest.resize(crc.DigestSize());
		crc.Final((byte*)&digest[0]);
		digest += "\n";

		const int text_length = text.size();
		std::string text_length_str;
		std::stringstream str;
		str << text_length;
		str >> text_length_str;
		text_length_str += '\n';

		text.insert(0, file_name+ '\n');
		text.insert(0, digest);
		text.insert(0, text_length_str);

		const int new_size = text.size();
		int rest = new_size % 16;
		while (rest < 16) {
			text += "A";
			++rest;
		}
	}

	void make_text_for_decryption() {
		int text_index;
		std::string length_string;
		for (text_index = 0;;++text_index) {
			if (buffer[text_index] != '\n') {
				length_string += buffer[text_index];
			}
			else {
				break;
			}
		}
		orginal_file_size = std::stoi(length_string);
		++text_index;
		std::string crc;
		for (;;++text_index) {
			if (buffer[text_index] != '\n') {
				crc += buffer[text_index];
			}
			else {
				break;
			}
		}
		++text_index;
		for (;;++text_index) {
			if (buffer[text_index] != '\n') {
				file_name += buffer[text_index];
			}
			else {
				break;
			}
		}
		++text_index;
		for (int left_chars = orginal_file_size;left_chars >= 0;--left_chars) {
			text += buffer[text_index];
			++text_index;
		}
		buffer.push_back(0);
		while (buffer[text_index] == 'A') {
			text += buffer[text_index];
			++text_index;
		}
	}

	std::string save_as_text_file(std::string path, bool random_saved_file_name) {
		std::string random_file_name= path;
		if (random_saved_file_name) {
			for (int i = 0;i < random_file_name_length;++i) {
				char c = '!';
				while ((c < 'A') || (c > 'z') || ((c > 'Z') && (c, 'a'))) {
					c = (unsigned char)generate_random_char();
				}

				random_file_name += c;
			}
			random_file_name += ".txt";
		}
		else {
			random_file_name += this->file_name;
		}
		std::ofstream file;
		file.open(random_file_name,std::ios::binary);
		if (!file)
		{
			std::cout << "Error in creating file!!!";
			return "";
		}
		file << text;
		file.close();
		return random_file_name;
	}
public:
	std::vector<unsigned char> buffer;
	std::string text;
	std::string file_name;
	std::string path;
	int orginal_file_size;
};