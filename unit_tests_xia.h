#pragma once
#include "insertion_encryption.h"
#include "generate_random.h"
#include <iostream>

bool random_unit_test() {
	std::string test_string="0123456789123456";
	std::string AES_password= "01234567891234560123456789123456";
	std::string xor_password= "01234567891234560123456789123456";
	std::string ins_password= "01234567891234560123456789123456";
	std::string random;
	for (int i = 0;i < 256;++i) {
		random += (char)i;
	}
	std::cout << "Test running\n";

	const int nr_of_random_tests = 100000000;
	for (int i = 0;i < nr_of_random_tests;++i) {
		for (int j = 0;j < 16;++j) {
			test_string[j] = generate_random_char();
		}
		std::string plaintext = test_string;
		std::string cipher = xor_insertion_encryption(plaintext, AES_password, xor_password, ins_password, random);
		std::string recovered = xor_insertion_decryption(cipher, AES_password, xor_password, ins_password);
		if (plaintext.compare(recovered)) {
			std::cout << "Error for string: " << plaintext << "\n";
		}
	}
	std::cout << "Test eneded";
	return true;
}

bool all_char_combination_duets_test() {
	std::string test_string = "0123456789123456";
	std::string AES_password = "01234567891234560123456789123456";
	std::string xor_password = "01234567891234560123456789123456";
	std::string ins_password = "01234567891234560123456789123456";
	std::string random;
	for (int i = 0;i < 256;++i) {
		random += (char)i;
	}
	std::cout << "Test running\n";

	for (int i = 0;i < 256;++i) {
		for (int j = 0;j < 256;++j) {
			test_string[14] = (unsigned char)i;
			test_string[15] = (unsigned char)j;
		}
		std::string plaintext = test_string;
		std::string cipher = xor_insertion_encryption(plaintext, AES_password, xor_password, ins_password, random);
		std::string recovered = xor_insertion_decryption(cipher, AES_password, xor_password, ins_password);
		if (plaintext.compare(recovered)) {
			std::cout << "Error for string: " << plaintext << "\n";
		}
	}
	std::cout << "Test eneded";
	return true;
}