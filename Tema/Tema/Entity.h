#pragma once
#include <openssl/ec.h>
#include <openssl/rsa.h>
#include <string>
#include <vector>

using namespace std;

class Entity
{
private:
	int id;
	EC_KEY* EC_key;
	RSA* RSA_key;

	string calculate_time_difference();

public:
	Entity(int id);
	~Entity();
	EC_KEY* get_EC_key() { return this->EC_key; }
	bool load_private_key(string filename, string password);
	bool load_public_key(string filename, unsigned char** der_mac, size_t* der_len);
	bool verify_public_key_mac(unsigned char* mac_value,size_t mac_len);
	unsigned char* get_raw_public_key(size_t* raw_pub_len);
	bool generate_EC_key_pair();
	bool save_private_key(string filename, string password);
	bool save_pub_key(string filename);
	bool generate_and_save_MAC(string pub_key_file);
};

