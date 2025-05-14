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
	string password;
	EC_KEY* EC_key;
	RSA* RSA_key;

	string calculate_time_difference();

public:
	Entity(int id,string password); 
	~Entity();
	int get_id() { return this->id; }
	string get_password() { return this->password; }
	string get_ECC_pub_key_file() { return to_string(id)+"_pub.ecc"; }
	string get_RSA_pub_key_file() { return to_string(id) + "_pub.rsa"; }
	string get_ECC_prv_key_file() { return to_string(id) + "_priv.ecc"; }
	string get_RSA_prv_key_file() { return to_string(id) + "_priv.rsa"; }
	string get_ECC_mac_file() { return to_string(id) + "_ecc.mac"; }
	string get_RSA_mac_file() { return to_string(id) + "_rsa.mac"; }
	EC_KEY* get_ECC_key() { return this->EC_key; }
	RSA* get_RSA_key() { return this->RSA_key; }
	bool load_ECC_private_key(string password);
	bool load_RSA_private_key(string passowrd);
	bool load_ECC_public_key(unsigned char** der_mac, size_t* der_len);
	bool load_RSA_public_key(unsigned char** der_mac, size_t* der_len);
	bool verify_public_key_mac(unsigned char* mac_value,size_t mac_len);
	unsigned char* get_raw_ECC_public_key(size_t* raw_pub_len);
	unsigned char* get_raw_RSA_public_key(size_t* raw_pub_len);
	bool generate_ECC_key_pair();
	bool generate_RSA_key_pair();
	bool save_ECC_private_key(string password);
	bool save_RSA_private_key(string password);
	bool save_ECC_pub_key();
	bool save_RSA_pub_key();
	bool generate_and_save_MAC(string pub_key_file);
};

