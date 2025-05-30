#define _CRT_SECURE_NO_WARNINGS
#pragma warning(disable : 4996)
#include "Entity.h"
#include "PubKeyMAC_Asn1.h"
#include <openssl/obj_mac.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <openssl/asn1.h>
#include <openssl/evp.h>
#include <openssl/applink.c>
#include <openssl/bn.h>
#include <ctime>
#include <fstream>
#include <iostream>
#include <chrono>

#define SYM_KEY_SIZE 32
#define GMAC_IV_LEN 12
#define GMAC_TAG_LEN 16
#define EXP_VALUE 65537
#define RSA_KEY_LEN 3072

string Entity::calculate_time_difference()
{
	tm specified_time;
	specified_time.tm_year = 105; //diferenta de timp din 1900 pana in 2005 (cat este specificat in cerinta deoarece tm_year reprezinta numarul de ani din 1900)
	specified_time.tm_mon = 4; //indexarea lunilor incepe de la 0
	specified_time.tm_mday = 5;
	specified_time.tm_hour = 5;
	specified_time.tm_min = 5;
	specified_time.tm_sec = 5;
	specified_time.tm_isdst = 0;

	time_t specified_time_t = _mkgmtime(&specified_time);
	if (specified_time_t == -1) {
		cerr << "Something went wrong while trying to transform the tm structure to time_t\n";
		return {};
	}
	
	time_t current_time_t = time(nullptr);

	long long diff = current_time_t - specified_time_t;

	return to_string(diff);
}

Entity::Entity(int id, string password)
{
	this->id = id;
	this->password = password;
	this->EC_key = nullptr;
	this->RSA_key = nullptr;
}

Entity::~Entity()
{
	this->id = 0;
	if (this->EC_key != nullptr)
		EC_KEY_free(this->EC_key);
	if (this->RSA_key != nullptr)
		RSA_free(this->RSA_key);
}

void Entity::register_entity()
{
	this->generate_ECC_key_pair();
	this->save_ECC_private_key();
	this->save_ECC_pub_key();
	
	this->generate_RSA_key_pair();
	this->save_RSA_private_key();
	this->save_RSA_pub_key();

	this->generate_and_save_MAC(this->get_ECC_pub_key_file());
	this->generate_and_save_MAC(this->get_RSA_pub_key_file());
}

bool Entity::load_ECC_private_key()
{
	FILE* file = fopen(this->get_ECC_prv_key_file().c_str(), "r");
	if (file == nullptr) {
		std::cerr << "Something went wrong while trying to load the ECC private key for entity: " << this->id << " : {the file can't be opened}\n";
		return false;
	}

	this->EC_key = PEM_read_ECPrivateKey(file, nullptr, nullptr, const_cast<char*>(this->password.c_str()));

	if (this->EC_key == nullptr) {
		std::cerr << "Something went wrong while trying to load the ECC private key for entity: " << this->id << " : {the key couldn't be read}\n";
		return false;
	}
	fclose(file);
	return true;
}

bool Entity::load_RSA_private_key()
{
	string filename = this->get_RSA_prv_key_file();
	FILE* file = fopen(filename.c_str(), "r");
	if (file == nullptr) {
		std::cerr << "Something went wrong while trying to load the RSA private key for entity: " << this->id << " : {the file can't be opened}\n";
		return false;
	}

	this->RSA_key = PEM_read_RSAPrivateKey(file, nullptr, nullptr, const_cast<char*>(this->password.c_str()));

	if (this->RSA_key == nullptr) {
		std::cerr << "Something went wrong while trying to load the ECC private key for entity: " << this->id << " : {the key couldn't be read}\n";
		return false;
	}
	fclose(file);
	return true;
}

bool Entity::load_RSA_public_key()
{
	string filename = this->get_RSA_pub_key_file();
	FILE* file = fopen(filename.c_str(), "r");

	this->RSA_key = PEM_read_RSAPublicKey(file, nullptr, nullptr, nullptr);

	if (this->RSA_key == nullptr) {
		std::cerr << "Something went wrong while trying to load the ECC private key for entity: " << this->id << " : {the public key couldn't be read}\n";
		return false;
	}
	fclose(file);
	
	return true;
}

bool Entity::load_ECC_key_mac(unsigned char** der_mac,size_t* der_len)
{
	string mac_filename = this->get_ECC_mac_file();

	FILE* mac_file = fopen(mac_filename.c_str(), "rb");
	fseek(mac_file, 0, SEEK_END);
	*der_len = ftell(mac_file);
	fseek(mac_file, 0, SEEK_SET);

	*der_mac = (unsigned char*)malloc(*der_len);
	fread(*der_mac, *der_len, 1, mac_file);
	fclose(mac_file);
	return true;
}

bool Entity::load_RSA_key_mac(unsigned char** der_mac, size_t* der_len)
{
	string mac_filename = this->get_RSA_mac_file();

	FILE* mac_file = fopen(mac_filename.c_str(), "rb");
	if (mac_file == nullptr)
		return false;
	fseek(mac_file, 0, SEEK_END);
	*der_len = ftell(mac_file);
	fseek(mac_file, 0, SEEK_SET);

	*der_mac = (unsigned char*)malloc(*der_len);
	fread(*der_mac, *der_len, 1, mac_file);
	fclose(mac_file);
	return true;
}

bool Entity::verify_public_key_mac(string key_filename,unsigned char* der_mac, size_t der_len)
{
	size_t raw_pub_len = 0;
	unsigned char* raw_pub_key = nullptr;
	if (key_filename.find("ecc") != string::npos)
		raw_pub_key = get_raw_ECC_public_key(&raw_pub_len);
	else if (key_filename.find("rsa") != string::npos)
		raw_pub_key = get_raw_RSA_public_key(&raw_pub_len);

	if (raw_pub_len <= 0) {
		std::cerr << "Something went wrong while trying to verify the public key for entity with id " << this->id << " : {raw_pub_key is empty}\n";
		return false;
	}
	const unsigned char* p_der_mac = der_mac;
	PubKeyMAC* pub_MAC = d2i_PubKeyMAC(nullptr,&p_der_mac, der_len);

	size_t mac_key_len = ASN1_STRING_length(pub_MAC->MACKey);
	unsigned char* mac_key = (unsigned char*)malloc(mac_key_len);
	memcpy(mac_key, ASN1_STRING_get0_data(pub_MAC->MACKey), mac_key_len);

	size_t mac_value_len = ASN1_STRING_length(pub_MAC->MACValue);
	unsigned char* mac_value = (unsigned char*)malloc(mac_value_len);
	memcpy(mac_value, ASN1_STRING_get0_data(pub_MAC->MACValue), mac_value_len);

	EVP_CIPHER_CTX* gmac_ctx = EVP_CIPHER_CTX_new();

	unsigned char* iv = (unsigned char*)malloc(GMAC_IV_LEN);
	memset(iv, 0, GMAC_IV_LEN);
	if (EVP_EncryptInit_ex(gmac_ctx, EVP_aes_256_gcm(),nullptr, mac_key, iv) != 1) {
		std::cerr << "Something went wrong while trying to verify the public key for entity with id " << this->id << " : {authentification can't be initialized}\n";
		return false;
	}

	int output_len = 0;
	if (EVP_EncryptUpdate(gmac_ctx, NULL, &output_len, raw_pub_key, raw_pub_len) != 1) {
		std::cerr << "Something went wrong while trying to save the MAC for the key saved in the file " << this->id << " : {authentification can't be updated}\n";
		return false;
	}

	int final_outl = 0;
	if (EVP_EncryptFinal_ex(gmac_ctx, NULL, &final_outl) != 1) {
		std::cerr << "Something went wrong while trying to save the MAC for the key saved in the file " << this->id << " : {authentification can't be finalized}\n";
		return false;
	}

	unsigned char* gmac_tag = (unsigned char*)malloc(GMAC_TAG_LEN);
	memset(gmac_tag, 0, GMAC_TAG_LEN);
	if (EVP_CIPHER_CTX_ctrl(gmac_ctx, EVP_CTRL_GCM_GET_TAG, GMAC_TAG_LEN, gmac_tag) != 1) {
		std::cerr << "Something went wrong while trying to save the MAC for the key saved in the file " << this->id << " : {authentification tag can't be extracted}\n";
		return false;
	}

	if (CRYPTO_memcmp(gmac_tag, mac_value, GMAC_TAG_LEN) == 0)
		return true;

	return false;
}

unsigned char* Entity::get_raw_RSA_public_key(size_t* raw_pub_len)
{
	if (this->RSA_key == nullptr) {
		std::cerr << "Something went wrong while trying to get the raw RSA public key for entity with id " << this->id << " : {there is no RSA key assigned}\n";
		return nullptr;
	}

	int raw_len = i2d_RSAPublicKey(this->RSA_key, nullptr);

	if (raw_len <= 0) {
		std::cerr << "Something  went wrong while trying to get the raw RSA public key for entity with id " << this->id << " : {can't get the raw key\n}";
		return nullptr;
	}

	*raw_pub_len = static_cast<size_t>(raw_len);
	unsigned char* raw_pub_buff = (unsigned char*)OPENSSL_malloc(*raw_pub_len);

	unsigned char* p = raw_pub_buff;
	raw_len = i2d_RSAPublicKey(this->RSA_key, &p);
	if (raw_len <= 0) {
		std::cerr << "Something  went wrong while trying to get the raw RSA public key for entity with id " << this->id << " : {can't serialize the public key to DER format\n}";
		return nullptr;
	}

	return raw_pub_buff;
}

bool Entity::generate_ECC_key_pair()
{
	this->EC_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	if (this->EC_key == nullptr) {
		std::cerr << "Something went wrong while trying to set the elliptic curve prime256v1\n";
		return false;
	}

	if (EC_KEY_generate_key(this->EC_key) != 1) {
		EC_KEY_free(this->EC_key);
		this->EC_key = nullptr;
		std::cerr << "Something went wrong while trying to generate the key for elliptic curve prime256v1\n";
		return false;
	}

	return true;
}

bool Entity::generate_RSA_key_pair()
{
	this->RSA_key = RSA_new();
	BIGNUM* exponent = BN_new();

	BN_set_word(exponent, EXP_VALUE);

	if (!RSA_generate_key_ex(this->RSA_key, RSA_KEY_LEN, exponent, nullptr)){
		std::cerr << "Something went wrong while trying to generate the rsa key\n";
		return false;
	}

	return true;
}

bool Entity::save_ECC_private_key()
{
	string filename = to_string(this->id);
	filename += "_priv.ecc";
	if (this->EC_key == nullptr) {
		std::cerr << "Something went wrong while trying to save the ECC private key for entity with id " << this->id << " : {there is no key assigned}\n";
		return false;
	}

	BIO* file = BIO_new_file(filename.c_str(), "w");
	if (file == nullptr) {
		std::cerr << "Something went wrong while trying to save the ECC private key for entity with id " << this->id << " : {the file can't be opened}\n";
		return false;
	}
	EVP_PKEY* pKey = EVP_PKEY_new();
	if (pKey == nullptr) {
		std::cerr << "Something went wrong while trying to save the ECC private key for entity with id " << this->id << " : {the new EVP_PKEY can't be created}\n";
		return false;
	}
	EVP_PKEY_assign(pKey,EVP_PKEY_EC,EC_KEY_dup(this->EC_key));

	if (PEM_write_bio_PrivateKey(file, pKey, EVP_aes_256_cbc(), (unsigned char*)this->password.c_str(), password.length(), nullptr, nullptr) != 1) {
		std::cerr << "Something went wrong while trying to save the ECC private key for entity with id " << this->id << " : {the key can't be written in the PEM file}\n";
		return false;
	}

	EVP_PKEY_free(pKey);
	BIO_free_all(file);

	return true;
}

bool Entity::save_RSA_private_key()
{
	string filename = this->get_RSA_prv_key_file();
	if (this->RSA_key == nullptr) {
		std::cerr << "Something went wrong while trying to save the RSA private key for entity with id " << this->id << " : {there is no key assigned}\n";
		return false;
	}

	BIO* file = BIO_new_file(filename.c_str(), "wb");
	if (file == nullptr) {
		std::cerr << "Something went wrong while trying to save the RSA private key for entity with id " << this->id << " : {the file can't be opened}\n";
		return false;
	}

	if (PEM_ASN1_write_bio((i2d_of_void*)i2d_RSAPrivateKey,PEM_STRING_RSA,file,this->RSA_key,EVP_aes_256_cbc(),(unsigned char*)this->password.c_str(),password.length(),nullptr,nullptr) != 1) {
		std::cerr << "Something went wrong while trying to save the RSA private key for entity with id " << this->id << " : {the key can't be written in the PEM file}\n";
		return false;
	}

	BIO_free_all(file);
	return true;
}

unsigned char* Entity::get_raw_ECC_public_key(size_t* raw_pub_len) {
	const EC_POINT* pub_point = EC_KEY_get0_public_key(this->EC_key);
	if (pub_point == nullptr) {
		std::cerr << "Something went wrong while trying to get the raw public key for entity with id " << this->id << " : {the public point can't be determined for key}\n";
		return nullptr;
	}

	const EC_GROUP* key_group = EC_KEY_get0_group(this->EC_key);
	if (key_group == nullptr) {
		std::cerr << "Something went wrong while trying to get the raw public key for entity with id " << this->id << " : {the key group can't be determined}\n";
		return nullptr;
	}
	
	unsigned char* raw_pub_buff=nullptr;
	BN_CTX* bn_ctx = BN_CTX_new();
	if (bn_ctx == nullptr) {
		std::cerr << "Something went wrong while trying to get the raw public key for entity with id " << this->id << " : {the BN_CTX can't be created}\n";
		return nullptr;
	}

	*raw_pub_len = EC_POINT_point2buf(key_group, pub_point, POINT_CONVERSION_UNCOMPRESSED, &raw_pub_buff, bn_ctx);

	if (*raw_pub_len == 0) {
		std::cerr << "Something went wrong while trying to get the raw public key for entity with id " << this->id << " : {the key couldn't be transformed to raw format}\n";
		return nullptr;
	}

	BN_CTX_free(bn_ctx);
	return raw_pub_buff;
}

bool Entity::save_ECC_pub_key()
{
	string filename = to_string(this->id);
	filename += "_pub.ecc";

	if (this->EC_key == nullptr) {
		std::cerr << "Something went wrong while trying to save the ECC public key for entity with id " << this->id << " : {there is no key assigned}";
		return false;
	}

	BIO* file = BIO_new_file(filename.c_str(), "w");
	if (file == nullptr) {
		std::cerr << "Something went wrong while trying to save the ECC public key for entity with id " << this->id << " : {the file can't be opened}";
		return false;
	}

	if (PEM_write_bio_EC_PUBKEY(file, this->EC_key) != 1) {
		std::cerr << "Something went wrong while trying to save the ECC public key for entity with id " << this->id << " : {the pub_key can't be written in the PEM file}\n";
		return false;
	}

	BIO_free_all(file);
	return true;
}

bool Entity::save_RSA_pub_key()
{
	string filename = this->get_RSA_pub_key_file();

	if (this->RSA_key == nullptr) {
		std::cerr << "Something went wrong while trying to save the RSA public key for entity with id " << this->id << " : {there is no key assigned}";
		return false;
	}

	BIO* file = BIO_new_file(filename.c_str(), "w");
	if (file == nullptr) {
		std::cerr << "Something went wrong while trying to save the RSA public key for entity with id " << this->id << " : {the file can't be opened}";
		return false;
	}

	if (PEM_write_bio_RSAPublicKey(file,this->RSA_key) != 1) {
		std::cerr << "Something went wrong while trying to save the RSA public key for entity with id " << this->id << " : {the pub_key can't be written in the PEM file}\n";
		return false;
	}

	BIO_free_all(file);
	return true;
}

bool Entity::generate_and_save_MAC(string pub_key_file)
{
	size_t raw_pub_key_len;
	unsigned char* raw_pub_key = nullptr;
	if (pub_key_file.find("ecc")!=string::npos)
		raw_pub_key = get_raw_ECC_public_key(&raw_pub_key_len);
	else if (pub_key_file.find("rsa")!=string::npos)
		raw_pub_key = get_raw_RSA_public_key(&raw_pub_key_len);

	string time_diff = this->calculate_time_difference();
	if (time_diff.empty()) {
		std::cerr << "Something went wrong while trying to save the MAC for the key saved in the file " << pub_key_file << " : {the time difference is empty}\n";
		return false;
	}
	unsigned char* sym_gmac_key = (unsigned char*)malloc(SYM_KEY_SIZE);

	const EVP_MD* digest = EVP_sha3_256();
	if (digest == nullptr) {
		std::cerr << "Something went wrong while trying to save the MAC for the key saved in the file " << pub_key_file << " : {the digest can't be initialized}\n";
		return false;
	}

	if (PKCS5_PBKDF2_HMAC(time_diff.c_str(), time_diff.length(), NULL, 0, 50000, digest, SYM_KEY_SIZE, sym_gmac_key) != 1) {
		std::cerr << "Something went wrong while trying to save the MAC for the key saved in the file " << pub_key_file << " : {the time_diff couldn't be digested}\n";
		return false;
	}

	unsigned char* gmac_iv = (unsigned char*)malloc(GMAC_IV_LEN);
	memset(gmac_iv, 0, GMAC_IV_LEN);

	int update_outl = 0,final_outl=0;
	unsigned char* gmac_tag = (unsigned char*)malloc(GMAC_TAG_LEN);
	EVP_CIPHER_CTX* gmac_ctx = nullptr;
	
	gmac_ctx = EVP_CIPHER_CTX_new();

	if (EVP_EncryptInit_ex(gmac_ctx, EVP_aes_256_gcm(), NULL, sym_gmac_key, gmac_iv) != 1) {
		std::cerr << "Something went wrong while trying to save the MAC for the key saved in the file " << pub_key_file << " : {authentification can't be initialized}\n";
		return false;
	}

	if (EVP_EncryptUpdate(gmac_ctx, NULL, &update_outl, raw_pub_key, raw_pub_key_len) != 1) {
		std::cerr << "Something went wrong while trying to save the MAC for the key saved in the file " << pub_key_file << " : {authentification can't be updated}\n";
		return false;
	}

	if (EVP_EncryptFinal_ex(gmac_ctx, NULL, &final_outl) != 1) {
		std::cerr << "Something went wrong while trying to save the MAC for the key saved in the file " << pub_key_file << " : {authentification can't be finalized}\n";
		return false;
	}

	if (EVP_CIPHER_CTX_ctrl(gmac_ctx, EVP_CTRL_GCM_GET_TAG, GMAC_TAG_LEN, gmac_tag) != 1) {
		std::cerr << "Something went wrong while trying to save the MAC for the key saved in the file " << pub_key_file << " : {authentification tag can't be extracted}\n";
		return false;
	}

	PubKeyMAC* pkm_data = PubKeyMAC_new();

	pkm_data->pubKeyName = ASN1_PRINTABLESTRING_new();
	if (!ASN1_STRING_set(pkm_data->pubKeyName, reinterpret_cast<const unsigned char*>(pub_key_file.c_str()), static_cast<int>(pub_key_file.length()))) {
		std::cerr << "Something went wrong while trying to save the MAC for the key saved in the file " << pub_key_file << " : {ASN1_PRINTABLESTRING can't be set}\n";
		return false;
	}

	pkm_data->MACKey = ASN1_OCTET_STRING_new();
	if (!ASN1_OCTET_STRING_set(pkm_data->MACKey, sym_gmac_key, SYM_KEY_SIZE)) {
		std::cerr << "Something went wrong while trying to save the MAC for the key saved in the file " << pub_key_file << " : {ASN1_OCTET_STRING can't be set}\n";
		return false;
	}

	pkm_data->MACValue = ASN1_OCTET_STRING_new();
	if (!ASN1_OCTET_STRING_set(pkm_data->MACValue, gmac_tag, GMAC_TAG_LEN)) {
		std::cerr << "Something went wrong while trying to save the MAC for the key saved in the file " << pub_key_file << " : {ASN1_OCTET_STRING can't be set}\n";
		return false;
	}

	unsigned char* der_mac = nullptr;
	int der_mac_len = i2d_PubKeyMAC(pkm_data, &der_mac);
	if (der_mac_len <= 0) {
		std::cerr << "Something went wrong while trying to save the MAC for the key saved in the file " << pub_key_file << " : {ASN1 structure can't be serialized}\n";
		return false;
	}
	string mac_filename;
	if (pub_key_file.find("rsa")!=string::npos)
		mac_filename = this->get_RSA_mac_file();
	else if (pub_key_file.find("ecc")!=string::npos)
		mac_filename = this->get_ECC_mac_file();
	ofstream mac_file(mac_filename, ios::binary | ios::out);

	if (!mac_file.is_open()) {
		std::cerr << "Something went wrong while trying to save the MAC for the key saved in the file " << pub_key_file << " : {MAC file can't be opened}\n";
		return false;
	}

	mac_file.write(reinterpret_cast<const char*>(der_mac), der_mac_len);

	PubKeyMAC_free(pkm_data);
	OPENSSL_free(der_mac);
	mac_file.close();
	free(gmac_tag);
	free(gmac_iv);
	free(sym_gmac_key);
	EVP_CIPHER_CTX_free(gmac_ctx);
	return true;
}