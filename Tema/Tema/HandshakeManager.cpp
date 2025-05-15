#define _CRT_SECURE_NO_WARNINGS
#pragma warning(disable : 4996)
#include "HandshakeManager.h"
#include "SymElements_Asn1.h"
#include <iostream>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/kdf.h>
#include <fstream>

#define COORD_LEN 32
#define SYMKEY_LEN 16
#define IV_LEN 16

HandshakeManager::HandshakeManager()
{
	this->entityA = nullptr;
	this->entityB = nullptr;
	this->sym_key = nullptr;
	this->iv = nullptr;
	this->handshakes_counter = 0;
}

HandshakeManager::HandshakeManager(Entity* entity1, Entity* entity2)
{
	this->entityA = entity1;
	this->entityB = entity2;
	this->sym_key = nullptr;
	this->iv = nullptr;
	this->handshakes_counter = 0;
}

bool HandshakeManager::change_entities(Entity* entity1, Entity* entity2)
{
	this->entityA = entity1;
	this->entityB = entity2;
	return true;
}

bool HandshakeManager::load_keys_and_verify_MAC(Entity* entity)
{
	entity->load_ECC_private_key();
	unsigned char* der_mac = nullptr;
	size_t der_mac_len = 0;
	entity->load_ECC_key_mac(&der_mac, &der_mac_len);
	if (!entity->verify_public_key_mac(entity->get_ECC_pub_key_file(), der_mac, der_mac_len)) {
		std::cerr << "Something went wrong while trying to establish the handshake: {entity with id: "<< entity->get_id() << " doesn't have a valid public key}\n";
		return false;
	}
	free(der_mac);
	der_mac = nullptr;
	der_mac_len = 0;
	unsigned char* der_mac_rsa = nullptr;
	entity->load_RSA_public_key();
	entity->load_RSA_key_mac(&der_mac_rsa, &der_mac_len);
	if (!entity->verify_public_key_mac(entity->get_RSA_pub_key_file(),der_mac_rsa, der_mac_len)) {
		std::cerr << "Something went wrong while trying to establish the handshake: {entity with id: " << entity->get_id() << " doesn't have a valid public key}\n";
		return false;
	}
	free(der_mac);
	return true;
}

int HandshakeManager::save_sym_elements()
{
	SymElements* elements_data = SymElements_new();

	elements_data->SymElementsID = ASN1_INTEGER_new();
	if (!ASN1_INTEGER_set(elements_data->SymElementsID,this->handshakes_counter)) {
		std::cerr << "Something went wrong while trying to save the symElements for the handshake no. " << this->handshakes_counter << " : {ASN1_INTEGER can't be set}\n";
		return false;
	}

	elements_data->SymKey = ASN1_OCTET_STRING_new();
	if (!ASN1_OCTET_STRING_set(elements_data->SymKey, this->sym_key, SYMKEY_LEN)) {
		std::cerr << "Something went wrong while trying to save the symElements for the handshake no. " << this->handshakes_counter << " : {ASN1_OCTET_STRING can't be set}\n";
		return false;
	}

	elements_data->IV = ASN1_OCTET_STRING_new();
	if (!ASN1_OCTET_STRING_set(elements_data->IV, this->iv, IV_LEN)) {
		std::cerr << "Something went wrong while trying to save the symElements for the handshake no. " << this->handshakes_counter << " : {ASN1_OCTET_STRING can't be set}\n";
		return false;
	}

	unsigned char* der_sym = nullptr;
	int der_sym_len = i2d_SymElements(elements_data, &der_sym);

	if (der_sym_len <= 0) {
		std::cerr << "Something went wrong while trying to save the symElements for the handshake no. " << this->handshakes_counter << " : {ASN1 structure can't be serialized}\n";
		return false;
	}

	unsigned char* base64_sym = (unsigned char*)malloc((der_sym_len + 2) / 3 * 4);
	int base64_output_len = EVP_EncodeBlock(base64_sym, der_sym, der_sym_len);
	if (base64_output_len <= 0) {
		std::cerr << "Something went wrong while trying to save the symElements for the handshake no. " << this->handshakes_counter << " : {base64 encoding failed}\n";
		return false;
	}
	string symfilename = to_string(this->handshakes_counter) + ".sym";
	ofstream sym_file(symfilename, ios::binary | ios::out);

	if (!sym_file.is_open()) {
		std::cerr << "Something went wrong while trying to save the symElements for the handshake no. " << this->handshakes_counter << " : {can't open file}\n";
		return false;
	}

	sym_file.write(reinterpret_cast<const char*>(base64_sym), base64_output_len);

	sym_file.close();

	SymElements_free(elements_data);
	this->handshakes_counter += 1;
	return (this->handshakes_counter - 1);
}

bool HandshakeManager::establish_handshake()
{
	if (entityA == nullptr || entityB == nullptr) {
		std::cerr << "Something went wrong while trying to establish the handshake: {one or more entities are not set}\n";
		return false;
	}
	if (!load_keys_and_verify_MAC(entityA))
		return false;
	if (!load_keys_and_verify_MAC(entityB))
		return false;

	EC_KEY* entityA_key = entityA->get_ECC_key();
	EC_KEY* entityB_key = entityB->get_ECC_key();

	const BIGNUM* priv_key_A = EC_KEY_get0_private_key(entityA_key);
	const EC_POINT* pub_key_B = EC_KEY_get0_public_key(entityB_key);

	const EC_GROUP* group = EC_KEY_get0_group(entityA_key);
	EC_POINT* shared_point = EC_POINT_new(group);
	if (!EC_POINT_mul(group, shared_point, NULL, pub_key_B, priv_key_A, NULL)) {
		std::cerr << "Something went wrong while trying to establish the handshake: {can't calculate EC_POINT_mul}\n";
		return false;
	}

	BIGNUM* x = BN_new();
	BIGNUM* y = BN_new();

	if (!EC_POINT_get_affine_coordinates_GFp(group, shared_point, x, y, NULL)) {

		std::cerr << "Something went wrong while trying to establish the handshake: {can't get the coordinates for shared point}\n";

		return false;

	}

	unsigned char x_coord[COORD_LEN];
	unsigned char y_coord[COORD_LEN];

	if (BN_bn2binpad(x, x_coord, COORD_LEN) <= 0)
		std::cerr << "Something went wrong while trying to establish the handshake: {can't convert x coordinates in binary}\n";

	if (BN_bn2binpad(y, y_coord, COORD_LEN) <= 0)
		std::cerr << "Something went wrong while trying to establish the handshake: {can't convert y coordinates in binary}\n";

	unsigned char* x_coord_hash = (unsigned char*)malloc(COORD_LEN);

	EVP_MD_CTX* digest_ctx = EVP_MD_CTX_new();

	EVP_DigestInit_ex(digest_ctx, EVP_sha256(), NULL);
	EVP_DigestUpdate(digest_ctx, x_coord, COORD_LEN);
	unsigned int hash_len;
	EVP_DigestFinal(digest_ctx, x_coord_hash, &hash_len);
	if (hash_len == 0) {
		std::cerr << "Something went wrong while trying to establish the handshake: {hashing the x_coord failed}\n";
		return false;
	}

	unsigned char* msb = (unsigned char*)malloc(SYMKEY_LEN);
	unsigned char* lsb = (unsigned char*)malloc(SYMKEY_LEN);
	unsigned char* sym_left = (unsigned char*)malloc(SYMKEY_LEN);
	memcpy(msb, x_coord_hash, SYMKEY_LEN);
	memcpy(lsb, x_coord_hash + 16, SYMKEY_LEN);

	for (int i = 0; i < SYMKEY_LEN; i++)
		sym_left[i] = msb[i] ^ lsb[i];

	free(msb);
	free(lsb);
	EVP_MD_CTX_free(digest_ctx);

	unsigned char* sym_right = (unsigned char*)malloc(SYMKEY_LEN);
	unsigned char* output = (unsigned char*)malloc(SYMKEY_LEN * 2);
	if (PKCS5_PBKDF2_HMAC((const char*)y_coord, COORD_LEN, NULL, 0, 10000, EVP_sha384(), SYMKEY_LEN * 2, output) != 1) {
		std::cerr << "Something went wrong while trying to establish the handshake: {failed to apply PBKDF2 for y_coord}\n";
		return false;
	}
	memcpy(sym_right, output, SYMKEY_LEN);

	this->sym_key = (unsigned char*)malloc(SYMKEY_LEN);
	for (int i = 0; i < SYMKEY_LEN; i++)
		sym_key[i] = sym_left[i] ^ sym_right[i];

	this->iv = (unsigned char*)malloc(IV_LEN);
	memcpy(iv, output + SYMKEY_LEN, IV_LEN);

	free(output);
	return true;
}

HandshakeManager::~HandshakeManager()
{
	this->entityA = nullptr;
	this->entityB = nullptr;
}
