#include "TransactionsManager.h"
#include "Transaction_Asn1.h"
#pragma warning(disable:4996)
#include <sstream>
#include <iostream>
#include <vector>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <string>
#include <fstream>

#define IV_LEN 16
#define BLOCK_SIZE 16

unsigned char* TransactionsManager::encrypt_block(unsigned char* plain_text,int plain_text_len,unsigned char* key)
{
	unsigned char* cipher_text = (unsigned char*)malloc(BLOCK_SIZE);
	int update_len = 0, final_len = 0;
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

	if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, key, nullptr) != 1) {
		std::cerr << "Something went wrong while trying to encrypt block: {Encryption init failed!}\n";
		return nullptr;
	}

	EVP_CIPHER_CTX_set_padding(ctx, 0);

	if (EVP_EncryptUpdate(ctx, cipher_text, &update_len, plain_text, plain_text_len) != 1) {
		std::cerr << "Something went wrong while trying to encrypt block: {Encryption update failed!}\n";
		return nullptr;
	}

	if (EVP_EncryptFinal_ex(ctx, cipher_text, &final_len) != 1) {
		std::cerr << "Something went wrong while trying to encrypt block: {Encryption final failed!}\n";
		return nullptr;
	}

	EVP_CIPHER_CTX_free(ctx);

	return cipher_text;
}

TransactionsManager::TransactionsManager()
{
    this->encrypted_data = nullptr;
	this->transaction_id = 0;
	this->source_id = 0;
	this->dest_id = 0;
	this->subject.clear();
    this->sym_elements_id = 0;
	this->message.clear();
}

void TransactionsManager::encrypt_data(unsigned char* key, unsigned char* iv)
{
    unsigned char* inv_iv = (unsigned char*)malloc(IV_LEN);
    for (int i = 0; i < IV_LEN; i++)
        inv_iv[i] = iv[IV_LEN - i - 1];

    int total_blocks = (this->message.length() + BLOCK_SIZE - 1) / BLOCK_SIZE;

    this->encrypted_data = (unsigned char*)malloc((total_blocks + 1) * BLOCK_SIZE);

    unsigned char* plaintext_block = (unsigned char*)malloc(BLOCK_SIZE);
    unsigned char* modified_cipher_block = (unsigned char*)malloc(BLOCK_SIZE);
    unsigned char* iv_param = (unsigned char*)malloc(IV_LEN);
    memcpy(iv_param, iv, IV_LEN);

    for (int block_num = 0; block_num < total_blocks; block_num++) {
        int start_pos = block_num * BLOCK_SIZE;
        int remaining_bytes = this->message.length() - start_pos;
        int bytes_to_copy = min(BLOCK_SIZE, remaining_bytes);

        memcpy(plaintext_block, this->message.c_str() + start_pos, bytes_to_copy);

        if (bytes_to_copy < BLOCK_SIZE) {
            int padding_len = BLOCK_SIZE - bytes_to_copy;
            for (int i = bytes_to_copy; i < BLOCK_SIZE; i++)
                plaintext_block[i] = padding_len;
        }

        unsigned char* cipher_block = this->encrypt_block(iv_param, BLOCK_SIZE, key);
        memcpy(iv_param, cipher_block, IV_LEN);

        for (int i = 0; i < BLOCK_SIZE; i++)
            modified_cipher_block[i] = cipher_block[i] ^ inv_iv[i] ^ plaintext_block[i];

        memcpy(this->encrypted_data + block_num * BLOCK_SIZE, modified_cipher_block, BLOCK_SIZE);

        free(cipher_block);
    }

    for (int i = 0; i < BLOCK_SIZE; i++)
        this->encrypted_data[total_blocks * BLOCK_SIZE + i] = 0xFF;

    free(plaintext_block);
    free(modified_cipher_block);
    free(iv_param);
    free(inv_iv);
}

void TransactionsManager::decrypt_data(unsigned char* key, unsigned char* iv)
{
    unsigned char* inv_iv = (unsigned char*)malloc(IV_LEN);
    for (int i = 0; i < IV_LEN; i++)
        inv_iv[i] = iv[IV_LEN - i - 1];

    this->message.clear();
    unsigned char* ciphertext_block = (unsigned char*)malloc(BLOCK_SIZE);
    unsigned char* plaintext_block = (unsigned char*)malloc(BLOCK_SIZE);
    unsigned char* iv_param = (unsigned char*)malloc(IV_LEN);
    memcpy(iv_param, iv, IV_LEN);

    int block_num = 0;

    while (true) {
        memcpy(ciphertext_block, this->encrypted_data + block_num * BLOCK_SIZE, BLOCK_SIZE);

        bool is_end_marker = true;
        for (int i = 0; i < BLOCK_SIZE; i++) {
            if (ciphertext_block[i] != 0xFF) {
                is_end_marker = false;
                break;
            }
        }

        if (is_end_marker) {
            break; 
        }

        unsigned char* aes_block = this->encrypt_block(iv_param, BLOCK_SIZE, key);
        memcpy(iv_param, aes_block, IV_LEN);

        for (int i = 0; i < BLOCK_SIZE; i++)
            plaintext_block[i] = aes_block[i] ^ inv_iv[i] ^ ciphertext_block[i];

        unsigned char* next_block = this->encrypted_data + (block_num + 1) * BLOCK_SIZE;
        bool next_is_end = true;
        for (int i = 0; i < BLOCK_SIZE; i++) {
            if (next_block[i] != 0xFF) {
                next_is_end = false;
                break;
            }
        }

        if (next_is_end) {
            int padding_len = plaintext_block[BLOCK_SIZE - 1];
            bool valid_padding = true;

            if (padding_len > 0 && padding_len <= BLOCK_SIZE) {
                for (int i = BLOCK_SIZE - padding_len; i < BLOCK_SIZE; i++) {
                    if (plaintext_block[i] != padding_len) {
                        valid_padding = false;
                        break;
                    }
                }

                if (valid_padding) {
                    this->message.append((char*)plaintext_block, BLOCK_SIZE - padding_len);
                }
                else {
                    this->message.append((char*)plaintext_block, BLOCK_SIZE);
                }
            }
            else {
                this->message.append((char*)plaintext_block, BLOCK_SIZE);
            }
        }
        else {
            this->message.append((char*)plaintext_block, BLOCK_SIZE);
        }

        free(aes_block);
        block_num++;
    }

    free(plaintext_block);
    free(ciphertext_block);
    free(iv_param);
    free(inv_iv);
}

bool TransactionsManager::sign_and_save_transaction(Entity* sender)
{
    if (sender == nullptr) {
        std::cerr << "Something went wrong while trying to sign the transaction: {sender entity is null}\n";
        return false;
    }

    Transaction* asn1_transaction = Transaction_new();
    if(asn1_transaction ==nullptr) {
        std::cerr << "Something went wrong while trying to sign the transaction: {transaction struct can't be created}\n";
        return false;
    }
    ASN1_INTEGER_set(asn1_transaction->TransactionID, this->transaction_id);
    ASN1_STRING_set(asn1_transaction->Subject, this->subject.c_str(), this->subject.length());
    ASN1_INTEGER_set(asn1_transaction->SenderID, this->source_id);
    ASN1_INTEGER_set(asn1_transaction->ReceiverID, this->dest_id);
    ASN1_INTEGER_set(asn1_transaction->SymElementsID, this->sym_elements_id);
    int total_blocks = (this->message.length() + BLOCK_SIZE - 1) / BLOCK_SIZE;
    int encrypted_len = (total_blocks + 1) * BLOCK_SIZE;
    ASN1_OCTET_STRING_set(asn1_transaction->EncryptedData, this->encrypted_data,encrypted_len);

    asn1_transaction->TransactionSign = ASN1_OCTET_STRING_new();
    ASN1_OCTET_STRING_set(asn1_transaction->TransactionSign, NULL, 0);

    unsigned char* serialised_der = nullptr;
    int serialised_der_len = i2d_Transaction(asn1_transaction, &serialised_der);
    if (serialised_der_len <= 0) {
        std::cerr << "Something went wrong while trying to sign the transaction: {serialisation failed}\n";
        return false;
    }

    unsigned char* hash = (unsigned char*)malloc(SHA256_DIGEST_LENGTH);
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, serialised_der, serialised_der_len);
    SHA256_Final(hash, &ctx);

    sender->load_RSA_private_key();
    RSA* sender_rsa_key = sender->get_RSA_key();
    if(sender_rsa_key==nullptr) {
        std::cerr << "Something went wrong while trying to sign the transaction: {sender doesn't have a rsa key}\n";
        return false;
    }

    EVP_PKEY* evp_rsa_key = EVP_PKEY_new();
    EVP_PKEY_set1_RSA(evp_rsa_key, sender_rsa_key);

    EVP_PKEY_CTX* pkey_ctx = EVP_PKEY_CTX_new(evp_rsa_key, NULL);
    EVP_PKEY_sign_init(pkey_ctx);
    EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PADDING);
    EVP_PKEY_CTX_set_signature_md(pkey_ctx, EVP_sha256());
    size_t sign_len;
    EVP_PKEY_sign(pkey_ctx, NULL, &sign_len, hash, SHA256_DIGEST_LENGTH);
    unsigned char* signature = (unsigned char*)OPENSSL_malloc(sign_len);
    if (EVP_PKEY_sign(pkey_ctx, signature, &sign_len, hash, SHA256_DIGEST_LENGTH) != 1){
        std::cerr << "Something went wrong while trying to sign the transaction: {transaction couldn't be signed}\n";
        return false;
    }
    
    EVP_PKEY_CTX_free(pkey_ctx);
    EVP_PKEY_free(evp_rsa_key);

    ASN1_OCTET_STRING_set(asn1_transaction->TransactionSign, signature, sign_len);

    unsigned char* der_transaction = nullptr;
    int der_transaction_len = i2d_Transaction(asn1_transaction, &der_transaction);
    if (der_transaction_len <= 0) {
        std::cerr << "Something went wrong while trying to sign the transaction: {couldn't DER encode}\n";
        return false;
    }

    string transaction_filename = to_string(this->source_id) + "_" + to_string(this->dest_id) + "_" + to_string(this->transaction_id) + ".trx";
    ofstream transaction_file(transaction_filename, ios::binary | ios::out);
    if (!transaction_file.is_open()) {
        std::cerr << "Something went wrong while trying to save the transaction: {file can't be opened}\n";
        return false;
    }
    transaction_file.write((const char*)der_transaction, der_transaction_len);
    transaction_file.close();

    OPENSSL_free(signature);
    OPENSSL_free(serialised_der);
    return true;
}

bool TransactionsManager::break_transaction(string transaction)
{
	stringstream strstream(transaction);
	string segment;
	vector<string> segments_array;
	while (getline(strstream, segment, '/')) {
		segments_array.push_back(segment);
	}
	if (segments_array.size() != 5)
		return false;

	this->transaction_id = stoi(segments_array[0]);
	this->source_id = stoi(segments_array[1]);
	this->dest_id = stoi(segments_array[2]);
	this->subject = segments_array[3];
	this->message = segments_array[4];

	return true;
}

void TransactionsManager::print_transaction()
{
	cout << this->transaction_id << "/" << this->source_id << "/" << this->dest_id << "/" << this->subject << "/" << this->message << endl;
}

TransactionsManager::~TransactionsManager()
{
	this->transaction_id = 0;
	this->source_id = 0;
	this->dest_id = 0;
	this->subject.clear();
	this->message.clear();
}
