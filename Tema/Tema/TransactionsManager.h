#pragma once
#include <string>
#include "Entity.h"
using namespace std;

class TransactionsManager
{
private:
	int transaction_id;
	int source_id;
	int dest_id;
	string subject;
	string message;
	unsigned char* encrypted_data;
	int sym_elements_id;

	unsigned char* encrypt_block(unsigned char* plaintext, int plaintext_len,unsigned char* key);
public:
	TransactionsManager();

	int get_transaction_id(){ return this->transaction_id; }
	int get_source_id() { return this->source_id; }
	int get_dest_id() { return this->dest_id; }
	string get_subject() { return this->subject; }
	string get_message() { return this->message; }
	unsigned char* get_encrypted_data() { return this->encrypted_data; }

	void set_sym_elements_id(int sym_elements) { this->sym_elements_id = sym_elements; }

	void encrypt_data(unsigned char* key,unsigned char* iv);
	void decrypt_data(unsigned char* key, unsigned char* iv);

	bool sign_and_save_transaction(Entity* sender);

	bool break_transaction(string transaction);
	void print_transaction();
	~TransactionsManager();
};

