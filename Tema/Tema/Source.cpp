#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include "Entity.h"
#include "HandshakeManager.h"
#include "TransactionsManager.h"
#include "Logger.h"
#include <fstream>
#include <vector>

using namespace std;

Logger* actions_logger = Logger::getInstance();

Entity* get_entity_by_id(vector<Entity*> entities,int id) {
	for (int i = 0; i < entities.size(); i++)
		if (entities[i]->get_id() == id)
			return entities[i];

	return nullptr;
}

int main(int argc, char* argv[]) {
	vector<Entity*> entities;
	vector<TransactionsManager*> transactions;
	HandshakeManager* handshake = new HandshakeManager();
	int entities_number = 0;
	int transactions_number = 0;
	string password;
	int entity_id;

	ifstream input(argv[1]);
	input >> entities_number;

	for (int i = 0; i < entities_number; i++) {
		input >> entity_id;
		input >> password;
		Entity* new_entity = new Entity(entity_id, password);
		new_entity->register_entity();
		entities.push_back(new_entity);
	}

	input >> transactions_number;
	string transaction_line;
	input.ignore(numeric_limits<streamsize>::max(), '\n');
	for (int i = 0; i < transactions_number; i++) {
		getline(input, transaction_line);
		TransactionsManager* new_transaction = new TransactionsManager();
		new_transaction->break_transaction(transaction_line);
		transactions.push_back(new_transaction);
	}

	int sym_elements_id = 0;
	for (int i = 0; i < transactions.size(); i++) {
		if (handshake->get_entityA() != nullptr && handshake->get_entityB() != nullptr) {
			if (handshake->get_entityA()->get_id() != transactions[i]->get_source_id() && handshake->get_entityB()->get_id() != transactions[i]->get_dest_id() ||
				handshake->get_entityA()->get_id() != transactions[i]->get_dest_id() && handshake->get_entityB()->get_id() != transactions[i]->get_dest_id()) {
				Entity* source_entity = get_entity_by_id(entities, transactions[i]->get_source_id());
				Entity* dest_entity = get_entity_by_id(entities, transactions[i]->get_dest_id());
				handshake->change_entities(source_entity, dest_entity);
				
				actions_logger->log_action("entity with the specified id initiated a transaction\n", handshake->get_entityA()->get_id());
				actions_logger->log_action("handshake initiated by entity with the specified id\n", handshake->get_entityA()->get_id());
				
				if(handshake->establish_handshake())
					actions_logger->log_action("handshake initiated by entity with the specified id successfully ended\n", handshake->get_entityA()->get_id());
				else
					actions_logger->log_action("handshake initiated by entity with the specified id ended unexpectedly, check the console log for more info\n", handshake->get_entityA()->get_id());
				
				sym_elements_id=handshake->save_sym_elements();
			}
		}
		if (handshake->get_entityA() == nullptr || handshake->get_entityB() == nullptr) {
			Entity* source_entity = get_entity_by_id(entities, transactions[i]->get_source_id());
			Entity* dest_entity = get_entity_by_id(entities, transactions[i]->get_dest_id());
			handshake->change_entities(source_entity, dest_entity);
			
			actions_logger->log_action("entity with the specified id initiated a transaction\n", handshake->get_entityA()->get_id());
			actions_logger->log_action("handshake initiated by entity with the specified id\n", handshake->get_entityA()->get_id());
			
			if (handshake->establish_handshake())
				actions_logger->log_action("handshake initiated by entity with the specified id successfully ended\n", handshake->get_entityA()->get_id());
			else
				actions_logger->log_action("handshake initiated by entity with the specified id ended unexpectedly, check the console log for more info\n", handshake->get_entityA()->get_id());
			
			sym_elements_id=handshake->save_sym_elements();
		}
		else
			actions_logger->log_action("entity with the specified id initiated a transaction\n", handshake->get_entityA()->get_id());
		transactions[i]->set_sym_elements_id(sym_elements_id);

		transactions[i]->encrypt_data(handshake->get_sym_key(), handshake->get_iv());
		//transactions[i]->decrypt_data(handshake->get_sym_key(), handshake->get_iv());
		transactions[i]->sign_and_save_transaction(handshake->get_entityA());
		actions_logger->log_action("transaction initiated by the entity with the specified id has been successfully processed\n", handshake->get_entityA()->get_id());
	}
	//actions_logger->close_file();
	//actions_logger->readLogBlob();

	delete handshake;
}