#pragma once
#include "Entity.h"

class HandshakeManager
{
private:
	Entity* entityA;
	Entity* entityB;

	long handshakes_counter;
	unsigned char* iv;
	unsigned char* sym_key;
	bool load_keys_and_verify_MAC(Entity* entity);
public:
	HandshakeManager();
	HandshakeManager(Entity* entity1,Entity* entity2);

	Entity* get_entityA() { return this->entityA; }
	Entity* get_entityB() { return this->entityB; }
	unsigned char* get_sym_key() { return this->sym_key; }
	unsigned char* get_iv() { return this->iv; }

	bool change_entities(Entity* entity1, Entity* entity2);
	int save_sym_elements();
	bool establish_handshake();
	~HandshakeManager();
};

