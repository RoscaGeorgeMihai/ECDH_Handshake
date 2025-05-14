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
public:
	HandshakeManager();
	HandshakeManager(Entity* entity1,Entity* entity2);
	bool change_entities(Entity* entity1, Entity* entity2);
	bool load_keys_and_verify_MAC(Entity* entity);
	bool save_sym_elements();
	bool establish_handshake();
	~HandshakeManager();
};

