#pragma once
#include "Entity.h"

class HandshakeManager
{
private:
	Entity* entityA;
	Entity* entityB;
public:
	HandshakeManager();
	HandshakeManager(Entity* entity1,Entity* entity2);
	bool establish_handshake();
	~HandshakeManager();
};

