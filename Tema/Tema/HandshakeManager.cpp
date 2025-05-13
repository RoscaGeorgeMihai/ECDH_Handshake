#include "HandshakeManager.h"

HandshakeManager::HandshakeManager()
{
	this->entityA = nullptr;
	this->entityB = nullptr;
}

HandshakeManager::HandshakeManager(Entity* entity1, Entity* entity2)
{
	this->entityA = entity1;
	this->entityB = entity2;
}

bool HandshakeManager::establish_handshake()
{

	return true;
}

HandshakeManager::~HandshakeManager()
{
	this->entityA = nullptr;
	this->entityB = nullptr;
}
