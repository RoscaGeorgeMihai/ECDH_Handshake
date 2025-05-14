#include "SymElements_Asn1.h"

ASN1_SEQUENCE(SymElements) = {
	ASN1_SIMPLE(SymElements,SymElementsID,ASN1_INTEGER),
	ASN1_SIMPLE(SymElements, SymKey, ASN1_OCTET_STRING),
	ASN1_SIMPLE(SymElements,IV,ASN1_OCTET_STRING)
}ASN1_SEQUENCE_END(SymElements);

IMPLEMENT_ASN1_FUNCTIONS(SymElements);