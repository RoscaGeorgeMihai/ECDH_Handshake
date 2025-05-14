#include <openssl/asn1t.h>

typedef struct SymElements {
	ASN1_INTEGER* SymElementsID;
	ASN1_OCTET_STRING* SymKey;
	ASN1_OCTET_STRING* IV;
}SymElements;

DECLARE_ASN1_FUNCTIONS(SymElements);
