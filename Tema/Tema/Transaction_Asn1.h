#include <openssl/asn1t.h>

typedef struct Transaction {
	ASN1_INTEGER* TransactionID;
	ASN1_PRINTABLESTRING* Subject;
	ASN1_INTEGER* SenderID;
	ASN1_INTEGER* ReceiverID;
	ASN1_INTEGER* SymElementsID;
	ASN1_OCTET_STRING* EncryptedData;
	ASN1_OCTET_STRING* TransactionSign;
}Transaction;

DECLARE_ASN1_FUNCTIONS(Transaction);
