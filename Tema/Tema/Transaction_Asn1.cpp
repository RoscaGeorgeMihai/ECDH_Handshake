#include "Transaction_Asn1.h"

ASN1_SEQUENCE(Transaction) = {
	ASN1_SIMPLE(Transaction,TransactionID,ASN1_INTEGER),
	ASN1_SIMPLE(Transaction,Subject,ASN1_PRINTABLESTRING),
	ASN1_SIMPLE(Transaction,SenderID,ASN1_INTEGER),
	ASN1_SIMPLE(Transaction,ReceiverID,ASN1_INTEGER),
	ASN1_SIMPLE(Transaction,SymElementsID,ASN1_INTEGER),
	ASN1_SIMPLE(Transaction,EncryptedData,ASN1_OCTET_STRING),
	ASN1_SIMPLE(Transaction,TransactionSign,ASN1_OCTET_STRING)
}ASN1_SEQUENCE_END(Transaction);

IMPLEMENT_ASN1_FUNCTIONS(Transaction);