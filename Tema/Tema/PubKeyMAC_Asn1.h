#include <openssl/asn1t.h>
#include <openssl/safestack.h>

typedef struct PubKeyMAC {
	ASN1_PRINTABLESTRING* pubKeyName;
	ASN1_OCTET_STRING* MACKey;
	ASN1_OCTET_STRING* MACValue;
}PubKeyMAC;

DECLARE_ASN1_FUNCTIONS(PubKeyMAC);