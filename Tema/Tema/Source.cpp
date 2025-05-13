#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include "Entity.h"

int main() {
	Entity* Bob = new Entity(1);
	Bob->generate_EC_key_pair();
	Bob->save_private_key("bobkey_prv","parola");
	Bob->save_pub_key("bobkey_pub");


	//Bob->load_private_key("bobkey_prv", "parola");
	//unsigned char* der_mac = nullptr;
	//size_t der_mac_len = 0;
	//Bob->load_public_key("bobkey_pub",&der_mac,&der_mac_len);
	//if (Bob->verify_public_key_mac(der_mac, der_mac_len))
	//	cout << "MAC VERIFICAT CU SUCCES!";

}