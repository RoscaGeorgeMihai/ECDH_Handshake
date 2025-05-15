# ECDH_Handshake

Folosind C/C++ si biblioteca OpenSSL, implementati o aplicatie care sa permita managementul unor tranzactii intre diferite entitati. Aplicatia va oferi urmatoarele functionalitati:  

- generarea a cate unei perechi de chei pentru fiecare entitate, folosind o curba eliptica pe 256 biti. Cheile astfel generate vor fi salvate in fisiere specifice, cheile private fiind salvate in mod criptat, iar cheile publice vor avea asignata cate un MAC (GMAC - cheie simetrica generata prin PBKDF2 cu SHA3-256 aplicat peste diferenta de timp pana la 050505050505Z, fara salt) stocat intr-un fisier corespondent fiecarei chei. Formatul de stocare a acestor chei este PEM.  
- realizarea unui handshake intre enitati prin efectuarea unui schimb de chei ECDH, folosind cheile generate anterior a caror autenticitate este validata. Dupa realizarea cu succes a schimbului de chei, se va efectua derivarea cheii simetrice (SymKey), folosita de AES-128-FancyOFB, pe baza urmatorului mecanism:  
    - peste valoarea componentei x este aplicata functia SHA-256, rezultatul fiind impartit in 2 elemente de cate 16 octeti, intre care se va face xor. Rezultatul final reprezinta elementul SymLeft.  
    - componenta y este folosita ca input pentru PBKDF2 cu SHA-384, fara salt. Rezultatul final reprezinta elementul SymRight.  
    - SymKey va consta in aplicare xor intre SymLeft si First_16_bytes (SymRight).  
    - Octetii neutilizati din SymRight vor fi folosiyi pentru extragerea tuturor celorlalte elemente necesare pentru criptarea simetrica.  
- AES-128-FancyOFB este modul de lucrul prezentat in exercitiile din laboratorul 4, cu mentiunea ca operatia "+ 5" va fi inlocuita cu "xor inv_IV", unde inv_IV este IV-ul inversat (IV-ul citit in sens invers).  
- fiecare tranzactie va fi semnata de emitent folosind o cheie RSA pe 3072 biti, generata la inregistrarea entitatii in sistem.  
Toate informatiile generate vor fi salvate in fisiere specifice, astfel:  

- cheile asimetrice in fisiere PEM;  
- mac-urile cheilor publice, in fisier raw, continand codificarea DER a elementelor de forma:   
    PubKeyMAC := Sequence  {   
	    PubKeyName: PrintableString  
	    MACKey: OCTET STRING  
	    MACValue: OCTET STRING  
    }  

- elementele simetrice necesare criptarii mesajelor, in fisiere codificate cu Base64, continand codificarea DER a elementelor de forma:  
    SymElements := Sequence  {  
	    SymElementsID: Integer  
	    SymKey: OCTET STRING   
	    IV: OCTET STRING  
    }  

- tranzactiile dintre entitati in fisiere raw, continand codificarea DER a elementelor de forma:  
    Transaction := Sequence  {  
	    TransactionID: Integer  
	    Subject: Printable String  
	    SenderID: Integer  
	    ReceiverID: Integer   
	    SymElementsID: Integer  
	    EncryptedData: OCTET STRING  
	    TransactionSign: OCTET STRING  
    }  

Se va realiza o jurnalizare a acțiunilor executate de entități, acestea fiind apoi salvate într-un fișier binar de tip blob. Formatul de salvare a datelor va fi de forma: \<data\>\<timp\>\<entitate\>\<actiune\>.

## Output  
Standarde salvare chei:  
- cheile RSA in format PKCS1
- cheile ECC in format PKCS8

