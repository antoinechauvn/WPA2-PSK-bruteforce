# WPA2-PSK-bruteforce
Bruteforcing WPA2-PSK MIC using IEEE 802.11i knowledge
- **4-Way Handshake**: Protocole de gestion des clés par paire défini par l’amendement 802.11i-2004. Il confirme la possession mutuelle d'une clé principale (*PMK*) par deux parties et distribue une clé temporelle de groupe (GTK).
- **WPA2-PSK (*WPA Personal*)**: Protocole 802.11 implémentant l’authentification à clé partagée
- **Robust Security Network (RSN)**: Le terme "*Robust Security Network*" est utilisé dans les réseaux WiFi pour décrire les améliorations de sécurité incluses dans les variantes IEEE 802.11i et WPA (WiFi Protected Access) 1 et 2. La suite de protocoles s'efforce de compenser les faiblesses associées au **WEP** (*Wired Equivalent Privacy*).
- **PMK (Pairwise Master Key):** La clé de premier ordre utilisée dans le cadre de cet amendement. La PMK peut être dérivée d'une méthode EAP (Extensible Authentication Protocol) ou être obtenue directement à partir d'une clé prépartagée (PSK).
- **PTK (Pairwise Transient Key):** clé dérivée de la clé principale (PMK), de l'adresse de l'authentificateur (AA), de l'adresse du demandeur (SPA), du nonce de l'authentificateur (ANonce) et du nonce du demandeur (SNonce) à l'aide de la fonction pseudo-aléatoire (PRF) et qui est divisée en cinq clés. Cette clé est utilisée pour chiffrer les données entre un client et un AP (unicast). Elle change au moins tous les 65 535 paquets.
- **PSK (Pre-Shared Key):** Clé statique qui est distribuée aux unités du système toujours par des moyens hors bande.  Dans le cadre d’une authentification PSK, la PSK équivaut à la PMK
- **HMAC (Hash-based Message Authentication Code)**: algorithme de hachage cryptographique utilisé pour la vérification de l'intégrité des données et l'authentification des messages. [RFC2104](https://www.ietf.org/rfc/rfc2104.txt)
- **GTK (Group Temporal Key)**: la GTK est utilisée pour le chiffrement des diffusions (broadcast), puisque la PTK n'est utilisée que pour l'AP et le client et qu'aucune autre station ne peut l'écouter, c'est pourquoi vous avez besoin d'une autre clé.
- **PRF (PseudoRandom Function):** Une fonction qui hachure diverses entrées pour obtenir une valeur pseudo-aléatoire.
- **GMK (Group Master Key):** Clé principale de la hiérarchie des clés de groupe
- **MIC (Message Integrity Code):** Valeur générée par une fonction cryptographique à clé symétrique. Si les données d'entrée sont modifiées, une nouvelle valeur ne peut être calculée correctement sans connaître la clé symétrique. Ainsi, la clé secrète protège les données d'entrée contre toute modification indétectable. C'est ce que l'on appelle traditionnellement un code d'authentification des messages (MAC).

![image](https://user-images.githubusercontent.com/83721477/228968930-ecbcbea1-b2b1-4c06-8d0c-25b8c4472e40.png)

## Hiérarchie des clés

![image](https://user-images.githubusercontent.com/83721477/228968954-dee867c2-3be7-490e-af03-4e61a9d32c07.png)

> **PMK = PBKDF2(HMAC-SHA1, PSK, SSID, 4096, 256)**
> 

On utilisera la fonction de dérivation de clé **PBKDF2** dans le but de réduire la vulnérabilité aux attaques par dictionnaire (*bruteforce attack*).

> **PTK = PRF-X (PMK, Pairwise key expansion, Min(AP_Mac, STA_Mac) + Max(AP_Mac, STA_Mac) + Min(ANonce, SNonce) + Max(ANonce, Snonce))**
> 
- || est l'opérateur de concaténation
- SNonce est un nombre généré de manière aléatoire par le client qui sera utilisé pour établir la PTK
- ANonce est un nombre généré de manière aléatoire par l’AP qui sera utilisé pour établir la PTK
- AP_Mac représente l’adresse MAC du point d’accès (Authenticator)
- STA_Mac représente l’adresse MAC du client (Supplicant)

Suivant le standard 802.11i-2004 on retrouve la fonction PRF implémenté comme suit

![image](https://user-images.githubusercontent.com/83721477/228969001-d79f02e8-10a6-4ee6-9f1b-ef3befc252e0.png)

**La taille de la PTK dépend du protocole de chiffrement choisi :**

- 512 bits pour TKIP
- 384 bits pour CCMP

**La PTK est divisée comme suit** :

- **KCK (Key Confirmation Key)** de 128 bits (0-127). On l’utilise pour authentifier les messages (MIC) durant le 4-Way Handshake et le Group Key Handshake.
- **KEK (Key Encryption Key)** de 128 bits (128-255). On l’utilise pour la confidentialité des données durant le 4-Way Handshake et le Group Key Handshake (GTK sera chiffré à l'aide de KEK pour être délivrée au client)
- **TK (Temporary Key) de 128 bits** (256-383). On l’utilise pour le chiffrement des données unicast
- **TMK (Temporary MIC Key)  2 clés de 64 bits** (384-511). On les utilises pour l'authentification des données (seulement dans TKIP). Une clé dédiée est utilisée pour chaque sens de communication.
    - MIC Tx - Utilisé pour les paquets unicast envoyés par les points d'accès.
    - MIC Rx - Utilisé pour les paquets unicast envoyés par les clients.

> **GTK = PRF(GMK, “Group Key Expansion”, AP_MAC || GNonce)**
> 

La taille de la GTK dépend du protocole de chiffrement:

- 256 bits pour TKIP
- 128 bits pour CCMP

**La GTK est divisée comme suit** :

- **GEK (Group Encryption Key)** de 128 bits. On l’utilise pour le chiffrement des données (utilisée par CCMP pour l'authentification et le chiffrement et par TKIP)
- **GIK (Group Integrity Key)** de 128 bits. On l’utilise pour l'authentification des données (utilisée seulement avec TKIP).

> **MIC (Message Integrity Code) = HMAC(SHA1, KCK, EAPOL M2 FRAME)[:16]**
> 

![image](https://user-images.githubusercontent.com/83721477/228969059-3023c954-e648-4aff-8bb0-39f751dd2a90.png)

**Trames EAPOL-Key**

Le HMAC est défini dans la RFC 2104 de l'IETF et le SHA1 dans la FIPS PUB 180-3-2008. La sortie du HMAC-SHA1 est tronquée à ses 128 MSB (octets 0-15 du condensé produit par le HMAC-SHA1), c'est-à-dire que les quatre derniers octets générés sont rejetés.

## Sources

[https://github.com/koutto/pi-pwnbox-rogueap/wiki/05.-WPA-WPA2-Personal-(PSK)-Authentication](https://github.com/koutto/pi-pwnbox-rogueap/wiki/05.-WPA-WPA2-Personal-%28PSK%29-Authentication)

[https://nicholastsmith.wordpress.com/2016/11/15/wpa2-key-derivation-with-anaconda-python/](https://nicholastsmith.wordpress.com/2016/11/15/wpa2-key-derivation-with-anaconda-python/#more-1403)

[https://praneethwifi.in/2019/11/09/4-way-hand-shake-keys-generation-and-mic-verification/](https://praneethwifi.in/2019/11/09/4-way-hand-shake-keys-generation-and-mic-verification/)

[https://avan.sh/posts/wpa2-psk-hacking-explained/](https://avan.sh/posts/wpa2-psk-hacking-explained/)

[https://rex.plil.fr/Enseignement/Reseau/Infonuagique.GIS4/infonuagique038.html](https://rex.plil.fr/Enseignement/Reseau/Infonuagique.GIS4/infonuagique038.html)

[https://github.com/k1nd0ne/ScapyWifi](https://github.com/k1nd0ne/ScapyWifi)

[https://irp.nain-t.net/doku.php/310lansecure:20_wpa2:40_wpa2](https://irp.nain-t.net/doku.php/310lansecure:20_wpa2:40_wpa2)

[https://www.cyberpunk.rs/capturing-wpa-wpa2-handshake](https://www.cyberpunk.rs/capturing-wpa-wpa2-handshake)

[https://repo.zenk-security.com/Protocoles_reseaux_securisation/Securite Wi-Fi - WEP, WPA et WPA2.pdf](https://repo.zenk-security.com/Protocoles_reseaux_securisation/Securite%20Wi-Fi%20-%20WEP,%20WPA%20et%20WPA2.pdf)

IEEE Std 802.11i-2004
