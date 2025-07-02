import time
import hashlib

def slow_print(text, delay=0.03):
    for c in text:
        print(c, end='', flush=True)
        time.sleep(delay)
    print()

def banner():
    print("\033[92m")
    print(r"""
 ____             _           _____                  _           
|  _ \  __ _ _ __| | _____   |_   _| __ __ _  ___ ___(_) ___  ___ 
| | | |/ _` | '__| |/ / _ \    | || '__/ _` |/ __/ _ \ |/ _ \/ __|
| |_| | (_| | |  |   <  __/    | || | | (_| | (_|  __/ |  __/\__ \
|____/ \__,_|_|  |_|\_\___|    |_||_|  \__,_|\___\___|_|\___||___/

""")
    print("\033[0m")

def mission_scan():
    banner()
    slow_print("Mission 1 : Scan réseau", 0.03)
    slow_print("Commande : scan", 0.02)

    targets = [
        {"ip": "192.168.1.1", "vulnerable": False},
        {"ip": "192.168.1.12", "vulnerable": False},
        {"ip": "192.168.1.42", "vulnerable": True},
    ]

    while True:
        cmd = input("root@dark:~# ").strip().lower()
        if cmd == "scan":
            for target in targets:
                status = "❗ VULNÉRABLE" if target["vulnerable"] else "🔐 Sécurisée"
                slow_print(f"[{target['ip']}] - {status}", 0.02)
            break
        else:
            slow_print("Commande invalide. Tape 'scan' pour lancer le scan.", 0.02)
    input("Appuie sur Entrée pour continuer...")

def mission_bruteforce():
    banner()
    slow_print("Mission 2 : Bruteforce root", 0.03)

    wordlist = [
        "admin", "password", "root", "123456", "darkroot", "toor", "cyberroot", "letmein"
    ]
    correct_password = "toor"
    for pwd in wordlist:
        slow_print(f"Test : {pwd}", 0.01)
        if pwd == correct_password:
            slow_print("Mot de passe trouvé : toor ✅", 0.03)
            input("Appuie sur Entrée pour continuer...")
            return
    slow_print("Mot de passe non trouvé ❌", 0.03)
    input("Appuie sur Entrée pour continuer...")

def mission_camhack():
    banner()
    slow_print("Mission 3 : Piratage de la webcam", 0.03)
    slow_print("Commande : camjack", 0.02)

    while True:
        cmd = input("root@target:~# ").strip().lower()
        if cmd == "camjack":
            slow_print("Connexion à la caméra en cours...", 0.02)
            slow_print("Image capturée : [webcam_feed.jpg] 📷", 0.03)
            break
        else:
            slow_print("Commande incorrecte. Réessaye.", 0.02)
    input("Appuie sur Entrée pour continuer...")

def mission_injection():
    banner()
    slow_print("Mission 4 : Injection de script", 0.03)
    slow_print("Commande : inject payload.py", 0.02)

    while True:
        cmd = input("root@target:~# ").strip().lower()
        if cmd == "inject payload.py":
            slow_print("Script injecté et exécuté ! 🐍", 0.03)
            break
        else:
            slow_print("Commande invalide.", 0.02)
    input("Appuie sur Entrée pour continuer...")

def mission_hash_crack():
    banner()
    slow_print("Mission 5 : Cracker le hash MD5", 0.03)
    target_hash = hashlib.md5("cyberroot".encode()).hexdigest()
    slow_print(f"Hash cible : {target_hash}", 0.03)

    wordlist = [
        "admin", "password", "root", "123456", "darkroot", "toor", "cyberroot", "letmein"
    ]

    for word in wordlist:
        hashed = hashlib.md5(word.encode()).hexdigest()
        if hashed == target_hash:
            slow_print(f"Match trouvé : {word} ✅", 0.03)
            input("Appuie sur Entrée pour continuer...")
            return
    slow_print("Échec : aucun mot trouvé ❌", 0.03)
    input("Appuie sur Entrée pour continuer...")

def mission_malware_upload():
    banner()
    slow_print("Mission 6 : Upload de malware (fictif)", 0.03)
    slow_print("Commande : upload backdoor.exe", 0.02)

    while True:
        cmd = input("root@victime:~# ").strip().lower()
        if cmd == "upload backdoor.exe":
            slow_print("Malware uploadé dans /tmp/backdoor.exe", 0.03)
            break
        else:
            slow_print("Commande incorrecte.", 0.02)
    input("Appuie sur Entrée pour continuer...")

def mission_flag():
    banner()
    slow_print("Mission 7 : Capture du FLAG", 0.03)
    slow_print("Commande : cat /root/flag.txt", 0.02)

    while True:
        cmd = input("root@system:~# ").strip().lower()
        if cmd == "cat /root/flag.txt":
            slow_print("FLAG{you_pwned_the_game} 🌟", 0.03)
            slow_print("Félicitations, toutes les missions sont terminées 🎉", 0.03)
            break
        else:
            slow_print("Commande incorrecte.", 0.02)
    input("Appuie sur Entrée pour quitter.")

def main():
    mission_scan()
    mission_bruteforce()
    mission_camhack()
    mission_injection()
    mission_hash_crack()
    mission_malware_upload()
    mission_flag()

if __name__ == "__main__":
    main()
