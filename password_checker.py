import re #recherches dans du texte
import hashlib #hachage cryptographique
import requests

def check_strength(password):
    errors=[]
    if len(password)<8:
        errors.append("Le mot de passe est trop court (moins de 8 caractères).")
    if not re.search(r"[A-Z]", password):
        errors.append("Il manque une majuscule.")
    if not re.search(r"[a-z]", password):
        errors.append("Il manque une minuscule.")
    if not re.search(r"[0-9]", password):
        errors.append("Il manque un chiffre")
    if not re.search(r"[$!@#%^_*():/;<>'?]", password):
        errors.append("Il manque un caractère spécial.")
    return errors


def check_pwned(password):

    #On transforme le mot de passe en hash SHA-1 : chaîne de 40 caractères hexadécimaux (160 bits)
    #Mais il serait mieux d'utiliser SHA-3 ou SHA-256 (plus performant et évite les collisions
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()

    #On garde les 5 premiers caractères du hash pour faire un appel anonyme à l'API et ne pas envoyer le mot de passe complet
    prefix = sha1[:5]
    #Et les 5 derniers
    suffix = sha1[5:]

    #On fait un appel à l'API Pwned Passwords (HaveIBeenPwned)
    url = f"https://api.pwnedpasswords.com/range/{prefix}"

    #On récupère une liste de suffixes de hash + nombre de fois où ils ont été vus
    response = requests.get(url)

    #On vérifie localement si le suffixe du hash du mot de passe est dans la réponse
    hashes = (line.split(':') for line in response.text.splitlines())
    for hash_suffix, count in hashes:
        if hash_suffix == suffix:
            return int(count)
    return 0

if __name__ == '__main__':
    password=input("Entrer le mot de passe à vérifier: ")
    issues = check_strength(password)
    if issues:
        for issue in issues:
            print("Le mot de passe n'est pas assez robuste : ", issue)
    else:
        print("Le mot de passe est robuste.")

        #Je vérifie sur la base de données compromises
        print("\n Vérification dans les bases de données compromises...")
        count = check_pwned(password)
        if count:
            print(f" Attention : Ce mot de passe a été trouvé {count} fois dans des fuites de données !")
        else:
            print("Ce mot de passe ne semble pas avoir été compromis.")

