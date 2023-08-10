import re
from termcolor import colored
import subprocess
import tempfile
import os

# Supported hash types and their corresponding regex patterns, hashcat modes, and John the Ripper modes
HASH_TYPES = [
    {
        "name": "MD5",
        "regex": r"^[a-fA-F0-9]{32}$",
        "hashcat_mode": "0",
        "john_mode": "raw-md5"
    },
    {
        "name": "SHA1",
        "regex": r"^[a-fA-F0-9]{40}$",
        "hashcat_mode": "100",
        "john_mode": "raw-sha1"
    },
    {
        "name": "SHA256",
        "regex": r"^[a-fA-F0-9]{64}$",
        "hashcat_mode": "1400",
        "john_mode": "raw-sha256"
    },
    {
        "name": "SHA512",
        "regex": r"^[a-fA-F0-9]{128}$",
        "hashcat_mode": "1700",
        "john_mode": "raw-sha512"
    },
    {
        "name": "Argon2",
        "regex": r"^\$argon2(id?|d?|i?)\$v=\d+\$m=\d+,t=\d+,p=\d+\$.+\$.+$",
        "hashcat_mode": "16*",
        "john_mode": "argon2"
    },
    {
        "name": "bcrypt",
        "regex": r"^\$2[axyb]\$.{56}$",
        "hashcat_mode": "3200",
        "john_mode": "bcrypt"
    },
    {
        "name": "PBKDF2-HMAC-SHA256",
        "regex": r"^\$pbkdf2-sha256\$\d+\$.{1,32}\$.{1,44}$",
        "hashcat_mode": "10900",
        "john_mode": "PBKDF2-HMAC-SHA256"
    },
        {
        "name": "NTLM",
        "regex": r"^[a-fA-F0-9]{32}$",
        "hashcat_mode": "1000",
        "john_mode": "nt"
    },
    {
        "name": "LM",
        "regex": r"^[a-fA-F0-9]{16}:[a-fA-F0-9]{16}$",
        "hashcat_mode": "3000",
        "john_mode": "lm"
    },
    {
        "name": "Unix DES",
        "regex": r"^[a-zA-Z0-9./]{13}$",
        "hashcat_mode": "1500",
        "john_mode": "des"
    },
    {
        "name": "Unix MD5",
        "regex": r"^\$1\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{22}$",
        "hashcat_mode": "500",
        "john_mode": "md5crypt"
    },
    {
        "name": "Unix SHA256",
        "regex": r"^\$5\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{43}$",
        "hashcat_mode": "7400",
        "john_mode": "sha256crypt"
    },
    {
        "name": "Unix SHA512",
        "regex": r"^\$6\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{86}$",
        "hashcat_mode": "1800",
        "john_mode": "sha512crypt"
    },
    {
        "name": "MySQL323",
        "regex": r"^[a-fA-F0-9]{16}$",
        "hashcat_mode": "200",
        "john_mode": "mysql"
    },
    {
        "name": "MySQL4.1/MySQL5",
        "regex": r"^\*[a-fA-F0-9]{40}$",
        "hashcat_mode": "300",
        "john_mode": "mysql-sha1"
    },
    {
        "name": "PostgreSQL MD5",
        "regex": r"^md5[a-fA-F0-9]{32}$",
        "hashcat_mode": "900",
        "john_mode": "md5"
    },
    {
        "name": "Oracle 11g/12c",
        "regex": r"^S:[a-fA-F0-9]{16}:[a-fA-F0-9]{32}$",
        "hashcat_mode": "112",
        "john_mode": "raw-sha1"
    },
    {
        "name": "Oracle 7-10g",
        "regex": r"^[a-fA-F0-9]{16}$",
        "hashcat_mode": "3100",
        "john_mode": "DES"
    },
    {
        "name": "Cisco-PIX MD5",
        "regex": r"^[a-zA-Z0-9/+]{16}$",
        "hashcat_mode": "2400",
        "john_mode": "md5pix"
    },
    {
        "name": "Cisco-ASA MD5",
        "regex": r"^[a-zA-Z0-9/+]{32}$",
        "hashcat_mode": "2410",
        "john_mode": "md5asa"
    },
    {
        "name": "Cisco-IOS SHA256",
        "regex": r"^\$8\$[a-zA-Z0-9./]{14}\$[a-zA-Z0-9./]{43}$",
        "hashcat_mode": "9200",
        "john_mode": "sha256crypt"
    },
    {
        "name": "Cisco $7$ Type",
        "regex": r"^7[0-9a-fA-F]{2,}$",
        "hashcat_mode": "5700",
        "john_mode": "cisco7"
    },
    {
        "name": "MSSQL(2000)",
        "regex": r"^0x0100[a-fA-F0-9]{88}$",
        "hashcat_mode": "131",
        "john_mode": "mssql"
    },
    {
        "name": "MSSQL(2005)",
        "regex": r"^0x0100[a-fA-F0-9]{88}$",
        "hashcat_mode": "132",
        "john_mode": "mssql05"
    },
    {
        "name": "MSSQL(2012)",
        "regex": r"^0x0200[a-fA-F0-9]{128}$",
        "hashcat_mode": "1731",
        "john_mode": "mssql12"
    },
    {
        "name": "phpass",
        "regex": r"^\$P\$.{31}$",
        "hashcat_mode": "400",
        "john_mode": "phpass"
    },
    {
        "name": "Django (SHA-1)",
        "regex": r"^(sha1|{SHA})[a-zA-Z0-9./]{29}$",
        "hashcat_mode": "101",
        "john_mode": "raw-sha1"
    },
    {
        "name": "Django (PBKDF2-HMAC-SHA256)",
        "regex": r"^\$pbkdf2-django\$.{1,32}\$.{1,44}$",
        "hashcat_mode": "10000",
        "john_mode": "pbkdf2-hmac-sha256"
    },
    {
        "name": "WPA/WPA2",
        "regex": r"^(?:WPA|WPA2):[0-9a-fA-F]{64}:[0-9a-zA-Z_\-]+:[0-9a-zA-Z_\-]+",
        "hashcat_mode": "2500",
        "john_mode": "wpapsk"
    },
    {
        "name": "Kerberos 5 AS-REQ Pre-Auth etype 23",
        "regex": r"^\$krb5pa\$23\$.+\$[a-fA-F0-9]{32}$",
        "hashcat_mode": "7500",
        "john_mode": "krb5pa-md5"
    },
    {
        "name": "Kerberos 5 TGS-REP etype 23",
        "regex": r"^\$krb5tgs\$23\$.+\$[a-fA-F0-9]{32}$",
        "hashcat_mode": "13100",
        "john_mode": "krb5tgs-md5"
    },
    {
        "name": "Drupal7",
        "regex": r"^\$S\$.{52}$",
        "hashcat_mode": "7900",
        "john_mode": "drupal7"
    },
    {
        "name": "vBulletin < v3.8.5",
        "regex": r"^[a-fA-F0-9]{32}:[a-fA-F0-9]{3}$",
        "hashcat_mode": "2611",
        "john_mode": "md5"
    },
    {
        "name": "vBulletin >= v3.8.5",
        "regex": r"^[a-fA-F0-9]{32}:[a-fA-F0-9]{30}$",
        "hashcat_mode": "2711",
        "john_mode": "md5"
    },
    {
        "name": "IP.Board/IPB2",
        "regex": r"^[a-fA-F0-9]{32}:.{5}$",
        "hashcat_mode": "2811",
        "john_mode": "md5"
    },
    {
        "name": "MyBB",
        "regex": r"^[a-fA-F0-9]{32}:[a-fA-F0-9]{8}$",
        "hashcat_mode": "3711",
        "john_mode": "md5"
    },
    {
        "name": "SMF (Simple Machines Forum) >= v1.1",
        "regex": r"^[a-fA-F0-9]{40}:[a-zA-Z0-9]{8}$",
        "hashcat_mode": "121",
        "john_mode": "raw-sha1"
    },
    {
        "name": "Apache MD5",
        "regex": r"^\$apr1\$.{8}\$[a-zA-Z0-9./]{22}$",
        "hashcat_mode": "1600",
        "john_mode": "md5apr1"
    },
    {
        "name": "Apache SHA1",
        "regex": r"^\{SHA\}[a-zA-Z0-9./]{27}=$",
        "hashcat_mode": "101",
        "john_mode": "raw-sha1"
    },
    {
        "name": "HMAC-SHA1",
        "regex": r"^[a-fA-F0-9]{40}:[a-zA-Z0-9+/]{1,}$",
        "hashcat_mode": "150",
        "john_mode": "hmac-sha1"
    },
    {
        "name": "HMAC-SHA256",
        "regex": r"^[a-fA-F0-9]{64}:[a-zA-Z0-9+/]{1,}$",
        "hashcat_mode": "1450",
        "john_mode": "hmac-sha256"
    },
    {
        "name": "HMAC-SHA512",
        "regex": r"^[a-fA-F0-9]{128}:[a-zA-Z0-9+/]{1,}$",
        "hashcat_mode": "1750",
        "john_mode": "hmac-sha512"
    },
    {
        "name": "SHA-3(Keccak-256)",
        "regex": r"^[a-fA-F0-9]{64}$",
        "hashcat_mode": "5000",
        "john_mode": "raw-keccak-256"
    },
    {
        "name": "SHA-3(Keccak-512)",
        "regex": r"^[a-fA-F0-9]{128}$",
        "hashcat_mode": "5100",
        "john_mode": "raw-keccak-512"
    },
    {
        "name": "RIPEMD-160",
        "regex": r"^[a-fA-F0-9]{40}$",
        "hashcat_mode": "6000",
        "john_mode": "ripemd-160"
    },
    {
        "name": "Whirlpool",
        "regex": r"^[a-fA-F0-9]{128}$",
        "hashcat_mode": "6100",
        "john_mode": "whirlpool"
    },
    {
        "name": "GOST R 34.11-94",
        "regex": r"^[a-fA-F0-9]{64}$",
        "hashcat_mode": "6900",
        "john_mode": "gost"
    },
    {
        "name": "bcrypt",
        "regex": r"^\$2[ayb]\$[0-9]{2}\$[a-zA-Z0-9./]{53}$",
        "hashcat_mode": "3200",
        "john_mode": "bcrypt"
    },
    {
        "name": "scrypt",
        "regex": r"^\$7\$[a-zA-Z0-9./]{14}\$[a-zA-Z0-9./]{43}$",
        "hashcat_mode": "8900",
        "john_mode": "scrypt"
    },
    {
        "name": "PBKDF2-HMAC-SHA1",
        "regex": r"^\$pbkdf2\$[0-9]+\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{27}=$",
        "hashcat_mode": "12000",
        "john_mode": "pbkdf2-hmac-sha1"
    },
    {
        "name": "PBKDF2-HMAC-SHA256",
        "regex": r"^\$pbkdf2-sha256\$[0-9]+\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{43}$",
        "hashcat_mode": "10900",
        "john_mode": "pbkdf2-hmac-sha256"
    },
    {
        "name": "PBKDF2-HMAC-SHA512",
        "regex": r"^\$pbkdf2-sha512\$[0-9]+\$[a-zA-Z0-9./]{16}\$[a-zA-Z0-9./]{86}$",
        "hashcat_mode": "7100",
        "john_mode": "pbkdf2-hmac-sha512"
    },
    {
        "name": "MS Office <= 2003 MD5",
        "regex": r"^[a-fA-F0-9]{32}:[a-fA-F0-9]+:[a-fA-F0-9]{32}$",
        "hashcat_mode": "9700",
        "john_mode": "oldoffice"
    },
    {
        "name": "MS Office 2007",
        "regex": r"^\$office\$2007\$[0-9]+\$[a-zA-Z0-9./]+\$[a-zA-Z0-9./]+",
        "hashcat_mode": "9400",
        "john_mode": "office"
    },
        {
        "name": "LM",
        "regex": r"^[a-fA-F0-9]{16}$",
        "hashcat_mode": "3000",
        "john_mode": "lm"
    },
    {
        "name": "MS Office 2013",
        "regex": r"^\$office\$2013\$[0-9]+\$[a-zA-Z0-9./]+\$[a-zA-Z0-9./]+",
        "hashcat_mode": "9600",
        "john_mode": "office"
    },
    {
        "name": "MS Office 2016/2019",
        "regex": r"^\$office\$2016\$[0-9]+\$[a-zA-Z0-9./]+\$[a-zA-Z0-9./]+",
        "hashcat_mode": "21800",
        "john_mode": "office"
    },
    {
        "name": "PDF 1.1-1.3 (Acrobat 2-4)",
        "regex": r"^\$pdf\$[0-9]\*3\*40\*[0-9]+(?:[0-9a-fA-F]{2}\*){32}[a-fA-F0-9]+",
        "hashcat_mode": "10400",
        "john_mode": "pdf"
    },
    {
        "name": "PDF 1.4-1.6 (Acrobat 5-8)",
        "regex": r"^\$pdf\$[0-9]\*3\*128\*[0-9]+(?:[0-9a-fA-F]{2}\*){32}[a-fA-F0-9]+",
        "hashcat_mode": "10500",
        "john_mode": "pdf"
    },
    {
        "name": "PDF 1.7 (Acrobat 9)",
        "regex": r"^\$pdf\$[0-9]\*4\*256\*[0-9]+(?:[0-9a-fA-F]{2}\*){32}[a-fA-F0-9]+",
        "hashcat_mode": "10600",
        "john_mode": "pdf"
    },
    {
        "name": "PDF 1.7 (Acrobat X/XI)",
        "regex": r"^\$pdf\$[0-9]\*6\*256\*[0-9]+(?:[0-9a-fA-F]{2}\*){32}[a-fA-F0-9]+",
        "hashcat_mode": "10700",
        "john_mode": "pdf"
    },
    {
        "name": "PostgreSQL MD5",
        "regex": r"^md5[a-fA-F0-9]{32}$",
        "hashcat_mode": "10",
        "john_mode": "postgres"
    },
    {
        "name": "Oracle 7-10g (DES)",
        "regex": r"^[a-fA-F0-9]{16}$",
        "hashcat_mode": "3100",
        "john_mode": "oracle"
    },
    {
        "name": "Oracle 11g/12c (SHA1)",
        "regex": r"^S:[a-fA-F0-9]{16}\$[a-fA-F0-9]{40}$",
        "hashcat_mode": "112",
        "john_mode": "oracle12c"
    },
    {
        "name": "MySQL 3.x",
        "regex": r"^[a-fA-F0-9]{16}$",
        "hashcat_mode": "200",
        "john_mode": "mysql323"
    },
    {
        "name": "MySQL 4.x-5.x",
        "regex": r"^[a-fA-F0-9]{40}$",
        "hashcat_mode": "300",
        "john_mode": "mysql-sha1"
    },
    {
        "name": "MongoDB (SCRAM-SHA-1)",
        "regex": r"^SCRAM-SHA-1\$[a-zA-Z0-9+/]{4}\$[a-zA-Z0-9+/]{16}\$[a-zA-Z0-9+/]{28}$",
        "hashcat_mode": "SCRAM-SHA-1",
        "john_mode": "mongodb"
    },
    {
        "name": "Cisco IOS Type 4 (SHA256)",
        "regex": r"^\$4\$[a-zA-Z0-9./]{43}$",
        "hashcat_mode": "9200",
        "john_mode": "cisco4"
    },
    {
        "name": "Cisco IOS Type 5 (MD5)",
        "regex": r"^\$1\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{22}$",
        "hashcat_mode": "500",
        "john_mode": "md5crypt"
    },
    {
        "name": "Cisco IOS Type 7 (Vigenere)",
        "regex": r"^[a-fA-F0-9]{4}(?:[a-fA-F0-9]{2})+$",
        "hashcat_mode": "NOT_SUPPORTED",
        "john_mode": "cisco7"
    },
    {
        "name": "Django (PBKDF2-SHA256)",
        "regex": r"^\$pbkdf2_sha256\$[0-9]+\$[a-zA-Z0-9+/]+\$[a-zA-Z0-9+/]{43}$",
        "hashcat_mode": "10000",
        "john_mode": "pbkdf2-hmac-sha256"
    },
    {
        "name": "Drupal 7 (SHA512)",
        "regex": r"^\$S\$[a-zA-Z0-9./]{52}$",
        "hashcat_mode": "7900",
        "john_mode": "drupal7"
    },
       {
        "name": "SHA3-224",
        "regex": r"^[a-fA-F0-9]{56}$",
        "hashcat_mode": "17400",
        "john_mode": "sha3-224"
    },
    {
        "name": "SHA3-256",
        "regex": r"^[a-fA-F0-9]{64}$",
        "hashcat_mode": "17500",
        "john_mode": "sha3-256"
    },
    {
        "name": "SHA3-384",
        "regex": r"^[a-fA-F0-9]{96}$",
        "hashcat_mode": "17600",
        "john_mode": "sha3-384"
    },
    {
        "name": "SHA3-512",
        "regex": r"^[a-fA-F0-9]{128}$",
        "hashcat_mode": "17700",
        "john_mode": "sha3-512"
    },
    {
        "name": "Keccak-224",
        "regex": r"^[a-fA-F0-9]{56}$",
        "hashcat_mode": "17800",
        "john_mode": "keccak-224"
    },
    {
        "name": "Keccak-256",
        "regex": r"^[a-fA-F0-9]{64}$",
        "hashcat_mode": "17900",
        "john_mode": "keccak-256"
    },
    {
        "name": "Keccak-384",
        "regex": r"^[a-fA-F0-9]{96}$",
        "hashcat_mode": "18000",
        "john_mode": "keccak-384"
    },
    {
        "name": "Keccak-512",
        "regex": r"^[a-fA-F0-9]{128}$",
        "hashcat_mode": "18100",
        "john_mode": "keccak-512"
    },
    {
        "name": "Snefru-128",
        "regex": r"^[a-fA-F0-9]{32}$",
        "hashcat_mode": "NOT_SUPPORTED",
        "john_mode": "snefru-128"
    },
    {
        "name": "Snefru-256",
        "regex": r"^[a-fA-F0-9]{64}$",
        "hashcat_mode": "NOT_SUPPORTED",
        "john_mode": "snefru-256"
    },
    {
        "name": "Tiger-192",
        "regex": r"^[a-fA-F0-9]{48}$",
        "hashcat_mode": "NOT_SUPPORTED",
        "john_mode": "tiger"
    },
    {
        "name": "SipHash",
        "regex": r"^[a-fA-F0-9]{16}$",
        "hashcat_mode": "NOT_SUPPORTED",
        "john_mode": "siphash"
    },
    {
        "name": "Panama",
        "regex": r"^[a-fA-F0-9]{32}$",
        "hashcat_mode": "NOT_SUPPORTED",
        "john_mode": "panama"
    },
    {
        "name": "NTLMv2",
        "regex": r"^[a-zA-Z0-9]+::[a-zA-Z0-9]+:[a-fA-F0-9]+:[a-fA-F0-9]+(:.+)?$",
        "hashcat_mode": "5600",
        "john_mode": "netntlmv2"
    },
{
    "name": "Unix MD5",
    "regex": r"^\$1\$[a-zA-Z0-9./]{0,8}\$[a-zA-Z0-9./]{21}$",
    "hashcat_mode": "500",
    "john_mode": "md5crypt"
},
{
    "name": "MD4",
    "regex": r"^[a-fA-F0-9]{32}$",
    "hashcat_mode": "900",
    "john_mode": "raw-md4"
},
{
    "name": "ZIP",
    "regex": r"^\$pkzip2\$[a-zA-Z0-9\/.+]+$",
    "hashcat_mode": "13600",
    "john_mode": "zip",
},
{
    "name": "RAR3-hp",
    "regex": r"^\$RAR3\$[\*]{0,1}\d+\*[a-fA-F0-9]{16}\*[a-fA-F0-9]{32}$",
    "hashcat_mode": "12500",
    "john_mode": "rar",
},
{
    "name": "RAR5",
    "regex": r"^\$rar5\$16\*[a-fA-F0-9]{16}\*[a-fA-F0-9]{32}$",
    "hashcat_mode": "13000",
    "john_mode": "rar5",
},
{
    "name": "7z",
    "regex": r"^\$7z\$[a-zA-Z0-9\/.+]+$",
    "hashcat_mode": "11600",
    "john_mode": "7z",
}




]

def crack_hash(tool, hash_input, mode, dictionary):
    if tool == "hashcat":
        cmd = ["hashcat", "-m", mode, "-a", "0", hash_input, dictionary]
    elif tool == "john":
        # Create a temporary file containing the hash
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as temp_file:
            temp_file.write(hash_input)
            temp_file_path = temp_file.name

        cmd = ["john", "--format=" + mode, "--wordlist=" + dictionary, temp_file_path]

    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        print(colored(f"Error: {e}", "red"))
    finally:
        if tool == "john":
            # Remove the temporary file
            os.remove(temp_file_path)
        
def identify_hash(hash_str):
    matches = []
    for hash_type in HASH_TYPES:
        regexes = hash_type.get("regexes", [hash_type["regex"]])
        for regex in regexes:
            if re.match(regex, hash_str):
                matches.append(hash_type)
                break

    total_matches = len(matches)
    if total_matches == 0:
        return [("Unknown", "", "", 100.0)]

    probability = 100.0 / total_matches
    results = []
    for match in matches:
        results.append((match["name"], match["hashcat_mode"], match["john_mode"], probability))

    return results


if __name__ == "__main__":
    hash_input = input("Enter the hash to identify: ")

    try:
        hash_results = identify_hash(hash_input)
    except Exception as e:
        print(colored(f"Error: {e}", "red"))
        exit()

    if len(hash_results) == 1:
        hash_name, hashcat_mode, john_mode, probability = hash_results[0]
        print(colored(f"{probability:.2f}% {hash_name} (Hashcat mode: {hashcat_mode}, John the Ripper mode: {john_mode})", "green"))
    else:
        print(colored("Multiple hash types detected:", "yellow"))
        for i, (hash_name, hashcat_mode, john_mode, probability) in enumerate(hash_results):
            print(colored(f"{probability:.2f}% {hash_name} (Hashcat mode: {hashcat_mode}, John the Ripper mode: {john_mode})", "green"))
            if i == 0:
                print(colored("This is the most likely hash type.\n", "cyan"))
                most_likely_hash = (hash_name, hashcat_mode, john_mode, probability)

        # Update the hash type to the most likely one
        hash_name, hashcat_mode, john_mode, probability = most_likely_hash

    choice = input(colored("Do you want to use Hashcat or John the Ripper to crack the hash? (Enter 'hashcat', 'john', or 'none'): ", "yellow")).lower()
    if choice in ["hashcat", "john"]:
        dictionary = "/usr/share/wordlists/rockyou.txt"
        mode = hashcat_mode if choice == "hashcat" else john_mode
        crack_hash(choice, hash_input, mode, dictionary)
    elif choice == "none":
        print(colored("No cracking tool selected. Exiting.", "yellow"))
    else:
        print(colored("Invalid selection. Exiting.", "red"))
