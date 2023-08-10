# HashFailer

HashFailer is an open-source tool for identifying and cracking various hash types using Hashcat and John the Ripper. It's designed to help security professionals, researchers, and enthusiasts with hash analysis and password recovery.

<img width="447" alt="image" src="https://github.com/xpinux/Hashfailer/assets/33750676/6f3d55af-8126-49a4-9faa-88648a415fd2">

## Features

- Supports a wide range of hash types, making it versatile for different scenarios.
- Integrates both Hashcat and John the Ripper for efficient cracking.
- Provides automatic hash type identification, reducing manual effort.
- Easy-to-use command-line interface with intuitive options.


## Requirements

- Python 3.6 or higher
- [Hashcat](https://hashcat.net/hashcat/)
- [John the Ripper](https://www.openwall.com/john/
- `pip install termcolor`

##Usage
1. Run the script:
`python hashfailer.py`
2. Follow the prompts to enter the hash you want to identify and crack.
3.Choose Hashcat or John the Ripper for cracking.

## Wordlist Requirements

To effectively utilize HashFailer with Hashcat and John the Ripper, it's essential to have appropriate wordlists for dictionary-based attacks. These wordlists contain potential passwords that will be employed in the cracking process. Here's how you can establish the necessary wordlists:

The default wordlist used is rockyou.txt, located in the directory provided below. If you're using Kali Linux, it's recommended to employ this wordlist. Make sure to unpack it from the tar archive.
  `dictionary = "/usr/share/wordlists/rockyou.txt"`

For Advanced Users: If you're an advanced user, you can navigate to the code section where the 'directory' variable is defined and modify it to point to your preferred directory and wordlist.

##License
This project is open source and available under the MIT License.

%%Contributing
Contributions are welcome! Please feel free to submit pull requests or open issues if you encounter any problems or have suggestions.

##Disclaimer
This tool is intended for educational and security research purposes only. Use this tool responsibly and only on systems you have explicit permission to access.
