# cyber-da2


The digital assignment 2 for cyber security course, Fall 2017, by Ganesan R

### Usage
    app.py [ -e file_to_encrypt ] [-d decrypt_file_name ] [-r recipient's name] [-o output_file_name] [-g name_of_person_to_generate_keys_for] [-u owner_of_private_key]


### Generate keys for bob:

```bash
$ app.py -g bob
```
### How to encrypt secret.txt to send to bob:

```bash
$ app.py -e secret.txt -o secret.enc -r bob
```
### How to decrypt as bob:

```bash
$ app.py -d secret.enc -u bob -o secret.dec
```