A utility to encrypt multiples files with multiple passwords into a single ciphertext that then can be decrypted to multiple files given the right password.

#### Usage

To encrypt multiple files:
```
$ ncipher -e a.txt b.txt -o ciphertext
Password for file "a.txt": somepassword
Password for file "b.txt": anotherpassword
```
To decrypt:
```
$ ncipher -d ciphertext -o out.txt
Password: anotherpassword
```
`out.txt` would then be decrypted with the same content as `b.txt`.

#### References

The algorithm was strongly inspired by [Sultanik, E. (2014, 27 June). Lenticrypt: a Provably Plausibly Deniable Cryptosystem; or, This Picture of Cats is Also a Pricture of Dogs?. POC || GTFO, 4th edition, p.22](https://www.alchemistowl.org/pocorgtfo/pocorgtfo04.pdf)
