# PROBONITE

Aprés avoir correctement installer TFHE (verifier que les headers sont dans /usr/local/include et le fichier libtfhe-nayuki-portable.dylib est dans /usr/local/lib). On peut compiler le programme avec la commande suivante :

```bash
g++ main.cpp -o main -ltfhe-nayuki-portable
```

Il se peut que des warnings s'affichent, pour les eviter il faut rajouter l'option `std=c++11`.