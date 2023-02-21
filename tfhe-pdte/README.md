# PROBONITE


Aprés avoir correctement installer TFHE (verifier que les headers sont dans /usr/local/include et le fichier libtfhe-nayuki-portable.dylib est dans /usr/local/lib). On peut compiler le fichier FBootsrrapping toujours en travaux avec la commande suivante :

```bash
g++ -std=c++11 FBootstrapping.cpp -o test -ltfhe-nayuki-portable
```

