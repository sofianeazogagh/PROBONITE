# PROBONITE implemented with openfhe



## Requirements

* OpenFHE

## Build

```bash
cd src
mkdir build
```

```bash
cd build
```
```bash
cmake ..
```

Modifier le CMakeLists.txt en fonction de
* PROBONITE pour les differentes primitive de PROBONITE
* FBoostrapping pour un public blind array access
* les autres fichiers pour des tests


```bash
make
```

Puis lancer l'executable créer.
