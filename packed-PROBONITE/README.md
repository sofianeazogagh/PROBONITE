# Blind Array Access packed version



## Requirements

* OpenFHE
* OpenMP

## Build

```bash
mkdir build
```

```bash
cd build
```
```bash
cmake ..
```

Modifier le CMakeLists.txt en fonction du code source voulu
* MultiBAAcc.cpp utilise MultiOHS
* BAAcc.cpp utilise un seul OHS

```bash
make
```

Puis lancer l'executable créer.


## Comments

The keys must be generated locally (to heavy for git)