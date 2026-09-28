# Démarrage rapide

Passez de l'installation à votre premier candidat à la vulnérabilité en 15 minutes. N'importe quel binaire ELF sans symboles fonctionne.

---

## Installation

**Prérequis:** Python 3.10+, pip

```bash
pip install git+https://github.com/Ablation-Tool/ablation
```

Avec les fonctionnalités LLM:

```bash
pip install "git+https://github.com/Ablation-Tool/ablation#egg=ablation[llm]"
```

Depuis les sources:

```bash
git clone https://github.com/Ablation-Tool/ablation
cd ablation
pip install -e .
```

Vérifiez l'installation:

```bash
python -c "from ablation.analyzers.binary_context import BinaryContext; print('ok')"
```

---

## Étape 1: Charger le binaire

`BinaryContext` est le point d'entrée pour toute analyse. Passez n'importe quel binaire ELF sans symboles:

```python
from ablation.analyzers.binary_context import BinaryContext

ctx = BinaryContext.load_or_build('/path/to/binary.so')
print(ctx.summary())
```

**Première exécution:** 0,5 à 5 secondes selon la taille du binaire. Ablation construit et met en cache dans `~/.ablation/cache/<sha256>_<name>.json`.

**Chaque exécution suivante:** 110 ms. Le cache est indexé par SHA256, donc une compilation différente du même nom de binaire reconstruit automatiquement.

Exemple de sortie:

```
BinaryContext: libservice.so
  sha256     : fdfaceccdc740d82...
  base_va    : 0x0
  func_starts: 19024
  exports    : 14
  plt entries: 187
  strings    : 44821
  call_edges : 58903
  str_xrefs  : 218440 pairs indexed
  named funcs: 0 (overlay)
```

---

## Étape 2: Lancer une analyse sémantique

L'analyse est le flux de travail central. Elle encode toutes les fonctions comme des empreintes comportementales BERT et interroge par description de vulnérabilité en anglais courant. Utilisez `sweeps/base_sweep.py` comme modèle, ou construisez le vôtre:

```python
from ablation.analyzers.corpus_builder import CorpusBuilder
from ablation.analyzers.semantic_search import SemanticSearcher
from ablation.analyzers.pattern_library import PatternLibrary

# Construire le corpus de descriptions comportementales dans func_id.db
cb = CorpusBuilder()
cb.build('/path/to/binary.so', product='my-target', version='1.0')

# Construire les embeddings BERT (~35s pour 19k fonctions sur CPU)
searcher = SemanticSearcher('~/.ablation/func_id.db')
searcher.build_corpus()

# Interroger par description de vulnérabilité
results = searcher.query(
    "TLV parser that advances pointer without minimum length check",
    top_k=10
)

for r in results:
    print(f"  0x{r.va:x}  {r.name or hex(r.va):<50s}  score={r.score:.3f}")
```

**Temps d'exécution attendu:** 35 à 60 secondes pour 19 000 fonctions sur CPU. Les requêtes suivantes sur le même corpus s'exécutent en moins d'une seconde car les embeddings sont en cache.

---

## Étape 3: Trier les candidats

Pour chaque candidat à score élevé, obtenez son contexte:

```python
va = 0x1000  # VA candidat depuis les résultats de l'analyse

# Que fait appel cette fonction?
print("callees:", ctx.callees_of(va))

# Quelles chaînes référence-t-elle?
print("strings:", ctx.strings_in_func(va))

# Qui l'appelle?
print("callers:", ctx.callers_of(va))
```

La plupart des candidats prennent deux à trois minutes pour être triés de cette façon. Si la liste des appelés contient des fonctions mémoire (`memcpy`, `malloc`, `free`) et que la chaîne d'appelants atteint un point d'entrée réseau, procédez au traçage manuel.

---

## Étape 4: Nommer les fonctions confirmées

Quand vous identifiez le rôle d'une fonction, enregistrez son nom. Les noms persistent entre les sessions et apparaissent dans toutes les sorties d'analyse ultérieures:

```python
ctx.set_name(0x1000, 'proto_parse_message', source='confirmed')

# Les noms apparaissent partout:
print(ctx.callees_of(0x1000))   # étiquettes au lieu d'adresses hexadécimales
print(ctx.names_table())           # toutes les fonctions nommées dans ce binaire
```

Les noms sont stockés dans `~/.ablation/function_names.json`, indexés par SHA256 du binaire. Ils survivent aux redémarrages de session, aux déplacements de binaires et aux redémarrages système.

---

## Étape 5: Enregistrer les motifs confirmés

Quand vous confirmez une vraie vulnérabilité, enregistrez la requête qui l'a trouvée. Elle sera rejouée automatiquement sur les futurs binaires:

```python
from ablation.analyzers.pattern_library import PatternLibrary

pl = PatternLibrary()
pl.record_hit(
    query="TLV pointer advance loop with no minimum length check",
    binary_sha="fdfaceccdc740d82",
    va=0x1000,
    confirmed=True,
    vuln_class="infinite_loop",
    cvss=7.5,
)
```

Lors de n'importe quelle analyse future, qu'il s'agisse d'une version de firmware différente ou d'un autre fournisseur, `pl.sweep(searcher)` exécute automatiquement tous les motifs confirmés.

---

## Reprendre une session

Ablation est conçu pour la recherche en plusieurs sessions. Au début de chaque session:

```python
# Charger le contexte (110ms -- utilise le cache)
ctx = BinaryContext.load_or_build('/path/to/binary.so')

# Afficher toutes les fonctions nommées précédemment
print(ctx.names_table())

# Réviser les découvertes confirmées
from ablation.analyzers.finding_registry import FindingRegistry
fr = FindingRegistry()
fr.list_findings(binary_sha=ctx.sha256[:16])
```

---

## Prochaines étapes

- [Flux de travail de chasse aux vulnérabilités](../../workflows/vuln-hunting.md) -- boucle complète de l'analyse à la découverte prête pour la divulgation
- [Référence des modules](../../module-reference/) -- plus de 50 analyseurs avec paramètres et exemples
- [CONTRIBUTING.md](../../../CONTRIBUTING.md) -- comment ajouter des motifs, des analyses et des modules d'analyseurs
