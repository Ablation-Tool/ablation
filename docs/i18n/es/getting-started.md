# Primeros pasos

Pasa de la instalación a tu primer candidato a vulnerabilidad en 15 minutos. Cualquier binario ELF sin símbolos funciona.

---

## Instalación

**Requisitos:** Python 3.10+, pip

```bash
pip install git+https://github.com/Ablation-Tool/ablation
```

Con funciones LLM:

```bash
pip install "git+https://github.com/Ablation-Tool/ablation#egg=ablation[llm]"
```

Desde el código fuente:

```bash
git clone https://github.com/Ablation-Tool/ablation
cd ablation
pip install -e .
```

Verifica la instalación:

```bash
python -c "from ablation.analyzers.binary_context import BinaryContext; print('ok')"
```

---

## Paso 1: Cargar el binario

`BinaryContext` es el punto de entrada para todo análisis. Pasa cualquier binario ELF sin símbolos:

```python
from ablation.analyzers.binary_context import BinaryContext

ctx = BinaryContext.load_or_build('/path/to/binary.so')
print(ctx.summary())
```

**Primera ejecución:** 0.5 a 5 segundos según el tamaño del binario. Ablation construye y guarda en caché en `~/.ablation/cache/<sha256>_<name>.json`.

**Cada ejecución posterior:** 110 ms. La caché está indexada por SHA256, por lo que una compilación diferente del mismo nombre de binario reconstruye automáticamente.

Ejemplo de salida:

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

## Paso 2: Ejecutar un análisis semántico

El análisis es el flujo de trabajo central. Codifica todas las funciones como huellas de comportamiento BERT y realiza consultas por descripción de vulnerabilidad en inglés simple. Usa `sweeps/base_sweep.py` como plantilla, o construye la tuya:

```python
from ablation.analyzers.corpus_builder import CorpusBuilder
from ablation.analyzers.semantic_search import SemanticSearcher
from ablation.analyzers.pattern_library import PatternLibrary

# Construir corpus de descripciones de comportamiento en func_id.db
cb = CorpusBuilder()
cb.build('/path/to/binary.so', product='my-target', version='1.0')

# Construir embeddings BERT (~35s para 19k funciones en CPU)
searcher = SemanticSearcher('~/.ablation/func_id.db')
searcher.build_corpus()

# Consultar por descripción de vulnerabilidad
results = searcher.query(
    "TLV parser that advances pointer without minimum length check",
    top_k=10
)

for r in results:
    print(f"  0x{r.va:x}  {r.name or hex(r.va):<50s}  score={r.score:.3f}")
```

**Tiempo estimado:** 35 a 60 segundos para 19.000 funciones en CPU. Las consultas posteriores al mismo corpus tardan menos de un segundo porque los embeddings están en caché.

---

## Paso 3: Clasificar candidatos

Para cada candidato con puntuación alta, obtén su contexto:

```python
va = 0x1000  # VA candidata de los resultados del análisis

# ¿Qué llama esta función?
print("callees:", ctx.callees_of(va))

# ¿A qué cadenas hace referencia?
print("strings:", ctx.strings_in_func(va))

# ¿Qué la llama?
print("callers:", ctx.callers_of(va))
```

La mayoría de los candidatos tarda dos a tres minutos en clasificarse de esta forma. Si la lista de llamadas contiene funciones de memoria (`memcpy`, `malloc`, `free`) y la cadena de llamantes llega a un punto de entrada de red, procede a la traza manual.

---

## Paso 4: Nombrar funciones confirmadas

Cuando identifiques el propósito de una función, registra su nombre. Los nombres persisten entre sesiones y aparecen en toda la salida de análisis posterior:

```python
ctx.set_name(0x1000, 'proto_parse_message', source='confirmed')

# Los nombres aparecen en todas partes:
print(ctx.callees_of(0x1000))   # etiquetas en lugar de direcciones hexadecimales
print(ctx.names_table())           # todas las funciones nombradas en este binario
```

Los nombres se almacenan en `~/.ablation/function_names.json`, indexados por SHA256 del binario. Sobreviven a reinicios de sesión, movimientos de binarios y reinicios del sistema.

---

## Paso 5: Registrar patrones confirmados

Cuando confirmes una vulnerabilidad real, registra la consulta que la encontró. Se reproducirá automáticamente en binarios futuros:

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

En cualquier análisis futuro, ya sea de una versión diferente de firmware o de otro proveedor, `pl.sweep(searcher)` ejecuta todos los patrones confirmados automáticamente.

---

## Reanudar una sesión

Ablation está diseñado para investigación en múltiples sesiones. Al inicio de cualquier sesión:

```python
# Cargar contexto (110ms -- usa caché)
ctx = BinaryContext.load_or_build('/path/to/binary.so')

# Mostrar todas las funciones nombradas anteriormente
print(ctx.names_table())

# Revisar hallazgos confirmados
from ablation.analyzers.finding_registry import FindingRegistry
fr = FindingRegistry()
fr.list_findings(binary_sha=ctx.sha256[:16])
```

---

## Próximos pasos

- [Flujo de trabajo de búsqueda de vulnerabilidades](../../workflows/vuln-hunting.md) -- ciclo completo desde el análisis hasta el hallazgo listo para divulgación
- [Referencia de módulos](../../module-reference/) -- más de 50 analizadores con parámetros y ejemplos
- [CONTRIBUTING.md](../../../CONTRIBUTING.md) -- cómo añadir patrones, análisis y módulos de analizadores
