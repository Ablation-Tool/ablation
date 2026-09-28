# Primeiros passos

Vá da instalação ao seu primeiro candidato a vulnerabilidade em 15 minutos. Qualquer binário ELF sem símbolos funciona.

---

## Instalação

**Requisitos:** Python 3.10+, pip

```bash
pip install git+https://github.com/Ablation-Tool/ablation
```

Com recursos LLM:

```bash
pip install "git+https://github.com/Ablation-Tool/ablation#egg=ablation[llm]"
```

A partir do código-fonte:

```bash
git clone https://github.com/Ablation-Tool/ablation
cd ablation
pip install -e .
```

Verifique a instalação:

```bash
python -c "from ablation.analyzers.binary_context import BinaryContext; print('ok')"
```

---

## Passo 1: Carregar o binário

`BinaryContext` é o ponto de entrada para toda análise. Passe qualquer binário ELF sem símbolos:

```python
from ablation.analyzers.binary_context import BinaryContext

ctx = BinaryContext.load_or_build('/path/to/binary.so')
print(ctx.summary())
```

**Primeira execução:** 0,5 a 5 segundos dependendo do tamanho do binário. O Ablation constrói e armazena em cache em `~/.ablation/cache/<sha256>_<name>.json`.

**Cada execução subsequente:** 110 ms. O cache é indexado por SHA256, portanto uma compilação diferente do mesmo nome de binário reconstrói automaticamente.

Exemplo de saída:

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

## Passo 2: Executar uma varredura semântica

A varredura é o fluxo de trabalho central. Ela codifica todas as funções como impressões digitais comportamentais BERT e consulta por descrição de vulnerabilidade em inglês simples. Use `sweeps/base_sweep.py` como modelo ou construa o seu próprio:

```python
from ablation.analyzers.corpus_builder import CorpusBuilder
from ablation.analyzers.semantic_search import SemanticSearcher
from ablation.analyzers.pattern_library import PatternLibrary

# Construir corpus de descrições comportamentais em func_id.db
cb = CorpusBuilder()
cb.build('/path/to/binary.so', product='my-target', version='1.0')

# Construir embeddings BERT (~35s para 19k funções na CPU)
searcher = SemanticSearcher('~/.ablation/func_id.db')
searcher.build_corpus()

# Consultar por descrição de vulnerabilidade
results = searcher.query(
    "TLV parser that advances pointer without minimum length check",
    top_k=10
)

for r in results:
    print(f"  0x{r.va:x}  {r.name or hex(r.va):<50s}  score={r.score:.3f}")
```

**Tempo esperado:** 35 a 60 segundos para 19.000 funções na CPU. Consultas subsequentes ao mesmo corpus levam menos de um segundo porque os embeddings estão em cache.

---

## Passo 3: Triagem de candidatos

Para cada candidato com alta pontuação, obtenha seu contexto:

```python
va = 0x1000  # VA candidato dos resultados da varredura

# O que esta função chama?
print("callees:", ctx.callees_of(va))

# Quais strings ela referencia?
print("strings:", ctx.strings_in_func(va))

# O que a chama?
print("callers:", ctx.callers_of(va))
```

A maioria dos candidatos leva dois a três minutos para triagem dessa forma. Se a lista de chamadas contém funções de memória (`memcpy`, `malloc`, `free`) e a cadeia de chamadores alcança um ponto de entrada de rede, prossiga para o rastreamento manual.

---

## Passo 4: Nomear funções confirmadas

Quando você identificar o propósito de uma função, registre seu nome. Os nomes persistem entre sessões e aparecem em toda saída de análise subsequente:

```python
ctx.set_name(0x1000, 'proto_parse_message', source='confirmed')

# Os nomes aparecem em todo lugar:
print(ctx.callees_of(0x1000))   # rótulos em vez de endereços hexadecimais
print(ctx.names_table())           # todas as funções nomeadas neste binário
```

Os nomes são armazenados em `~/.ablation/function_names.json`, indexados pelo SHA256 do binário. Sobrevivem a reinicializações de sessão, movimentos de binários e reinicializações do sistema.

---

## Passo 5: Registrar padrões confirmados

Quando você confirmar uma vulnerabilidade real, registre a consulta que a encontrou. Ela será reproduzida automaticamente em binários futuros:

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

Em qualquer varredura futura, seja de uma versão diferente de firmware ou de outro fornecedor, `pl.sweep(searcher)` executa todos os padrões confirmados automaticamente.

---

## Retomar uma sessão

O Ablation foi projetado para pesquisa em múltiplas sessões. No início de qualquer sessão:

```python
# Carregar contexto (110ms -- usa cache)
ctx = BinaryContext.load_or_build('/path/to/binary.so')

# Exibir todas as funções nomeadas anteriormente
print(ctx.names_table())

# Revisar descobertas confirmadas
from ablation.analyzers.finding_registry import FindingRegistry
fr = FindingRegistry()
fr.list_findings(binary_sha=ctx.sha256[:16])
```

---

## Próximos passos

- [Fluxo de trabalho de caça a vulnerabilidades](../../workflows/vuln-hunting.md) -- ciclo completo da varredura até a descoberta pronta para divulgação
- [Referência de módulos](../../module-reference/) -- mais de 50 analisadores com parâmetros e exemplos
- [CONTRIBUTING.md](../../../CONTRIBUTING.md) -- como adicionar padrões, varreduras e módulos de analisadores
