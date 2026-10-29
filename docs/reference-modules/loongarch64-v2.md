<a id="loongarchdecoderv2"></a>
# LoongArch64 KASAN/KCOV Filtering

`LoongArchDecoderV2` extends the native LoongArch decoder with instrumentation tagging for KASAN- and KCOV-instrumented kernels. It identifies known sanitizer calls and recognized KASAN shadow-check preambles, then can yield a cleaned instruction stream for downstream analysis.

## Why filter instrumentation?

Sanitizer calls and shadow checks add control flow that is unrelated to the original kernel logic. When an analyst compares a KASAN report with a production build, those additions can hide the relevant path or inflate call relationships. Removing recognized instrumentation makes the remaining instructions easier to compare.

The approach relies on symbol addresses and a bounded set of compiler idioms, not on a claim that every sanitizer sequence is understood. Users gain a preprocessing aid for differential review, with tagging retained so removed instructions can be audited. It remains a small adapter between `System.map` evidence and later analysis rather than an automatic vulnerability validator. New compiler patterns can extend the tagger; uncertain sequences should remain visible instead of being deleted speculatively.

## What it does

1. Decodes 32-bit little-endian LoongArch frames using the V1 decoder.
2. Marks direct calls to supplied `__asan_*`, `__kasan_*`, or `__sanitizer_cov_*` addresses.
3. Walks backward from tagged calls to mark a bounded set of recognized KASAN shadow-address instructions.
4. Returns either all tagged frames or only non-instrumentation frames.

This filtering reduces irrelevant call edges in instrumented input. It does not turn a debug kernel into a production kernel, recover source code, or validate a KASAN report.

## Usage

```python
from ablation.analyzers.loongarch_decoder_v2 import LoongArchDecoderV2

decoder = LoongArchDecoderV2.from_system_map('/path/to/System.map')

frames = decoder.decode_frames_v2(section_bytes, base_addr=0xFFFF000000000000)
for frame in decoder.decode_frames_clean(section_bytes, base_addr=0xFFFF000000000000):
    print(frame)

stats = decoder.count_instrumentation(section_bytes, base_addr=0xFFFF000000000000)
print(stats)
```

Use addresses appropriate for the supplied section bytes. `from_system_map()` reads symbol addresses from a kernel map; it does not load the kernel image. `LoongArchDecoderV2(instrumentation_vas={...})` accepts an explicit address set instead.

`decode_frames_v2()` returns a list of `LoongArchFrameV2` objects. Each adds `is_instrumentation` and `idiom` metadata to the base frame. `decode_frames_clean()` returns an iterator over untagged frames. `count_instrumentation()` reports total, instrumentation, real, and percentage counts.

## Parameters and limitations

- `max_preamble=6` bounds the backward KASAN idiom scan. Larger values can tag more sequences but increase the chance of removing real instructions.
- An empty instrumentation address set produces V1-like behavior: sanitizer calls cannot be recognized by address alone.
- KCOV call classification and KASAN preamble classification are pattern-based. Different compiler versions or instrumentation layouts may not match.
- Removing instrumentation can change the apparent instruction sequence. Confirm a security-relevant branch or memory access against the unfiltered frames.
- The decoder does not automatically connect `LoongArch64TaintTracker` to cleaned frames; callers must use the cleaned stream in an appropriate downstream workflow.

## Related workflows

- [LoongArch64 Decompilation & Taint Analysis](loongarch.md)
- [KASAN Finding Validation](../workflows/kasan-oracle.md)
