# SunOS SPARC a.out Analysis

`ablation.sunos` parses big-endian SunOS SPARC OMAGIC a.out images and recovers symbols, relocation records, direct calls, and conservative constant call-argument provenance using only the Python standard library. It is intended for bounded static analysis of legacy drivers and objects, not execution or general a.out linking.

## Why this exists

1. **SunOS a.out is not ELF.** Header fields, symbol records, text/data layout, and relocation entries require a separate parser.
2. **Raw call placeholders are not final destinations.** Internal relocation records carry explicit signed addends that must be applied to the PC-relative displacement.
3. **Relocations need exact record semantics.** The supported OMAGIC layout uses twelve-byte records with big-endian address, flags, and addend fields.

## Usage

```bash
ablation sunos info INPUT
ablation sunos info INPUT --json
ablation sunos calls INPUT --target 0xADDRESS --json
ablation sunos render INPUT --target 0xADDRESS
ablation sunos dispatch INPUT --target 0xADDRESS --wrapper 0xWRAPPER --register %o1 --json
```

Zoe users can run the same interface with `zoe launch ablation -- sunos ...`. Python callers use `read_aout(path)` or `parse_aout(data)`. `SunosAout.calls()` returns typed direct calls with raw and resolved targets, external symbol names, delay-slot words, and relocation records. `SunosAout.call_argument(call, register)` recovers a signed constant written by a `mov` in the call delay slot, an immediately preceding instruction with no incoming branches, or the delay slot of a sole recovered direct-branch predecessor when no fallthrough path exists. `SunosAout.dispatch_arguments(target, register, wrappers)` adds calls through single-dispatcher wrapper functions and preserves unresolved or ambiguous values explicitly.

## Argument provenance

The `dispatch` command emits one record per direct or wrapper call. Each record includes the call address, register, signed value or `null`, provenance kind, setup instruction, and wrapper/internal-call addresses where applicable. Supported provenance kinds are `call_delay_slot`, `preceding_instruction`, `branch_delay_slot`, and `wrapper`; unresolved direct and wrapper values use `unresolved` and `wrapper_unresolved`. Only SPARC `or`-based immediate `mov` encodings are treated as constants. Register moves, competing predecessors, and possible fallthrough are not guessed.

## Relocation model

Each twelve-byte record contains `r_address:u32`, `flags:u32`, and `r_addend:u32`. The decoder uses:

- `symbol_index=(flags>>8)&0xffffff`;
- `extern=(flags>>7)&1`;
- `pcrel=(flags>>2)&1`;
- `length_code=flags&3`.

For an internal text record with `pcrel=1` and `length_code=2`, the direct-call target is `instruction_VA + sign_extend(displacement30)*4 + signed_addend`. External records resolve to their undefined symbol name. Other relocation records are preserved but not applied.

## Validated evidence

The Lotus Sybase DataLens driver has SHA256 `88a7ce88f9d1ead09508d0b01e636616d14442c98f4c74171d468680e73a5cce`, 1,417 symbols, and 5,800 text/data relocation records. The parser resolves `0xb1b0 -> 0xf624`, `0xb270 -> 0x2998`, and `0xb31c -> 0xd0d8`, including external `_strlen` calls and direct dispatcher calls. These corrected targets supersede raw self-call interpretations. The dispatcher census with wrapper `0xa4c8` resolves all twelve calls to fixed `%o1` values 0 or 6, including branch-delay setups at `0x9ef0` and `0xaec8`.

## Limits

- Only SunOS SPARC OMAGIC is accepted. Other a.out magic values, architectures, and relocation layouts are rejected.
- Direct calls are decoded; indirect calls and complete linker behavior are not claimed.
- Argument recovery covers constant `mov` setups and single-dispatcher wrappers with a conventional `ret`; it is not general interprocedural data flow, path-sensitive merging, or runtime pointer recovery.
- Wrapper scanning stops at the first conventional `ret`; unusual control flow or multiple dispatcher calls are rejected as ambiguous.
- Recovered static evidence does not establish protocol state, runtime behavior, or a vulnerability.
- No original executable is run by the parser or CLI.
