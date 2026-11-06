# HDL simulator runner (hdl_sim)

Run GHDL and Icarus Verilog from copied tool bundles, with explicit build directories, captured logs, and failure propagation.

---

## Why this exists

1. **Research collections are noexec mounts.** The CERN collection ships working GHDL 5.0.1 and Icarus 12.0 bundles, but their binaries cannot execute in place. Every analysis script re-implemented the same workaround — copy the bundle to an executable filesystem, chmod the binaries, invoke with the right library paths. Three copies of that logic existed before this module.

2. **Simulator invocations are easy to get subtly wrong.** GHDL wants analyze → elaborate → run in a per-design build directory; Icarus wants `-B`/`-M` library paths matching the copied bundle; a free-running testbench clock needs `--stop-time` or `std.env.stop` or the run never terminates. Centralizing the invocations makes those decisions once.

3. **Failures must carry output.** A failed analyze with the compiler's message captured is a debugging step; a bare nonzero exit is a mystery. `SimulationError.output` always contains the full tool output, and optional log files persist every run.

---

## How it works

```python
from ablation.integrations.hdl_sim import GHDLRunner, relocate_bundle

tools = relocate_bundle('/media/research/CERN/analysis/tools/ghdl-5.0.1/root',
                        '/tmp/fpga-work/ghdl')
ghdl = GHDLRunner(tools, '/tmp/fpga-work/build')
ghdl.analyze(['optin_command_decoder.vhd', 'optin_decoder_tb.vhd'])
ghdl.elaborate('optin_decoder_tb')
result = ghdl.run('optin_decoder_tb', assert_level='error', log='sim.log')
assert 'OPTIN_DECODER_TB PASS' in result.output
```

- `relocate_bundle(src, dst)` copies a tool tree once and sets execute bits on `usr/bin/*` and `bin/*`. Reusing an existing destination is a no-op. Nothing is downloaded and no package manager is touched.
- `GHDLRunner` finds `ghdl-mcode` (or a plain `ghdl` driver) in the bundle and runs `-a`/`-e`/`-r` with a configurable `--std` (default `08`) in the given build directory.
- `IverilogRunner` compiles with `iverilog -B <bundle libs>` and runs with `vvp -M <bundle libs>` so the copied bundle's library trees are used.
- All invocations return `SimResult(argv, returncode, output)`; nonzero exits raise `SimulationError` with the captured output. `log=` writes the same output to a file.

Validated against the real CERN GHDL bundle: the ALICE OPTIN decoder testbench analyzes, elaborates, and passes through this runner.

## Limits

- Only the mcode GHDL backend is located by default; GCC/LLVM backends with different binary names need the plain-`ghdl` fallback.
- No waveform capture, no VPI bridge (that remains `mixed-hdl-vpi-bridge` territory), no testbench generation.
- The caller is responsible for terminating simulations (`--stop-time` or `std.env.stop` in the testbench).

## Reproduce

`tests/test_hdl_sim.py` (7 tests) uses stub shell-script binaries, so no simulator is needed: relocation and chmod, argv construction for both tools, log writing, and failure propagation are all covered.
