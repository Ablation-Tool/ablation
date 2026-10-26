# Android Binder Surface

Disassemble DEX bytecode to annotated smali and lift it to readable pseudo-Java IR: resolving all method, field, type, and string references from the DEX flat tables: to identify exported Binder service classes, map `onTransact()` transaction code dispatch, and analyze the IPC call surface for authorization gaps, unsanitized parameter passing, and missing `checkCallingPermission()` guards.

---

## Why this exists

1. **Binder IPC is the primary inter-process communication mechanism in Android, and it operates below the intent system.** Any process with a handle to a Binder object can call `transact()` directly on it with arbitrary transaction codes and `Parcel` payloads. Exported services registered in the service manager (`ServiceManager.addService()`) and exported `<service>` components are reachable from any app holding the right permissions, or from no app at all if the service exports without a permission guard. `APKParser` identifies exported service components from the manifest; `DEXDisasm` + `DEXLifter` analyze the `onTransact()` implementation to determine what each transaction code does.

2. **`onTransact()` dispatch logic is not readable from smali alone: method reference indexes require full DEX table resolution.** Raw smali output like `invoke-virtual {v0, v1}, method@2847` is meaningless without resolving index 2847 against the method_ids table. `DEXDisasm` resolves every reference at decode time, producing `invoke-virtual {v0, v1}, Landroid/os/Parcel;->readString()Ljava/lang/String;`: making it immediately clear what data is being read from the incoming `Parcel`. `DEXLifter` goes further, lifting the full dispatch block to pseudo-Java so the switch statement structure, permission check locations, and parameter handling are readable without a decompiler.

3. **`checkCallingPermission()` absence in a transaction branch is not detectable from string-pool scanning, it requires control-flow analysis.** A service that calls `enforceCallingPermission()` at the top of `onTransact()` is different from one that checks it only in specific transaction branches. A service that calls neither is an authorization bypass. These patterns require reading the disassembly at the method level: exactly what `DEXDisasm.disasm_method()` and `DEXLifter.lift_method()` provide.

---

## How it works

```mermaid
flowchart TD
    A(["APKParser.from_path(apk_path)"]):::input --> B["parse_manifest() → ManifestInfo\nFilter components where tag=='service'\nis_exported_or_implicit() == True\n→ exported service list"]:::primary
    B:::primary --> C["iter_dex() → DEXFile list\nFor each exported service class name:\nDEXDisasm(dex)._build_code_map()\nBuilds (class_name, method_name) → (code_off, access_flags)"]:::secondary
    C:::secondary --> D["DEXDisasm.disasm_method(class_name, 'onTransact'):\ndecode_code_item(dex, code_off):\nParse code_item header: registers_size, ins_size, insns_size (16B)\nDecode insns[] array: opcode from word0[0:8], hi_byte from word0[8:16]\nFor each instruction: _OPCODES[opcode] → (mnemonic, fmt)\n_FMT_SIZE[fmt] → code unit count\n_decode_fmt() → DEXInstruction(cu_offset, opcode, mnemonic, fmt, regs, ref_idx, literal, branch)"]:::tertiary
    D:::tertiary --> E(["For instructions with ref_idx: _resolve_ref(dex, opcode, idx)\nString ref → dex.string_at(idx) → escaped string literal\nType ref → dex.type_name(idx) → 'Landroid/os/Parcel;'\nField ref → 'Lclass;->field:Ltype;'\nMethod ref → 'Lclass;->name(params)Lreturn;'\nInstructions rendered to smali lines with cu_offset prefix"]):::output
    D:::tertiary --> F["DEXLifter(dex).lift_method(class_name, 'onTransact'):\nparams_start = registers_size - ins_size\nFor each instruction:\nconst-string → String vN = \"literal\";\ninvoke-virtual → pending=(ret_type, call_expr)\nmove-result → ret_type vN = call_expr;\niput/iget → obj.field = val; / type vN = obj.field;\nif-eq/ne → if (cond) goto :LXX;\ngoto backward → // ↑ back-edge (loop marker)"]:::tertiary
    F:::tertiary --> G(["Output: readable pseudo-Java showing:\nParcel.readInt() transaction code dispatch\ncheckCallingPermission() / enforceCallingPermission() presence\nParcel.readString() / readParcelable() data sources\nMethod calls downstream of IPC data"]):::output
    classDef input     fill:#0d47a1,stroke:#1565c0,color:#fff
    classDef primary   fill:#e65100,stroke:#bf360c,color:#fff
    classDef secondary fill:#004d40,stroke:#00695c,color:#fff
    classDef tertiary  fill:#4a148c,stroke:#6a1b9a,color:#fff
    classDef neutral   fill:#37474f,stroke:#546e7a,color:#fff
    classDef output    fill:#1b5e20,stroke:#2e7d32,color:#fff
    linkStyle 0 stroke:#bf360c,stroke-width:2px
    linkStyle 1 stroke:#00695c,stroke-width:2px
    linkStyle 2 stroke:#6a1b9a,stroke-width:2px
    linkStyle 3 stroke:#2e7d32,stroke-width:3px
    linkStyle 4 stroke:#6a1b9a,stroke-width:2px
    linkStyle 5 stroke:#2e7d32,stroke-width:3px
```

### DEX instruction format summary selected

| Format | Code units | Use |
|---|---|---|
| `35c` | 3 | `invoke-virtual/direct/static/interface {vC..vG}, method@idx` |
| `3rc` | 3 | `invoke-*/range {vFirst..vLast}, method@idx` |
| `21c` | 2 | `const-string vA, "string"` / `check-cast vA, Ltype;` |
| `22c` | 2 | `iget-object / iput vA, vB, field@idx` |
| `22t` | 2 | `if-eq/ne/lt vA, vB, :LXX` |
| `31i` | 3 | `const vA, #0xNNNN` |

---

## Usage

```python
from ablation.core.apk_parser import APKParser
from ablation.analyzers.dex_disasm import DEXDisasm
from ablation.analyzers.dex_lifter import DEXLifter

apk_path = '/tmp/VendorService.apk'

# Step 1: identify exported Binder services from manifest
with APKParser.from_path(apk_path) as apk:
    mf = apk.parse_manifest()
    exported_services = [
        c for c in mf.components
        if c.tag == 'service' and c.is_exported_or_implicit()
    ]
    print(f"Exported services ({len(exported_services)}):")
    for svc in exported_services:
        print(f"  {svc.name}  perm={svc.permission}")

    # Step 2: get DEX files
    dexes = list(apk.iter_dex())

# Step 3: disassemble onTransact for each service (smali level)
for dex in dexes:
    dd = DEXDisasm(dex)
    for svc in exported_services:
        class_name = 'L' + svc.name.replace('.', '/').lstrip('/') + ';'
        methods = dd.list_methods(class_name)
        if 'onTransact' in methods:
            print(f"\n=== {svc.name} smali onTransact ===")
            print(dd.disasm_method(class_name, 'onTransact'))

# Step 4: lift to pseudo-Java for readability
for dex in dexes:
    lifter = DEXLifter(dex)
    for svc in exported_services:
        class_name = 'L' + svc.name.replace('.', '/').lstrip('/') + ';'
        if 'onTransact' in lifter.list_methods(class_name):
            print(f"\n=== {svc.name} lifted onTransact ===")
            print(lifter.lift_method(class_name, 'onTransact'))

# Step 5: also lift Stub.onTransact (AIDL-generated Binder stubs)
with APKParser.from_path(apk_path) as apk:
    for dex in apk.iter_dex():
        lifter = DEXLifter(dex)
        for cls in dex.iter_classes():
            if 'Stub' in cls.class_name and cls.class_name.endswith('$Stub;'):
                if 'onTransact' in lifter.list_methods(cls.class_name):
                    print(f"\n=== {cls.class_name} Stub.onTransact ===")
                    print(lifter.lift_method(cls.class_name, 'onTransact'))
```

---

## Example output

```
Exported services (2):
  com.vendor.sdk.RemoteService     perm=None
  com.vendor.sdk.AdminService      perm=android.permission.MANAGE_DEVICE_ADMINS

=== com.vendor.sdk.RemoteService smali onTransact ===
.method Lcom/vendor/sdk/RemoteService;->onTransact
    .registers 5

    0000  invoke-super {p0, p1, p2, p3, p4}, Landroid/os/Binder;->onTransact(ILandroid/os/Parcel;Landroid/os/Parcel;I)Z
    0004  move-result v0
    0006  const/4 v1, #0x1
    0008  packed-switch p1, :L001c
    0010  goto :L0034
    ...
    001c  // packed-switch table: code 1→:L0020, 2→:L002a
    0020  invoke-virtual {p2}, Landroid/os/Parcel;->readString()Ljava/lang/String;
    0024  move-result-object v2
    0026  invoke-virtual {p0, v2}, Lcom/vendor/sdk/RemoteService;->processCommand(Ljava/lang/String;)V
.end method

=== com.vendor.sdk.RemoteService lifted onTransact ===
// com.vendor.sdk.RemoteService.onTransact
boolean onTransact(int p1, Parcel p2, Parcel p3, int p4) {
    // registers=5  params=5  outs=5

    boolean v0 = super.onTransact(p1, p2, p3, p4);
    int v1 = 1;
    // packed-switch p1 → :L001c
:L0020
    String v2 = p2.readString();
    this.processCommand(v2);   // <-- string from IPC passed directly to processCommand()
    // no checkCallingPermission() in this branch
```

---

## False positives

**`is_exported_or_implicit()` returns true for intent-filter services that are not Binder services.** A `JobService`, `AccessibilityService`, or `NotificationListenerService` exports itself via intent-filter required by the framework but does not implement `onTransact()` for custom IPC, it uses the framework Binder stub. `DEXDisasm.list_methods()` returns empty for `onTransact` on these classes. Skip services with empty `list_methodsclass_name` results: they are framework-managed, not custom Binder surfaces.

**Lifted pseudo-Java shows `// no pending invoke` for move-result instructions.** This comment appears when a `move-result` instruction does not immediately follow its corresponding `invoke-*`: for example, when a `goto` or another instruction appears between them valid bytecode but uncommon. The smali output from `DEXDisasm` is always correct for these cases: use it as the authoritative reference when the lifted pseudo-Java output shows this comment. The instruction stream is valid; the lifter's pending-invoke state was cleared by the intervening instruction.

**Permission check in superclass `onTransact()` is not visible in the subclass disassembly.** If `RemoteService` calls `super.onTransact()` and the permission check is in the `Binder` superclass, `DEXLifter` on the subclass will not show a `checkCallingPermission()` call. This is the normal pattern for services that delegate auth to the superclass. Before reporting a missing permission check, confirm whether the `invoke-super` at the top of the method targets a class that enforces permissions.

---

## Pipeline position

**Before this module:** Use `APKParser.parse_manifest()` to generate the exported service list: `DEXDisasm` and `DEXLifter` require a class name to disassemble, and the manifest is the authoritative source for which services are exported and what permission guards exist at the component level.

**After this module:** For services with no `checkCallingPermission()` in `onTransact()` branches that read Parcel data: feed the sink method for example `processCommand(`) back through `DEXLifter.lift_method()` to trace the full data path from the IPC boundary to the sink. For services with `IPC_STRING_DIRECT_TO_SINK` patterns: a `readString()` result passed to a method like `exec()`, `Runtime.exec()`, or `ProcessBuilder`: escalate directly to a taint-trace with `TaintTracker`.

---

## Reading findings

| Observation | Meaning |
|:---|:---|
| `onTransact` absent from `list_methods()` | Class uses framework Binder stub: no custom IPC surface |
| `super.onTransact()` only, no `packed-switch` | Binder stub passes all transactions to superclass: analyze superclass |
| `p2.readString()` → `this.methodName()` with no permission check between | IPC string passes directly to method: taint trace required |
| `enforceCallingPermission()` before first `packed-switch` | Auth enforced globally: verify per-branch bypass is not possible |
| `DEXLifter` shows `// no pending invoke` | `move-result` without preceding `invoke-*`: check smali output directly |

---

## See also

- [Android / APK Analysis](android-apk-analysis.md): manifest exported component enumeration prerequisite for this analysis
- [Taint Analysis](taint-analysis.md): trace IPC-sourced string arguments from `readString()` through to execution sinks
- [JNI Bridge Reconstruction](jni-bridge-reconstruction.md): when `onTransact()` delegates to native code via JNI
