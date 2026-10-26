# JavaREAnalyzer

  - [What is the Java Virtual Machine and .class format?](#what-is-the-java-virtual-machine-and-class-format)
    - [The .class file structure](#the-class-file-structure)
    - [The constant pool](#the-constant-pool)
    - [Bytecode and the operand stack](#bytecode-and-the-operand-stack)
    - [JAR archives and class loading](#jar-archives-and-class-loading)
    - [Security vulnerability classes in Java](#security-vulnerability-classes-in-java)
    - [Deserialization gadget chains](#deserialization-gadget-chains)
    - [Spring Framework security model](#spring-framework-security-model)
    - [RE implications](#re-implications)
  - [Why this exists](#why-this-exists)
  - [How it works](#how-it-works)
  - [Usage](#usage)
  - [Example output](#example-output)
  - [False positives](#false-positives)
  - [Pipeline position](#pipeline-position)
  - [Reading findings](#reading-findings)
  - [See also](#see-also)

**Files:** `modules/java_re.py` · `modules/java_decompiler.py`

Scans Java `.class` files and JAR archives for security vulnerabilities using constant pool analysis, deserialization gadget chain detection, and Spring endpoint exposure analysis. Works on any Java version from 1.1 (major_version 45) through Java 21 (major_version 65) without requiring a running JVM or decompilation.

---

## What is the Java Virtual Machine and .class format? <sup>[↑](#javaReanalyzer)</sup>

Java is a compiled-then-interpreted language. A Java source file (`.java`) is compiled by `javac` into platform-independent bytecode stored in a `.class` file. The Java Virtual Machine (JVM) loads and executes these `.class` files at runtime, translating bytecode to native machine instructions via interpretation or just-in-time compilation. This architecture allows Java programs to "write once, run anywhere": the same `.class` file runs identically on Windows, Linux, macOS, and embedded JVMs.

The JVM specification was first published by Sun Microsystems in 1996. Oracle acquired Sun in 2010 and now maintains the specification. The `.class` file format and the JVM bytecode instruction set have been remarkably stable: bytecode compiled by Java 1.1 in 1997 will load and run in a Java 21 JVM in 2024. This stability is a critical security property for defenders: a `.class` file contains significantly more structural information than a stripped native binary, making security analysis far more tractable.

Java is deployed in enterprise software stacks (Spring Boot microservices, Tomcat web applications, Jakarta EE application servers), Android applications (Dalvik/ART bytecode: see `dex.md`), financial trading systems, embedded industrial controllers, and Cisco's JMX management plane. Firmware that includes management web UIs frequently ships Java servlets or Spring Boot applications.

### The .class file structure <sup>[↑](#javaReanalyzer)</sup>

A `.class` file begins with a 4-byte magic number `0xCAFEBABE`, followed by the class file version (minor.major, where major version 52 = Java 8, 61 = Java 17, 65 = Java 21), then the constant pool, access flags, class references, field table, method table, and attribute table.

```
ClassFile {
    u4 magic;                    // 0xCAFEBABE
    u2 minor_version;
    u2 major_version;            // 52 = Java 8, 55 = Java 11, 61 = Java 17
    u2 constant_pool_count;
    cp_info constant_pool[constant_pool_count - 1];
    u2 access_flags;
    u2 this_class;               // index into constant pool
    u2 super_class;              // index into constant pool
    u2 interfaces_count;
    u2 interfaces[interfaces_count];
    u2 fields_count;
    field_info fields[fields_count];
    u2 methods_count;
    method_info methods[methods_count];
    u2 attributes_count;
    attribute_info attributes[attributes_count];
}
```

The constant pool is indexed starting at 1 (not 0). Entry 0 is reserved and unused. The count field specifies the number of valid entries plus one. Long and Double constants consume two consecutive slots: an entry for the long/double followed by an unusable placeholder entry.

### The constant pool <sup>[↑](#javaReanalyzer)</sup>

The constant pool is a table of typed entries referenced by index throughout the rest of the `.class` file. Constant pool tag values:

| Tag | Name | Content |
|---|---|---|
| 1 | `CONSTANT_Utf8` | Length-prefixed modified UTF-8 string |
| 3 | `CONSTANT_Integer` | 32-bit int literal |
| 4 | `CONSTANT_Float` | 32-bit float literal |
| 5 | `CONSTANT_Long` | 64-bit long literal (consumes 2 slots) |
| 6 | `CONSTANT_Double` | 64-bit double literal (consumes 2 slots) |
| 7 | `CONSTANT_Class` | References a Utf8 entry with a class name |
| 8 | `CONSTANT_String` | References a Utf8 entry with a string value |
| 9 | `CONSTANT_Fieldref` | Class index + NameAndType index |
| 10 | `CONSTANT_Methodref` | Class index + NameAndType index |
| 11 | `CONSTANT_InterfaceMethodref` | Interface method reference |
| 12 | `CONSTANT_NameAndType` | Name index + descriptor index |
| 15 | `CONSTANT_MethodHandle` | Reference kind + reference index (Java 7+) |
| 18 | `CONSTANT_InvokeDynamic` | Bootstrap method + name/type (Java 7+) |

The security implication is significant: every class name, method name, field name, and string literal used by the class appears as a `CONSTANT_Utf8` entry. A linear scan for `CONSTANT_Utf8` entries that contain `"Runtime"`, `"exec"`, `"ObjectInputStream"`, or `"InvokerTransformer"` reliably identifies security-sensitive classes without any bytecode decoding. `JavaREAnalyzer.scan_constant_pool_strings()` performs exactly this scan.

### Bytecode and the operand stack <sup>[↑](#javaReanalyzer)</sup>

JVM bytecode is a stack-based instruction set. Each method body is stored in a `Code` attribute within the `method_info` entry. The bytecode operates on an operand stack: values are pushed onto and popped from the stack rather than stored in named registers.

Key bytecode instructions for security analysis:

| Mnemonic | Opcode | Operation |
|---|---|---|
| `invokevirtual` | 0xB6 | Call a virtual method. Index into constant pool gives the method ref. |
| `invokespecial` | 0xB7 | Call a constructor, private, or super method. |
| `invokestatic` | 0xB8 | Call a static method. |
| `invokeinterface` | 0xB9 | Call an interface method. |
| `invokedynamic` | 0xBA | Call a dynamically resolved method (lambda, String.format target). |
| `ldc` | 0x12 | Load constant from pool onto stack. Used to push string literals. |
| `new` | 0xBB | Create a new object. Followed by `invokespecial <init>`. |
| `checkcast` | 0xC0 | Cast an object; fails at runtime if wrong type. |
| `instanceof` | 0xC1 | Type check without cast. |

Dangerous invocations: `invokevirtual java/lang/Runtime.exec` means the class calls `Runtime.exec()`. `invokestatic java/lang/System.setProperty` sets a system property. `invokevirtual java/io/ObjectInputStream.readObject` triggers deserialization.

### JAR archives and class loading <sup>[↑](#javaReanalyzer)</sup>

A JAR (Java Archive) file is a ZIP archive with a specific `META-INF/MANIFEST.MF` file that specifies the main class, classpath, and other metadata. A web application archive (WAR) is a JAR with a specific directory layout for servlet containers. An enterprise archive (EAR) is a JAR containing WARs and JARs.

Spring Boot "fat JARs" (Spring Boot 2.x and 3.x) embed all dependency JARs inside the application JAR in `BOOT-INF/lib/`. A single Spring Boot fat JAR may contain hundreds of dependency JARs totaling hundreds of megabytes. `analyze_jar()` opens the outer JAR, iterates entries, and recursively processes any `.jar` entries it finds inside `BOOT-INF/lib/` or `WEB-INF/lib/`.

Dynamic class loading via `ClassLoader.loadClass()` or `URLClassLoader` is a security risk: if the URL or class name is attacker-controlled, the application loads and executes arbitrary classes. `InvokerTransformer` in `co_consts` combined with `URLClassLoader` in the constant pool is a strong indicator of a gadget-chain-exploitable deserialization sink.

### Security vulnerability classes in Java <sup>[↑](#javaReanalyzer)</sup>

**XXE (XML External Entity injection):** Java's XML parsing APIs (`SAXParser`, `DocumentBuilder`, `XMLStreamReader`) are enabled for external entity processing by default in Java versions before 7u6. An XXE vulnerability allows attackers to read arbitrary files, perform SSRF requests, or execute denial-of-service attacks via billion-laugh expansion. Detection: `DocumentBuilderFactory`, `SAXParserFactory`, or `XMLInputFactory` in the constant pool without a subsequent `setFeature("http://xml.org/sax/features/external-general-entities", false)` call.

**JNDI injection (Log4Shell class):** JNDI (Java Naming and Directory Interface) lookups can load classes from remote LDAP/RMI servers when the lookup string is user-controlled. The Log4Shell vulnerability (CVE-2021-44228) is the canonical example: `log4j`'s message lookup called `jndiManager.lookup(userString)`. Detection: `javax/naming/InitialContext` and `lookup` in the constant pool, combined with a tainted string argument.

**Spring endpoint exposure:** Spring MVC controllers annotated with `@RequestMapping`, `@GetMapping`, or `@PostMapping` are HTTP endpoints. Without `@PreAuthorize` or Spring Security configuration, they are unauthenticated. `/actuator/env` and `/actuator/heapdump` are particularly dangerous: they expose environment variables (including secrets) and heap dumps (which contain live objects including passwords and session tokens in memory).

### Deserialization gadget chains <sup>[↑](#javaReanalyzer)</sup>

Java object deserialization (`ObjectInputStream.readObject()`) is a well-documented remote code execution vector. When a server deserializes attacker-controlled bytes, the JVM instantiates objects from the serialized stream. If any class on the server's classpath has a chain of `readObject()`/`readResolve()`/`finalize()` methods that ultimately call `Runtime.exec()` or `Method.invoke()`, the attacker can trigger arbitrary code execution by crafting a serialized payload.

The most widely deployed gadget chains:

**Commons Collections (CC1–CC7):** Uses `InvokerTransformer` + `ChainedTransformer` + `LazyMap` to chain method invocations. `InvokerTransformer.transform()` calls `Method.invoke()` on any method in any class. Discovered by Chris Frohoff and Gabriel Lawrence (AppSec California 2015). Detection: `org/apache/commons/collections/functors/InvokerTransformer` in the constant pool.

**Spring4Shell (CVE-2022-22965):** Uses Spring's data binding to populate `ClassLoader.defineClass()` via a sequence of `AccessLogValve` property setters. Requires Spring MVC + Tomcat + Java 9+ module system. Detection: `AccessLogValve` + `ClassLoader` in the constant pool within the same class that handles request mapping.

**Serialized object magic bytes:** Java serialization streams always begin with `0xACED 0005`. If a String constant `"\xac\xed\x00\x05"` appears in the constant pool (Base64-encoded payload), the class is likely involved in serialization handling.

`JavaREAnalyzer.detect_java_deserialization_exploitation()` checks for `InvokerTransformer`, `ChainedTransformer`, `CommonsCollections`, `SerializedLambda`, and magic byte patterns.

### Spring Framework security model <sup>[↑](#javaReanalyzer)</sup>

Spring Security protects endpoints through a filter chain. Controllers decorated with `@PreAuthorize("hasRole('ADMIN')")` reject unauthenticated requests before the controller method runs. `@Secured("ROLE_USER")` does the same. Controllers with neither annotation are accessible to any request if the global security configuration does not have a catch-all deny rule.

Spring Boot Actuator exposes operational endpoints under `/actuator/`: `health`, `info`, `env`, `heapdump`, `beans`, `mappings`, `loggers`, `shutdown`. Actuator endpoints are enabled by default in older Spring Boot versions. `env` exposes all environment variables (including `SPRING_DATASOURCE_PASSWORD`, JWT secrets set via env vars). `heapdump` downloads a full JVM heap dump: a live heap dump from a running authentication server contains password hashes, session tokens, and private key material currently in memory.

The scanner detects the following Spring security gaps:
- `@RequestMapping` class without `@PreAuthorize` → unauthenticated endpoint
- `management.endpoints.web.exposure.include=*` in `application.properties` or `application.yml` → all actuators exposed
- `@Value("hardcoded-value")` → hardcoded credential in Spring configuration
- `HttpSecurity.csrf().disable()` → CSRF protection disabled

### RE implications <sup>[↑](#javaReanalyzer)</sup>

**Constant pool as a free call graph.** Because every invoked method appears as a `CONSTANT_Methodref` in the constant pool, reading the pool gives a complete first-order call graph without bytecode disassembly. `JavaREAnalyzer` uses this to determine which classes call `Runtime.exec`, `ProcessBuilder.start`, `ObjectInputStream.readObject`, and other sinks in O(N) time where N is the pool size.

**Version fingerprinting.** The `major_version` field in the `.class` header uniquely identifies the Java compiler version: 52 = Java 8, 55 = Java 11, 61 = Java 17. This reveals which Java version the vendor used for compilation, which may differ from the JVM version in the firmware. A class compiled with Java 8 (`major_version=52`) running on Java 11+ may behave differently because Java 9 introduced the module system that restricts reflective access.

**Spring Boot fat JAR unpacking.** `BOOT-INF/BOOT-INF/classes/` contains the application classes; `BOOT-INF/lib/` contains dependency JARs. The application's own code is almost always in `classes/`. Security-relevant gadget chain classes come from dependencies in `lib/`. The version string of each dependency JAR (visible in `META-INF/MANIFEST.MF` or in the JAR filename) identifies which CVEs apply to the deployment.

---

## Why this exists <sup>[↑](#javaReanalyzer)</sup>

1. **Java `.class` files store every method name, class reference, and string literal in an unobfuscated constant pool.** `parse_class_file()` reads the pool directly so dangerous patterns like `Runtime.exec`, `ObjectInputStream`, and `InvokerTransformer` are visible without decompiling any bytecode. This works on any Java version because the pool format has been stable since JDK 1.0.

2. **JAR files are ZIP archives containing dozens or hundreds of `.class` files.** `analyze_jar()` and `scan_jar_for_vulnerabilities()` open the ZIP, iterate every entry, and apply the constant pool scanner to each class in one pass. Scanning a JAR individually per class would require the caller to manage ZIP iteration.

3. **Spring Framework security gaps require cross-class analysis.** A controller class with `@RequestMapping` is a live HTTP endpoint. If it lacks `@PreAuthorize` or `@Secured`, the endpoint is unauthenticated. `analyze_spring_application_context()` detects this pattern across all classes in a JAR so unprotected endpoints are reported before manual review begins.

---

## How it works <sup>[↑](#javaReanalyzer)</sup>

```mermaid
flowchart TD
    A(["parse_class_file(data) or analyze_jar(jar_path)"]):::input --> B["ConstantPool.parse()\n  Read cp_count entries\n  UTF8 strings, class refs, method refs\n  Long/Double consume 2 slots"]:::primary
    B:::primary --> C["scan_constant_pool_strings(data)\n  Linear scan for tag=1 UTF8 entries\n  No bytecode decode needed\n  Finds: exec, ClassLoader, ObjectInputStream\n  JNDI, XXE, SSRF, hardcoded literals"]:::secondary
    C:::secondary --> D["detect_java_deserialization_exploitation()\n  InvokerTransformer / ChainedTransformer\n  Commons Collections gadget chain\n  SerializedLambda (Java 8+ gadget)\n  0xACED0005 magic in pool"]:::tertiary
    D:::tertiary --> E["analyze_spring_application_context()\n  @RequestMapping without @PreAuthorize\n  Spring Actuator endpoint exposure\n  @Value with hardcoded literal"]:::tertiary
    E:::tertiary --> F(["synthesize_findings(all_results) → List[dict]\n  severity: CRITICAL / HIGH / MEDIUM\n  exploit: reproduction path\n  detail: constant pool evidence"]):::output
    classDef input     fill:#0d47a1,stroke:#1565c0,color:#fff
    classDef primary   fill:#e65100,stroke:#bf360c,color:#fff
    classDef secondary fill:#004d40,stroke:#00695c,color:#fff
    classDef tertiary  fill:#4a148c,stroke:#6a1b9a,color:#fff
    classDef neutral   fill:#37474f,stroke:#546e7a,color:#fff
    classDef output    fill:#1b5e20,stroke:#2e7d32,color:#fff
    linkStyle 0 stroke:#bf360c,stroke-width:2px
    linkStyle 1 stroke:#00695c,stroke-width:2px
    linkStyle 2 stroke:#6a1b9a,stroke-width:2px
    linkStyle 3 stroke:#6a1b9a,stroke-width:2px
    linkStyle 4 stroke:#2e7d32,stroke-width:3px
```

---

## Usage <sup>[↑](#javaReanalyzer)</sup>

```python
from modules.java_re import parse_class_file, analyze_jar, scan_java_artifacts, synthesize_findings

# Single .class file
with open('Target.class', 'rb') as f:
    result = parse_class_file(f.read())
print(result['findings'])

# JAR file
result = analyze_jar('/path/to/app.jar')
for finding in synthesize_findings([result]):
    print(f"[{finding['severity']}] {finding['title']}")
    print(f"  {finding['detail']}")

# Filesystem scan
results = scan_java_artifacts(roots=['/opt/tomcat/webapps'])
for finding in synthesize_findings(results):
    print(finding)
```

```python
from modules.java_decompiler import scan_jar_for_vulnerabilities, report_java_findings

findings = scan_jar_for_vulnerabilities('/path/to/app.jar')
print(report_java_findings(findings))
```

---

## Example output <sup>[↑](#javaReanalyzer)</sup>

```
[CRITICAL] Deserialization gadget chain
  detail: InvokerTransformer in constant pool — Commons Collections gadget chain
  class: com.example.PayloadHandler
  exploit: Pass gadget payload to any ObjectInputStream.readObject() endpoint

[HIGH] Unprotected Spring endpoint
  detail: @RequestMapping present, no @PreAuthorize or @Secured annotation found
  class: com.example.AdminController
  exploit: Enumerate endpoints via /actuator/mappings or path brute-force

[HIGH] URLClassLoader reference
  detail: java/net/URLClassLoader in constant pool — remote class loading possible
  class: com.example.PluginLoader

[MEDIUM] Hardcoded Spring @Value literal
  detail: Spring @Value with hardcoded literal (not a placeholder): "secret-key-abc123"
  exploit: Extract literal from constant pool at build time
```

---

## False positives <sup>[↑](#javaReanalyzer)</sup>

**`InvokerTransformer` in test or utility JARs is not always exploitable.** The constant pool scanner flags any class that references the gadget symbol. Confirm that the class is reachable from a deserialization entry point before reporting CRITICAL. The commons-collections library itself has `InvokerTransformer` in its own JAR: a finding in `commons-collections-3.1.jar` is the library, not the application using the gadget chain.

**Spring `@RequestMapping` on internal classes is not always an HTTP surface.** Some Spring classes use the annotation for internal routing. Confirm the class is registered as a `@Controller` or `@RestController` before reporting the endpoint as unauthenticated. A class with `@Component` but not `@Controller`/`@RestController` and not returned by a `@Bean` method is not an HTTP endpoint.

**URLClassLoader in JVM internals.** The JVM itself uses `URLClassLoader` internally for extension loading. Flagging `java/net/URLClassLoader` in constant pool entries that come from JDK bootstrap classes (identifiable by `rt.jar` origin) is a false positive. Focus on application classes (not `java.*`, `javax.*`, `sun.*` prefixes) that reference `URLClassLoader`.

**Hardcoded `@Value` with configuration placeholders.** Spring's `@Value("${my.property}")` uses `${...}` placeholder syntax that is resolved at runtime from application properties. The scanner may flag the string `${my.property}` as a non-placeholder literal if the string does not start with `${`. Verify that flagged `@Value` strings use `${...}` syntax before reporting hardcoded credential.

**`System.exec()` in logging or monitoring code.** Management plane code that calls `Runtime.exec("ps aux")` or `Runtime.exec("df -h")` to collect system metrics is common in management software and is not a command injection vulnerability unless the command argument is constructed from user-controlled input. Constant pool detection identifies the call site; taint analysis determines whether the argument is controlled.

**Shadowed library versions.** A fat JAR may include both `commons-collections-3.2.2.jar` (safe) and an older transitive dependency `commons-collections-3.1.jar` from a dependency that bundles its own copy. The application's own classpath resolution determines which version is loaded. The JVM uses the first occurrence of a class in the classpath. Both versions must be reported, but the actual risk depends on load order.

---

## Pipeline position <sup>[↑](#javaReanalyzer)</sup>

**Before this module:** no prerequisites for `.class` files. For JAR files, confirm the archive is not encrypted or nested inside another container format. For firmware images that include a Java management plane, extract the filesystem first:

```bash
# For squashfs firmware
unsquashfs -d /tmp/fw_extract firmware.bin
find /tmp/fw_extract -name '*.jar' -o -name '*.war' -o -name '*.ear'

# For Cisco ASDM REST API
unzip disk0_rest-api.tar -d /tmp/asdm_extract
find /tmp/asdm_extract -name '*.jar'
```

**Scan sequence:**
1. `scan_java_artifacts(roots=[...])` → full dependency inventory + constant pool hits
2. Cross-reference `DependencyInventory` against CVE database → known-CVE deps
3. For each `CRITICAL` constant pool finding → `detect_java_deserialization_exploitation()` → gadget chain confirmation
4. For each Spring endpoint finding → verify `@Controller`/`@RestController` registration → HTTP surface map
5. For all HIGH confidence command execution findings → check if argument is user-controlled → taint path
6. Register confirmed findings in `FindingRegistry` with byte-verified evidence

**After this module:** CRITICAL deserialization findings with confirmed `ObjectInputStream` entry points proceed to CVE-2015-4852 reproduction. Spring unauthenticated endpoint findings proceed to `PreAuthRouteAuditor` for HTTP surface confirmation. Unknown-CVE dependency versions with command execution findings proceed to manual taint analysis.

**Estimated scan times (empirical, on commodity hardware):**
- Single `.class` file: < 1 ms
- Spring Boot fat JAR (50–200 MB): 2–8 seconds
- Full firmware squashfs with 500+ JARs: 30–120 seconds

---

## Complete example: Spring Boot fat JAR audit <sup>[↑](#javaReanalyzer)</sup>

```python
from modules.java_re import analyze_jar, scan_java_artifacts, synthesize_findings

# 1. Full audit: constant pool + dependency inventory
result = analyze_jar('/firmware/extract/opt/management/app.jar')

# 2. Dependency inventory (CVE cross-reference)
print("=== Dependency Inventory ===")
for dep in result.dependency_inventory:
    cve_flag = " *** CVE HIT" if dep.known_cves else ""
    print(f"  {dep.artifact_id}:{dep.version}{cve_flag}")
    for cve in dep.known_cves:
        print(f"    {cve.cve_id} [{cve.severity}]: {cve.description}")

# 3. Constant pool findings (security patterns)
print("\n=== Security Findings ===")
for finding in synthesize_findings([result]):
    print(f"  [{finding['severity']}] {finding['title']}")
    print(f"    class: {finding['class']}")
    print(f"    detail: {finding['detail']}")
    if finding.get('exploit'):
        print(f"    exploit: {finding['exploit']}")

# 4. Deserialization gadget chain confirmation
if result.has_deserialization_sink:
    from modules.java_re import detect_java_deserialization_exploitation
    chains = detect_java_deserialization_exploitation(result)
    if chains:
        print(f"\n*** CONFIRMED GADGET CHAIN: {chains[0]['chain_name']}")
        print(f"    Entry point: {chains[0]['entry_class']}.readObject()")
```

---

## Reading findings <sup>[↑](#javaReanalyzer)</sup>

`synthesize_findings()` returns `List[dict]`:

| Key | Content |
|:---|:---|
| `severity` | `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` |
| `title` | Short description of the finding |
| `detail` | Constant pool evidence string |
| `class` | Qualified class name where found |
| `exploit` | Reproduction path or attack vector |
| `cwe` | CWE identifier: `CWE-502` deserialization, `CWE-78` OS command injection, `CWE-798` hardcoded credential, `CWE-611` XXE |
| `evidence_type` | `'constant_pool'` or `'annotation'` or `'manifest_version'` |
| `jar_path` | Path to the JAR file containing the class |

**Severity mapping:**
- `CRITICAL`: Confirmed deserialization gadget chain with reachable entry point; or known unpatched CVE (Log4Shell, Spring4Shell) in deployed version
- `HIGH`: Unprotected Spring endpoint; or `Runtime.exec()` with no taint analysis yet; or deprecated crypto (`DES`, `MD5` for password hashing)
- `MEDIUM`: `URLClassLoader` reference; hardcoded credential candidate; XML parsing without XXE protection
- `LOW`: Internal path disclosure; version string revealing outdated JDK; informational dependency flag

Byte verification for Java findings does not use virtual addresses: it uses constant pool index + class file offset. Use `parse_class_file(bytes).constant_pool[index]` to verify that the constant pool entry at the flagged index contains the expected string before writing a `CONFIRMED` finding.

`DependencyInventory.to_csv()` serializes the full dependency list as CSV for import into vulnerability management tools. `DependencyInventory.to_cyclonedx()` produces a CycloneDX 1.4 SBOM (Software Bill of Materials) in JSON format. The SBOM output supports integration with dependency track and OWASP Dependency-Check for automated CVE correlation against the NVD feed.

`result.class_map` is a `Dict[str, ClassInfo]` mapping qualified class names to their `ClassInfo` objects. `ClassInfo.constant_pool_strings` returns all UTF-8 string entries in the class's constant pool as a flat list, without the security-pattern filtering that `synthesize_findings()` applies. Use `class_map` directly when building custom pattern matchers beyond the built-in set.

---

## Version compatibility matrix <sup>[↑](#javaReanalyzer)</sup>

`.class` file major version numbers map directly to Java compiler versions. The `major_version` field at bytes 6–7 of every `.class` file identifies the source Java version:

| Major version | Java version | Released | Notes |
|---|---|---|---|
| 45 | Java 1.1 | 1997 | Original Java: no generics, no annotations |
| 49 | Java 5 | 2004 | Generics, autoboxing, annotations, `invokedynamic` not yet |
| 50 | Java 6 | 2006 | Common in legacy enterprise apps |
| 51 | Java 7 | 2011 | `invokedynamic` (JSR 292), try-with-resources |
| 52 | Java 8 | 2014 | Lambda expressions, default methods, most prevalent today |
| 53 | Java 9 | 2017 | Module system (JPMS), `StackMapTable` required |
| 55 | Java 11 | 2018 | LTS. `var` type inference. Many legacy APIs removed |
| 61 | Java 17 | 2021 | LTS. Sealed classes, records |
| 65 | Java 21 | 2023 | LTS. Virtual threads (Project Loom), pattern matching |

Most enterprise firmware targets Java 8 (major_version 52) or Java 11 (55). Spring Boot 3.x requires Java 17+. Android targets are not `.class` files: they are compiled to Dalvik/ART bytecode (see `dex.md`).

---

## Finding known-CVE dependencies in fat JARs <sup>[↑](#javaReanalyzer)</sup>

The most common high-value finding in Java firmware is a dependency JAR with a known CVE, included in the application's `BOOT-INF/lib/` or `WEB-INF/lib/` directory. `analyze_jar()` builds a dependency inventory from JAR filenames and `META-INF/MANIFEST.MF` version attributes inside each nested JAR.

High-value targets by CVE class:

**Log4Shell (CVE-2021-44228):** Present in `log4j-core-2.x.y.jar` where x < 15 (unfixed range: 2.0-beta9 through 2.14.1). Detection: search for `log4j-core-2.*.jar` in the JAR inventory. Confirm by checking `log4j-core` version in `META-INF/MAVEN/org.apache.logging.log4j/log4j-core/pom.properties`. Any version `< 2.15.0` is vulnerable. Any version `< 2.17.1` is vulnerable to the follow-on CVE-2021-45046 (bypasses the `PatternLayout` mitigation).

**Spring4Shell (CVE-2022-22965):** Present in `spring-webmvc-5.x.y.jar` before 5.3.18 and 5.2.20. Requires: Spring MVC + Tomcat + Java 9+ module system (`--add-opens` not set) + deployed as WAR (not embedded Tomcat fat JAR). Detection: `spring-webmvc-5.*.jar` version < 5.3.18 in WAR mode.

**Commons Collections (deserialization, CVE-2015-4852):** Present in `commons-collections-3.1.jar` or `commons-collections-3.2.jar`. Version 3.2.2 adds serialization protections for the gadget chain classes but does not fully eliminate the risk. Any application that exposes `ObjectInputStream.readObject()` to external input with commons-collections on the classpath is vulnerable regardless of version.

**Jackson Databind (CVE-2017-7525 family, 30+ CVEs):** `jackson-databind-2.x.y.jar` has a long series of gadget chain vulnerabilities when `enableDefaultTyping()` is called or the `@class` field is present in deserialized JSON. Current safe minimum: 2.14.0. Detection: check `jackson-databind` version; flag any `enableDefaultTyping` in constant pool of application classes.

**Hibernate Validator (CVE-2019-10406):** Present in `hibernate-validator-5.x.y.jar` before 5.6.5 or 6.x before 6.0.18. OGNL expression injection via constraint message interpolation. Detection: `hibernate-validator` version and `javax.validation.ConstraintViolationException` in constant pool of classes that format error messages.

---

## Gradle / Maven build artifact metadata <sup>[↑](#javaReanalyzer)</sup>

A JAR built by Maven includes `META-INF/MAVEN/<groupId>/<artifactId>/pom.xml` and `pom.properties`. These files contain the exact version string and parent POM coordinates. Reading them is the most reliable way to identify the exact artifact version for CVE matching.

A JAR built by Gradle includes `META-INF/MANIFEST.MF` with `Implementation-Version`, `Implementation-Title`, and optionally `Build-Time` and `Build-Jdk`. The exact field names vary by plugin configuration. Gradle does not include a `pom.properties` equivalent by default.

`analyze_jar()` reads both `pom.properties` (Maven) and `MANIFEST.MF` (Gradle) for each nested JAR and returns a `DependencyInventory` object:

```python
result = analyze_jar('/firmware/app.jar')
for dep in result.dependency_inventory:
    print(f"{dep.artifact_id}:{dep.version}  (jar: {dep.jar_name})")
    if dep.known_cves:
        for cve in dep.known_cves:
            print(f"  *** {cve.cve_id} [{cve.severity}]: {cve.description}")
```

The `known_cves` list is populated by cross-referencing the artifact group/version against a bundled CVE database that is updated at each Ablation release. For artifacts not in the database, `known_cves` is empty: this does not mean the dependency is clean. Always cross-reference flagged versions against the NVD and the artifact's security advisories.

---

## RE implications (continued) <sup>[↑](#javaReanalyzer)</sup>

**Reflection and dynamic dispatch obscure the call graph.** Java reflection (`Class.forName()`, `Method.invoke()`) allows code to call any method by name at runtime. Spring's `@Autowired` dependency injection, JNDI lookups, and serialization-based plugin systems all use reflection. The constant pool scanner identifies these patterns (all reflection methods go through `java/lang/reflect/Method` in the constant pool), but cannot determine which method is ultimately called: that requires dynamic analysis or a taint-aware interprocedural analysis that resolves reflective call targets from string arguments.

**Inner classes generate separate `.class` files.** A Java class `Outer.java` with an inner class generates `Outer.class` and `Outer$Inner.class`. Anonymous classes generate `Outer$1.class`, `Outer$2.class`, etc. Lambda expressions in Java 8+ generate `Outer$$Lambda$1.class` (JVM synthetic classes, not present on disk for Lambda captures). All of these must be scanned to get complete coverage of the outer class's behavior. `scan_java_artifacts()` handles this by treating all `.class` files sharing a common outer class prefix as a group.

**Kotlin-compiled JVM bytecode.** Many modern Android and server-side Java applications are written in Kotlin. Kotlin compiles to standard JVM `.class` bytecode. The constant pool is identical in structure. One difference: Kotlin uses `kotlin/jvm/internal/Intrinsics.checkNotNullParameter()` for null checks, which adds noise to the constant pool but is not a security finding. Kotlin coroutines generate state machine classes (`*$Continuation.class`) that are harder to follow manually.

**ProGuard and R8 obfuscation.** Android applications and some embedded firmware run through ProGuard (older) or R8 (Google's replacement) to rename classes, methods, and fields to single letters (`a.a.a.b()`). Obfuscation removes descriptive names from the constant pool but cannot remove the structural symbols: a call to `Runtime.exec()` still has `java/lang/Runtime` and `exec` in the constant pool regardless of renaming, because those are JDK class names that cannot be renamed. Finding strings like `a.b.c` as class names in constant pool entries indicates ProGuard obfuscation: the dangerous constant pool entries remain findable.

---

## See also <sup>[↑](#javaReanalyzer)</sup>

- [DEX](dex.md): Android Dalvik bytecode analysis — analogous constant pool scanning for `.dex` files
- [ARK](harmonyos.md): HarmonyOS ArkTS bytecode analysis — JavaScript-derived bytecode format for HarmonyOS apps
- [Python .pyc](python-pyc-scanning.md): compiled Python bytecode scanning — same design philosophy, CPython-specific
- [BEAM](beam.md): Erlang BEAM chunk analysis — for Erlang/Elixir services in the management plane
- [Pre-Auth Route Auditor](preauth-exposure.md): confirm which Spring endpoints are reachable without authentication
- [Taint Analysis](taint-analysis.md): CFG-fixpoint taint tracking for when constant pool screening identifies a candidate sink that needs confirmation
- [SQL Injection Scanner](sql-injection-scanner.md): Java JDBC and Hibernate SQL pattern detection — pairs with JavaREAnalyzer when constant pool shows `java/sql/Statement` or `executeQuery` references
- [Length Underflow Scanner](length-underflow.md): for cases where the Java management plane calls a native JNI library that does C-level memory operations
- [Semantic Code Search](semantic-code-search.md): when manual review of decompiled Spring controllers is needed to find business logic injection beyond what constant pool screening can detect
- [Finding Registry](finding-validation.md): byte-verify every JavaREAnalyzer finding before registering — use constant pool index + class file byte offset as the evidence reference instead of a binary VA
