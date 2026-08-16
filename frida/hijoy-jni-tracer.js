/**
 * hijoy-jni-tracer.js — HiJoy PTT JNI Function Tracer
 *
 * Hooks all 10 JNI functions in libhijoyptt.so to log:
 * - Function entry/exit
 * - Arguments (r0-r3)
 * - Return values
 * - PTT session structure fields
 *
 * Usage:
 *   frida -U -f com.hijoytech.iwalkie30 -l hijoy-jni-tracer.js --no-pause
 *
 * Author: NuClide Research
 * Date: 2026-08-16
 */

const LIB_NAME = "libhijoyptt.so";

// JNI function addresses (offsets from base)
const JNI_FUNCTIONS = {
    "CreateChannel":       0x000239a4,
    "DeleteChannel":       0x00023a78,
    "SetLocalReceiver":    0x00023b10,
    "SetSendDestination":  0x00023ba4,
    "StartListen":         0x00023ca0,
    "StartSend":           0x00023d90,
    "StopListen":          0x00023e08,
    "StopSend":            0x00023ef8,
    "SetSendCodec":        0x00023fe8,
    "SendSignaling":       0x0002511c,
};

// PTT session structure offsets (from static analysis)
const SESSION_OFFSETS = {
    "magic":        0x04,
    "state":        0x20,
    "flags":        0x28,
    "tx_rx_ctrl":   0x44,
    "listen_send":  0x54,
    "active":       0x58,
    "codec_type":   0x08,
    "codec_params": 0x0c,
    "local_recv":   0x24,
    "send_dest":    0x40,
    "remote_ip":    0xc8,
    "remote_port":  0xd0,
};

// Color codes
const GREEN = "\x1b[32m";
const RED = "\x1b[31m";
const BLUE = "\x1b[34m";
const YELLOW = "\x1b[33m";
const RESET = "\x1b[0m";

let sessionCounter = 0;
let activeSessions = new Map();

function hexdump(ptr, length) {
    try {
        return hexdump_raw(ptr, length);
    } catch (e) {
        return "[invalid pointer]";
    }
}

function hexdump_raw(ptr, length) {
    let result = "";
    const bytes = ptr.readByteArray(length);
    const arr = new Uint8Array(bytes);

    for (let i = 0; i < arr.length; i += 16) {
        result += ptr.add(i).toString().padStart(16, '0') + ": ";

        // Hex bytes
        for (let j = 0; j < 16 && i + j < arr.length; j++) {
            result += arr[i + j].toString(16).padStart(2, '0') + " ";
        }

        // ASCII
        result += " |";
        for (let j = 0; j < 16 && i + j < arr.length; j++) {
            const c = arr[i + j];
            result += (c >= 32 && c < 127) ? String.fromCharCode(c) : ".";
        }
        result += "|\n";
    }
    return result;
}

function dumpSession(sessionPtr, label) {
    if (!sessionPtr || sessionPtr.isNull()) {
        console.log(`    ${label}: NULL`);
        return;
    }

    console.log(`    ${label} @ ${sessionPtr}:`);

    try {
        for (const [name, offset] of Object.entries(SESSION_OFFSETS)) {
            const value = sessionPtr.add(offset).readU32();
            console.log(`      [+0x${offset.toString(16).padStart(3, '0')}] ${name.padEnd(15)}: 0x${value.toString(16).padStart(8, '0')} (${value})`);
        }
    } catch (e) {
        console.log(`      Error reading session: ${e.message}`);
    }
}

function hookJNIFunction(moduleName, funcName, offset) {
    const module = Process.getModuleByName(moduleName);
    const funcAddr = module.base.add(offset);

    console.log(`[*] Hooking ${funcName} @ ${funcAddr}`);

    Interceptor.attach(funcAddr, {
        onEnter: function(args) {
            const tid = Process.getCurrentThreadId();
            this.funcName = funcName;
            this.args = [args[0], args[1], args[2], args[3]];
            this.timestamp = Date.now();

            console.log(`\n${GREEN}[→] ${funcName}${RESET} (tid=${tid})`);
            console.log(`    r0 (arg0): ${args[0]}`);
            console.log(`    r1 (arg1): ${args[1]}`);
            console.log(`    r2 (arg2): ${args[2]}`);
            console.log(`    r3 (arg3): ${args[3]}`);

            // Dump PTT session structure if arg0 looks like a pointer
            if (args[0] && !args[0].isNull()) {
                try {
                    // Try to read first field to validate pointer
                    args[0].readU32();
                    dumpSession(args[0], "PTT Session");

                    // Track session
                    if (funcName === "CreateChannel") {
                        sessionCounter++;
                        activeSessions.set(args[0].toString(), sessionCounter);
                        console.log(`    ${YELLOW}[Session ${sessionCounter} CREATED]${RESET}`);
                    } else if (funcName === "DeleteChannel") {
                        const sessionId = activeSessions.get(args[0].toString());
                        if (sessionId) {
                            console.log(`    ${RED}[Session ${sessionId} DELETED]${RESET}`);
                            activeSessions.delete(args[0].toString());
                        }
                    }
                } catch (e) {
                    console.log(`    arg0 not a valid session pointer`);
                }
            }

            // Special handling for SendSignaling (protocol messages)
            if (funcName === "SendSignaling" && args[1] && !args[1].isNull()) {
                try {
                    console.log(`    ${BLUE}[Protocol Message]${RESET}`);
                    console.log(hexdump(args[1], 32));
                } catch (e) {
                    console.log(`    Error dumping message: ${e.message}`);
                }
            }
        },

        onLeave: function(retval) {
            const elapsed = Date.now() - this.timestamp;
            const tid = Process.getCurrentThreadId();

            console.log(`${RED}[←] ${this.funcName}${RESET} returned: ${retval} (${elapsed}ms, tid=${tid})`);
        }
    });
}

function main() {
    console.log("=".repeat(80));
    console.log("HiJoy PTT JNI Tracer");
    console.log("=".repeat(80));
    console.log("");

    // Wait for library to load
    const module = Process.findModuleByName(LIB_NAME);
    if (!module) {
        console.log(`[!] ${LIB_NAME} not loaded yet, waiting...`);

        const interval = setInterval(() => {
            const mod = Process.findModuleByName(LIB_NAME);
            if (mod) {
                clearInterval(interval);
                console.log(`[+] ${LIB_NAME} loaded at ${mod.base}`);
                hookAll();
            }
        }, 100);
    } else {
        console.log(`[+] ${LIB_NAME} loaded at ${module.base}`);
        hookAll();
    }
}

function hookAll() {
    console.log("[*] Installing hooks on all JNI functions...\n");

    for (const [funcName, offset] of Object.entries(JNI_FUNCTIONS)) {
        try {
            hookJNIFunction(LIB_NAME, funcName, offset);
        } catch (e) {
            console.log(`[!] Failed to hook ${funcName}: ${e.message}`);
        }
    }

    console.log("\n[+] All hooks installed. Monitoring PTT calls...\n");
    console.log("=".repeat(80));
}

// Entry point
setTimeout(main, 0);
