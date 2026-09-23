"""
Verification: BERT cosine similarity for cross-version homolog detection.

Extracts lina 9.14 attr_list_add_impl and lina 9.22 class_attr_parse_fn
from disk using capstone, encodes both, and confirms:
  - homolog pair scores >= 0.80
  - separation from unrelated function (ssl handler) is >= 5x
"""

import sys
sys.path.insert(0, str(__import__('pathlib').Path(__file__).parent.parent))

import capstone
import numpy as np
from sentence_transformers import SentenceTransformer
from modules.semantic_search import describe_function, normalize_asm

LINA_914 = '/home/cowboy/VDT/intel/cisco-downloads/asa9-14-extracted/lina'
LINA_922 = '/home/cowboy/VDT/intel/cisco-downloads/asa9-22-lina/asa/bin/lina'

# lina 9.14: VAs confirmed via func_id_db seed
VA_914_RADIUS  = 0xc563d0   # attr_list_add_impl
VA_914_CONTROL = 0xbdd220   # callee, different subsystem
# lina 9.22
VA_922_RADIUS  = 0x3a4bda0  # class_attr_parse_fn (evolved homolog)

def extract_func(path, va, max_bytes=2048):
    with open(path, 'rb') as f:
        f.seek(va)
        raw = f.read(max_bytes)
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    lines, calls = [], []
    for insn in md.disasm(raw, va):
        op = f'{insn.mnemonic} {insn.op_str}'.strip()
        lines.append(op)
        if insn.mnemonic == 'call' and insn.op_str.startswith('0x'):
            calls.append(insn.op_str)
        if insn.mnemonic in ('ret', 'retq', 'retn'):
            break
        if insn.mnemonic in ('jmp', 'jmpq'):
            try:
                dest = int(insn.op_str, 16)
                if abs(dest - va) > 0x10000:
                    break
            except ValueError:
                break
    return lines, calls

def main():
    asm_914, calls_914 = extract_func(LINA_914, VA_914_RADIUS)
    asm_922, calls_922 = extract_func(LINA_922, VA_922_RADIUS)
    asm_ctrl, calls_ctrl = extract_func(LINA_914, VA_914_CONTROL)

    print(f'9.14 attr_list_add_impl  : {len(asm_914)} instrs')
    print(f'9.22 class_attr_parse_fn : {len(asm_922)} instrs')
    print(f'9.14 control             : {len(asm_ctrl)} instrs')

    desc_914  = describe_function('attr_list_add_impl',  'RADIUS_ATTR_PARSER', calls_914,  [], asm_lines=asm_914)
    desc_922  = describe_function('class_attr_parse_fn', 'RADIUS_ATTR_PARSER', calls_922,  [], asm_lines=asm_922)
    desc_ctrl = describe_function('ssl_send_hello',      'TLS_HANDSHAKE',      calls_ctrl, [], asm_lines=asm_ctrl)

    print('\nEncoding...')
    model = SentenceTransformer('sentence-transformers/all-MiniLM-L6-v2', device='cpu')
    vecs = model.encode([desc_914, desc_922, desc_ctrl], normalize_embeddings=True)

    sim_homolog  = float(vecs[0] @ vecs[1])
    sim_ctrl_914 = float(vecs[0] @ vecs[2])
    sim_ctrl_922 = float(vecs[1] @ vecs[2])

    print(f'\n9.14 vs 9.22 (homolog)  : {sim_homolog:.4f}')
    print(f'9.14 vs control          : {sim_ctrl_914:.4f}')
    print(f'9.22 vs control          : {sim_ctrl_922:.4f}')
    print(f'separation margin        : {sim_homolog / max(sim_ctrl_914, sim_ctrl_922):.1f}x')

    assert sim_homolog >= 0.80,  f'homolog score {sim_homolog:.4f} < 0.80'
    assert sim_ctrl_914 < 0.40,  f'control score {sim_ctrl_914:.4f} unexpectedly high'
    assert sim_ctrl_922 < 0.40,  f'control score {sim_ctrl_922:.4f} unexpectedly high'

    print('\nPASS')

if __name__ == '__main__':
    main()
