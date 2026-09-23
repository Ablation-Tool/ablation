"""
Verification: version_delta patch localization on a synthetic RADIUS strlcpy patch.

Simulates a before/after where the strcpy call gains a length argument
(the class of fix for RADIUS Class attribute overflows). Confirms:
  - Jaccard similarity is high (same function, minor change)
  - PatchDelta.is_patched == True
  - The added instruction contains the length constant
"""

import sys
sys.path.insert(0, str(__import__('pathlib').Path(__file__).parent.parent))

from modules.version_delta import diff_functions, jaccard_similarity

# Synthetic RADIUS attr handler before the strlcpy length-arg fix
ASM_BEFORE = [
    'push rbp',
    'mov rbp, rsp',
    'push r14',
    'push rbx',
    'test rdi, rdi',
    'je 0xc56602',
    'mov r14, rdi',
    'mov rbx, rsi',
    'call 0x23f3dc0',           # attr_alloc()
    'test rax, rax',
    'je 0xc56602',
    'mov rdi, rax',
    'mov rsi, rbx',
    'call 0xbdd220',            # strcpy(dst, src)  ← pre-patch: no length limit
    'mov qword ptr [r14], rax',
    'pop rbx',
    'pop r14',
    'pop rbp',
    'ret',
]

# Same function after the strlcpy length-arg patch
ASM_AFTER = [
    'push rbp',
    'mov rbp, rsp',
    'push r14',
    'push rbx',
    'test rdi, rdi',
    'je 0xc56602',
    'mov r14, rdi',
    'mov rbx, rsi',
    'call 0x23f3dc0',           # attr_alloc()
    'test rax, rax',
    'je 0xc56602',
    'mov rdi, rax',
    'mov rsi, rbx',
    'mov rdx, 0xfd',            # ← patch: length = 253 (max RADIUS attr)
    'call 0xbdd230',            # strlcpy(dst, src, 253)
    'mov qword ptr [r14], rax',
    'pop rbx',
    'pop r14',
    'pop rbp',
    'ret',
]

def main():
    j = jaccard_similarity(ASM_BEFORE, ASM_AFTER)
    print(f'Jaccard before vs after : {j:.4f}')
    assert j >= 0.70, f'expected >=0.70 for minor patch, got {j}'

    delta = diff_functions(
        ASM_BEFORE, 'attr_list_add_impl',
        ASM_AFTER,  'attr_list_add_impl',
        version_a='9.14', version_b='9.16',
    )
    print(f'SequenceMatcher ratio   : {delta.ratio:.4f}')
    print(f'is_patched              : {delta.is_patched}')
    print(f'removed lines           : {delta.removed}')
    print(f'added lines             : {delta.added}')

    assert delta.is_patched, 'expected PatchDelta.is_patched == True'
    assert any('0xfd' in line or '<I>' in line for line in delta.added), \
        'expected length constant in added lines'

    print(f'\nunified diff:\n{delta.unified_diff("9.14", "9.16")}')
    print('\nPASS')

if __name__ == '__main__':
    main()
