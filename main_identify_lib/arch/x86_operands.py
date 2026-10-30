"""Decode x86 address fields using processor register IDs (intel.hpp rules)."""
from ..model import DecodedOperand


def decode_memory_operand(*, absolute, phrase, has_sib, sib, rex, displacement,
                          width, bits, segment=0, native_address=True, vector_index=False):
    if segment in (33, 34) or not native_address or vector_index:
        return DecodedOperand("unknown", width=width)
    base, index, scale = None, None, 1
    if has_sib:
        if not absolute:
            base = (sib & 7) | (8 if bits == 64 and rex & 1 else 0)
        index_number = ((sib >> 3) & 7) | (8 if bits == 64 and rex & 2 else 0)
        if index_number != 4:
            index = index_number
        scale = 1 << (sib >> 6 & 3)
    elif not absolute:
        if not 0 <= phrase < (16 if bits == 64 else 8):
            return DecodedOperand("unknown", width=width)
        base = phrase
    if not absolute:
        displacement &= (1 << bits) - 1
        if displacement & (1 << (bits - 1)):
            displacement -= 1 << bits
    return DecodedOperand("mem", base=base, index=index, scale=scale,
                          value=displacement, width=width)

