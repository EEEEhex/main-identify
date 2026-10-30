"""Go 1.18/1.20+ pclntab address ranges, without reading function names.

Layouts follow Go's runtime pcHeader/moduledata and debug/gosym. A zero
textStart or modified magic needs a corroborating moduledata record.
"""
from bisect import bisect_right
from dataclasses import dataclass
import struct


MAGICS = (b'\xf0\xff\xff\xff', b'\xf1\xff\xff\xff')


@dataclass(frozen=True)
class GoTable:
    header: int
    starts: tuple
    modified: bool = False

    def bounds(self, address):
        index = bisect_right(self.starts, address)-1
        if 0 <= index < len(self.starts)-1:
            return self.starts[index], self.starts[index+1]
        return None


def parse_table(header, bits, read, refs_to, is_code, allow_modified=False):
    """Return validated PC intervals, or None for malformed/unsupported data."""
    ptr = bits//8
    raw = read(header, 8+8*ptr)
    if (not raw or len(raw) != 8+8*ptr
            or raw[4:8] != bytes((0,0,1,ptr))):
        return None
    modified = raw[:4] not in MAGICS
    if modified and not allow_modified:
        return None
    word = 'Q' if ptr == 8 else 'I'
    words = struct.unpack('<'+word*8, raw[8:])
    nfunc, nfile, text = words[:3]
    offsets = words[3:]
    if (not 0 < nfunc <= 1_000_000 or not 0 < nfile <= 1_000_000
            or offsets[0] < len(raw) or offsets[-1] > 128*1024*1024
            or any(a >= b for a,b in zip(offsets,offsets[1:]))):
        return None
    table = header+offsets[-1]
    text_limit = None
    record_limit = None
    if modified or not text or not is_code(text):
        header_text = text
        text = 0
        for ref in list(refs_to(header))[:16]:
            data = read(ref, 24*ptr)
            if not data or len(data) != 24*ptr:
                continue
            module = struct.unpack('<'+word*24, data)
            if (module[0] == header
                    and all(module[index] == header+offset for index,offset in zip((1,4,7,10,13),offsets))
                    and module[16] == table and module[17] == nfunc+1
                    and module[18] == nfunc+1 and module[20] == module[22]
                    and module[22] < module[21] <= module[23] and is_code(module[22])):
                if modified:
                    # An altered magic is never enough. Correlate all five
                    # module slices, their extents, the ftab and text limits.
                    if (header_text not in (0,module[22])
                            or any(not 0 < module[i+1] <= module[i+2] <= 128*1024*1024
                                   for i in (1,4,7,10,13))
                            or any(module[i]+module[i+1] > module[i+3] for i in (1,4,7,10))):
                        continue
                    record_limit = module[14]
                text = module[22]
                text_limit = module[21]
                break
        if not text:
            return None
    size = (2*nfunc+1)*4
    data = read(table, size)
    if not data or len(data) != size:
        return None
    entries = struct.unpack('<'+'I'*(2*nfunc+1), data)
    pcs = entries[::2]
    if (pcs[0] != 0 or pcs[-1] > 1024*1024*1024
            or any(a >= b for a,b in zip(pcs,pcs[1:]))
            or (text_limit is not None and text+pcs[-1] != text_limit)
            or text+pcs[-1] >= 1 << bits or not read(text+pcs[-2],1)):
        return None
    if modified:
        # Some modified runtimes also encode _func.entryOff. The runtime's
        # sorted ftab still holds real entry offsets. Require the independent
        # module correlation above and bound every record in its pclntable.
        records = entries[1::2]
        if (record_limit < size or record_limit > 128*1024*1024
                or any(not size <= offset <= record_limit-40 for offset in records)
                or any(a+40 > b for a,b in zip(records,records[1:]))):
            return None
        last = read(table+records[-1],40)
        if not last or len(last) != 40:
            return None
    else:
        # Standard tables must corroborate _func.entryOff at separated records.
        # Names and file strings are deliberately unread on either path.
        for index in {0,nfunc//2,nfunc-1}:
            offset = entries[2*index+1]
            if not size <= offset < 128*1024*1024:
                return None
            entry = read(table+offset,4)
            if not entry or len(entry) != 4 or int.from_bytes(entry,'little') != pcs[index]:
                return None
    return GoTable(header, tuple(text+pc for pc in pcs), modified)
