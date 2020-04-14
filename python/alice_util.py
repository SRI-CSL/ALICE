import ahocorasick

def add_element_to_dict(dic, key, val):
    if not key in dic:
        dic[key] = []
    dic[key].append(val)
    return dic


# Use Aho-Corasick Algorithm (https://en.wikipedia.org/wiki/Aho%E2%80%93Corasick_algorithm)
def search(search_string, queries):
    idxs = {}

    if not queries:
        return idxs

    auto = ahocorasick.Automaton()

    for e in queries:
        auto.add_word(e, e)
    auto.make_automaton()

    for end_ind, e in auto.iter(search_string):
        start_ind = end_ind - len(e) + 1
        idxs = add_element_to_dict(idxs, e, start_ind)

    return idxs

# If an element from a whitelist or blacklist is in "string", return all locations (indexes) that element occurs
# Output Usage: output[query] = [idx1, idx2, ..., idxk]
def advanced_search(string, whitelist, blacklist):
    ind_whitelist = {}
    ind_blacklist = {}

    if not whitelist and not blacklist:
        return ind_whitelist, ind_blacklist

    idxs = search(string, whitelist+blacklist)

    for key, val_list in idxs.items():
        if key in whitelist:
            for val in val_list:
                ind_whitelist = add_element_to_dict(ind_whitelist, key, val)
        if key in blacklist:
            for val in val_list:
                ind_blacklist = add_element_to_dict(ind_blacklist, key, val)

    return ind_whitelist, ind_blacklist

def idx_to_bytes(byteidx, format):
    if format == "hex":
        return byteidx/2
    elif format == "bytearray":
        return byteidx
    else:
        print 'Unsupported Format: ' + format
        return -1

def bytes_to_idx(bytes, format):
    if format == "bytearray":
        return bytes
    elif format == "hex":
        return bytes*2
    else:
        print 'Unsupported Format: ' + format
        return -1

def parse_bytearray(bytearry, format):
    if format == "bytearray":
        return bytearry
    elif format == "hex":
        return ''.join([x.encode("hex") for x in bytearry])
    else:
        print 'Unsupported Format: ' + format
        return []


def parse_hex(hex, format):
    if format == "bytearray":
        return hex.decode("hex")
        #return [x.decode("hex") for x in hex]
    elif format == "hex":
        return hex
    else:
        print 'Unsupported Format: ' + format
        return []

def str_to_int(str, str_format, endian):
    hexstr = str
    if str_format == "bytearray":
        hexstr = parse_bytearray(str, "hex")
    if endian == "LE":
        hexstr = flip_str_endian(hexstr)
    return LE_signed_hex_str_to_int(hexstr)

def LE_signed_hex_str_to_int(addr):
    # Look for the negative output
    if addr[0].lower() == 'f':
        addr = - (0x100000000 - int('0x'+addr, 0))
    else:
        addr = int('0x'+addr, 0)
    return addr

def flip_str_endian(x):
    s = ''
    for i in range(0, len(x), 2):
        s = x[i:i+2] + s
    return s


def flip_list_endian(l):
    out = []
    for x in l:
        out.append(flip_str_endian(x))
    return out

def in_range(x, min, max):
    return x >= min and x <= max