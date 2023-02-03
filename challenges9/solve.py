def padding(s, l):
    pad_len = l - len(s)
    return s + "\\x{0:0{1}x}".format(pad_len,2) * pad_len

print(padding("YELLOW SUBMARINE", 20))