def validate_pad(s):
    pad_size = s[-1]
    if s[-pad_size:] != (pad_size.to_bytes(1,'little') * pad_size):
        raise Exception
    return True

validate_pad(b'ICE ICE BABY\x04\x04\x04\x04')
validate_pad(b'ICE ICE BABY\x01\x02\x03\x04')