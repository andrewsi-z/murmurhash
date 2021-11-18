import murmurhash.mrmr

def test_murmurhash2_hash64_1():
    string = 'fransisco'
    seed = 1
    expect=0x83fdaf4a6d0d3d9
    output = murmurhash.mrmr.hash64A(string,seed)
    assert output == expect

def test_murmurhash2_hash64_2():
    string = 'aaaa'
    seed = 0x9747b28c
    expect=0x41da53fdabaf04c8
    output = murmurhash.mrmr.hash64A(string,seed)
    assert output == expect
