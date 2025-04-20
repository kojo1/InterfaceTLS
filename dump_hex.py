def dump_hex(title: str, bin: bytes):
    print(f"{title}: ")
    loops = 0
    for b in bin:
        loops += 1
        print(f" {b:02x}", end="")
        if loops == 16:
            print("")
            loops = 0
    print("")
