def increment_version(version_str):
    major, minor, patch = version_str.split(".")

    patch = int(patch) + 1

    new_version_str = f"{major}.{minor}.{patch}"
    return new_version_str


with open("version.txt", "r+") as f:
    current_version = f.readline()
    new_version = increment_version(current_version)
    f.seek(0)
    f.write(new_version)
    with open("mod/modinfo.lua", "br+") as modinfo:
        info = modinfo.read()
        info = info.replace(bytes(current_version, "utf8"), bytes(new_version, "utf8"))
        modinfo.seek(0)
        modinfo.write(info)
