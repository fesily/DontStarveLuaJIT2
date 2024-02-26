import os

__all__ = ["read_version"] 

def read_version():
    GameDir = os.getenv("GAME_DIR")
    current_game_version = 0
    try:
        with open(f"{GameDir}/version.txt","r") as fp:
            current_game_version = fp.readline().strip()
    except FileNotFoundError:
        pass
    return current_game_version
