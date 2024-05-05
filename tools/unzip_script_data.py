import zipfile
import os
import sys
import pathlib

root_dir = sys.argv[1] or os.getcwd()
dataDir = pathlib.Path(root_dir, "data")
databundleDir =  pathlib.Path(dataDir, "databundles")
scriptsZipPath =  pathlib.Path(databundleDir, "scripts.zip")
targetPath = pathlib.Path(dataDir, "scripts")
os.removedirs(targetPath)

# ����һ��ZipFile����
with zipfile.ZipFile(scriptsZipPath, 'r') as zip_ref:
    # ��ѹzip�ļ���ָ��Ŀ���ļ���
    zip_ref.extractall(targetPath)

os.rename(scriptsZipPath, pathlib.Path(scriptsZipPath, ".bak"))

print("��ѹ��ɣ�")
