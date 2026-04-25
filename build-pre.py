import PyInstaller.__main__
import os
import shutil

APP_NAME = "path_preloader"
ICON_PATH = "icon.ico" if os.path.exists("icon.ico") else None

params = [
    "path_preloader-pre.py", 
    "--name", APP_NAME,           
    "--noconsole",         
    "--icon", ICON_PATH if ICON_PATH else "NONE",
    "--distpath", "dist"   
]

PyInstaller.__main__.run(params)
print(f"\n{APP_NAME} package in dist")
