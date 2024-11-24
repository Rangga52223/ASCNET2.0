import subprocess

required_packages = [
    "pandas", 
    "joblib", 
    "numpy", 
    "websockets", 
    "asyncio"
]

def install(package):
    subprocess.check_call(["python", "-m", "pip", "install", package])

for package in required_packages:
    install(package)
