import subprocess
import sys

def install_requirements():
    # Nama file requirements
    requirements_file = 'requirements.txt'
    
    # Install package
    try:
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', '-r', requirements_file])
        print("All requirements have been installed successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error occurred while installing packages: {e}")
        sys.exit(1)

if __name__ == "__main__":
    install_requirements()
