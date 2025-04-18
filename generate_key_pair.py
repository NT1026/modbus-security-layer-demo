import os
from utils import generate_key_pair


def main():
    if not os.path.exists("demo-keys"):
        os.makedirs("demo-keys")
    os.chdir("demo-keys")

    generate_key_pair("master")
    generate_key_pair("middleware")


if __name__ == "__main__":
    main()
