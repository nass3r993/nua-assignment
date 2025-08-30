import os

tests_dir = "tests"

for filename in os.listdir(tests_dir):
    if filename.endswith(".py"):
        file_path = os.path.join(tests_dir, filename)
        print(f"Running {file_path}...")
        # Execute the Python file
        exit_code = os.system(f"python {file_path}")
        print("\033[32m" + "-" * 60 + "\033[0m\n\n")
