import kagglehub
from pathlib import Path

# Download latest version
path = kagglehub.dataset_download("daumel/dns-tunneling-dataset")

print("Path to dataset files:", path)

dataset_path = Path(path) / "dns-exfiltration-dataset/02_generated_dataset"
output_file = Path("csv_files.txt")

csv_files = sorted(Path(dataset_path).rglob("*.csv"))

with output_file.open("w", encoding="utf-8") as f:
    for file in csv_files:
        f.write(str(file) + "\n")

print(f"Saved {len(csv_files)} CSV file paths to {output_file}")
