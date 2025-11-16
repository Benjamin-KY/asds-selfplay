#!/usr/bin/env python3
"""
Download CVEFixes dataset from Zenodo.

The dataset is large (~2-3 GB compressed), so this script helps automate
the download and extraction process.
"""

import argparse
import requests
import sys
from pathlib import Path
from tqdm import tqdm


ZENODO_DOI = "10.5281/zenodo.4476563"
ZENODO_LATEST_API = "https://zenodo.org/api/records/4476563"  # Latest version API


def download_file(url: str, output_path: Path, chunk_size: int = 8192):
    """Download file with progress bar"""
    response = requests.get(url, stream=True)
    response.raise_for_status()

    total_size = int(response.headers.get('content-length', 0))

    with open(output_path, 'wb') as f, tqdm(
        desc=output_path.name,
        total=total_size,
        unit='B',
        unit_scale=True,
        unit_divisor=1024,
    ) as pbar:
        for chunk in response.iter_content(chunk_size=chunk_size):
            if chunk:
                f.write(chunk)
                pbar.update(len(chunk))


def get_dataset_url():
    """Get latest dataset download URL from Zenodo API"""
    print(f"Fetching dataset info from Zenodo (DOI: {ZENODO_DOI})...")

    response = requests.get(ZENODO_LATEST_API)
    response.raise_for_status()

    data = response.json()

    # Find the database file
    for file_info in data['files']:
        filename = file_info['key']
        if filename.endswith('.db') or filename.endswith('.db.zip') or filename.endswith('.db.gz'):
            return file_info['links']['self'], filename

    raise ValueError("No database file found in Zenodo record")


def main():
    parser = argparse.ArgumentParser(
        description="Download CVEFixes dataset from Zenodo"
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="data/datasets",
        help="Directory to save dataset (default: data/datasets)"
    )
    parser.add_argument(
        "--skip-existing",
        action="store_true",
        help="Skip download if file already exists"
    )

    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    try:
        # Get download URL
        download_url, filename = get_dataset_url()
        output_path = output_dir / filename

        print(f"\nDataset file: {filename}")
        print(f"Download URL: {download_url}")
        print(f"Output path: {output_path}")

        # Check if already exists
        if output_path.exists() and args.skip_existing:
            print(f"\n✓ File already exists: {output_path}")
            print("Use --skip-existing=false to re-download")
            return

        # Download
        print(f"\nDownloading CVEFixes dataset...")
        print("This may take several minutes (file is ~2-3 GB)...\n")

        download_file(download_url, output_path)

        print(f"\n✓ Download complete: {output_path}")

        # Check if compressed
        if filename.endswith('.zip'):
            print("\nExtracting ZIP archive...")
            import zipfile
            with zipfile.ZipFile(output_path, 'r') as zip_ref:
                zip_ref.extractall(output_dir)
            print("✓ Extraction complete")

        elif filename.endswith('.gz'):
            print("\nExtracting GZ archive...")
            import gzip
            import shutil
            db_path = output_dir / filename.replace('.gz', '')
            with gzip.open(output_path, 'rb') as f_in:
                with open(db_path, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
            print("✓ Extraction complete")

        # Find .db file
        db_files = list(output_dir.glob("*.db"))
        if db_files:
            print(f"\n✓ Dataset ready: {db_files[0]}")
            print(f"\nTo use in Python:")
            print(f"  from src.datasets import CVEFixesLoader")
            print(f"  loader = CVEFixesLoader('{db_files[0]}')")
            print(f"  samples = loader.load_samples(language='python', limit=10)")
        else:
            print("\n⚠ Warning: No .db file found after extraction")

    except Exception as e:
        print(f"\n✗ Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
