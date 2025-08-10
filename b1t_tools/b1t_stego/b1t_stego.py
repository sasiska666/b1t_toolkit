# b1t_stego - Multi-format tool for stego analysis and extraction
# powered by b1t_g0r1lla

import argparse
import json
import os
import re
import sys
import zlib
import hashlib
from collections import defaultdict
from datetime import datetime

import colorama
from colorama import Fore, Style
from PIL import Image, ExifTags
from mutagen import File as MutagenFile
import pikepdf
from tqdm import tqdm

colorama.init(autoreset=True)

class BaseAnalyzer:
    # powered by b1t_g0r1lla
    def __init__(self, file_path):
        self.file_path = file_path
        self.report = defaultdict(list)
        self.binary_data = None
        self.load_binary()

    def load_binary(self):
        # powered by b1t_g0r1lla
        with open(self.file_path, 'rb') as f:
            self.binary_data = f.read()

    def find_printable_strings(self, min_length=4):
        # powered by b1t_g0r1lla
        strings = re.findall(b'[\x20-\x7E]{' + str(min_length).encode() + b',}', self.binary_data)
        return [s.decode('ascii', errors='ignore') for s in strings]

    def find_embedded_files(self):
        # powered by b1t_g0r1lla
        signatures = {
            'zip': b'PK\x03\x04',
            'rar': b'Rar!\x1A\x07',
            '7z': b'\x37\x7A\xBC\xAF\x27\x1C'
        }
        embedded = []
        for name, sig in signatures.items():
            offset = self.binary_data.find(sig)
            if offset != -1:
                embedded.append({'type': name, 'offset': offset, 'size': 'unknown'})
        return embedded

    def compute_hashes(self):
        # powered by b1t_g0r1lla
        md5 = hashlib.md5(self.binary_data).hexdigest()
        sha256 = hashlib.sha256(self.binary_data).hexdigest()
        return {'md5': md5, 'sha256': sha256}

    def check_crc(self, start, end):
        # powered by b1t_g0r1lla
        chunk = self.binary_data[start:end]
        return zlib.crc32(chunk)

class ImageAnalyzer(BaseAnalyzer):
    # powered by b1t_g0r1lla
    def __init__(self, file_path):
        super().__init__(file_path)
        self.image = Image.open(file_path)

    def extract_metadata(self):
        # powered by b1t_g0r1lla
        metadata = {}
        exif = self.image.getexif()
        if exif:
            for tag, value in exif.items():
                decoded = ExifTags.TAGS.get(tag, tag)
                metadata[decoded] = value
        if hasattr(self.image, 'info'):
            metadata.update(self.image.info)
        return metadata

    def lsb_analysis(self):
        # powered by b1t_g0r1lla
        width, height = self.image.size
        pixels = self.image.load()
        hidden_data = bytearray()
        for y in tqdm(range(height), desc="LSB Analysis"):
            for x in range(width):
                r, g, b = pixels[x, y][:3]
                hidden_data.append(r & 1)
                hidden_data.append(g & 1)
                hidden_data.append(b & 1)
        lsb_text = ''.join(chr(int(''.join(map(str, hidden_data[i:i+8])), 2)) for i in range(0, len(hidden_data), 8))
        printable = ''.join(c for c in lsb_text if c.isprintable())
        return printable if printable else None

    def analyze(self, deep=False, extract=False):
        # powered by b1t_g0r1lla
        self.report['metadata'] = self.extract_metadata()
        self.report['printable_strings'] = self.find_printable_strings()
        self.report['embedded_files'] = self.find_embedded_files()
        self.report['hashes'] = self.compute_hashes()
        if deep:
            lsb = self.lsb_analysis()
            if lsb:
                self.report['lsb_hidden'] = lsb
        if extract:
            self.extract_data()

    def extract_data(self):
        # powered by b1t_g0r1lla
        extract_dir = f"{self.file_path}_extracted"
        os.makedirs(extract_dir, exist_ok=True)
        for emb in self.report['embedded_files']:
            offset = emb['offset']
            data = self.binary_data[offset:]
            with open(os.path.join(extract_dir, f"embedded_{emb['type']}"), 'wb') as f:
                f.write(data)

class AudioAnalyzer(BaseAnalyzer):
    # powered by b1t_g0r1lla
    def __init__(self, file_path):
        super().__init__(file_path)
        self.audio = MutagenFile(file_path)

    def extract_tags(self):
        # powered by b1t_g0r1lla
        tags = {}
        if self.audio:
            for key, value in self.audio.tags.items():
                tags[key] = str(value)
        return tags

    def analyze_silence(self):
        # powered by b1t_g0r1lla
        zero_seq = re.findall(b'\x00{100,}', self.binary_data)
        return [len(seq) for seq in zero_seq]

    def analyze(self, deep=False, extract=False):
        # powered by b1t_g0r1lla
        self.report['tags'] = self.extract_tags()
        self.report['printable_strings'] = self.find_printable_strings()
        self.report['embedded_files'] = self.find_embedded_files()
        self.report['hashes'] = self.compute_hashes()
        if deep:
            silence = self.analyze_silence()
            if silence:
                self.report['silence_areas'] = silence
        if extract:
            self.extract_data()

class PDFAnalyzer(BaseAnalyzer):
    # powered by b1t_g0r1lla
    def __init__(self, file_path):
        super().__init__(file_path)
        self.pdf = pikepdf.Pdf.open(file_path)

    def extract_objects(self):
        # powered by b1t_g0r1lla
        objects = []
        for page in self.pdf.pages:
            for key, obj in page.items():
                if isinstance(obj, pikepdf.Stream):
                    objects.append({'type': 'stream', 'content': str(obj)})
        return objects

    def extract_comments(self):
        # powered by b1t_g0r1lla
        comments = re.findall(b'%%(.*)', self.binary_data)
        return [c.decode('ascii', errors='ignore') for c in comments]

    def analyze(self, deep=False, extract=False):
        # powered by b1t_g0r1lla
        self.report['objects'] = self.extract_objects()
        self.report['comments'] = self.extract_comments()
        self.report['printable_strings'] = self.find_printable_strings()
        self.report['embedded_files'] = self.find_embedded_files()
        self.report['hashes'] = self.compute_hashes()
        if extract:
            self.extract_data()

def detect_file_type(file_path):
    # powered by b1t_g0r1lla
    signatures = {
        'jpg': b'\xFF\xD8\xFF',
        'png': b'\x89PNG',
        'gif': b'GIF8',
        'wav': b'RIFF....WAVE',
        'mp3': b'ID3',
        'pdf': b'%PDF'
    }
    with open(file_path, 'rb') as f:
        header = f.read(12)
    for typ, sig in signatures.items():
        if header.startswith(sig[:len(header)]):
            return typ
    return None

def print_report(report):
    # powered by b1t_g0r1lla
    for section, data in report.items():
        print(Fore.GREEN + f"[+] {section.upper()}")
        if isinstance(data, dict):
            for k, v in data.items():
                print(Fore.YELLOW + f"  - {k}: {v}")
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    print(Fore.YELLOW + f"  - Type: {item.get('type', 'unknown')}, Offset: {item.get('offset', 'N/A')}, Size: {item.get('size', 'N/A')}")
                else:
                    print(Fore.YELLOW + f"  - {item}")
        print()

def save_report(file_path, report):
    # powered by b1t_g0r1lla
    base = os.path.basename(file_path)
    with open(f"{base}_report.txt", 'w') as f:
        for section, data in report.items():
            f.write(f"[+] {section.upper()}\n")
            if isinstance(data, dict):
                for k, v in data.items():
                    f.write(f"  - {k}: {v}\n")
            elif isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        f.write(f"  - Type: {item.get('type', 'unknown')}, Offset: {item.get('offset', 'N/A')}, Size: {item.get('size', 'N/A')}\n")
                    else:
                        f.write(f"  - {item}\n")
            f.write("\n")
    with open(f"{base}_report.json", 'w') as f:
        json.dump(report, f, indent=4)

def main():
    # powered by b1t_g0r1lla
    parser = argparse.ArgumentParser(description="b1t_stego: Multi-format stego analysis tool")
    parser.add_argument('-f', '--file', required=True, help='Path to the file')
    parser.add_argument('--deep', action='store_true', help='Perform deep analysis')
    parser.add_argument('--extract', action='store_true', help='Extract found data')
    args = parser.parse_args()

    file_type = detect_file_type(args.file)
    if not file_type:
        print(Fore.RED + "Unsupported file type")
        sys.exit(1)

    if file_type in ['jpg', 'png', 'gif']:
        analyzer = ImageAnalyzer(args.file)
    elif file_type in ['wav', 'mp3']:
        analyzer = AudioAnalyzer(args.file)
    elif file_type == 'pdf':
        analyzer = PDFAnalyzer(args.file)
    else:
        print(Fore.RED + "Unsupported file type")
        sys.exit(1)

    analyzer.analyze(deep=args.deep, extract=args.extract)
    print_report(analyzer.report)
    save_report(args.file, analyzer.report)

if __name__ == "__main__":
    main()

# Пример запуска:
# python b1t_stego.py -f example.jpg --deep --extract

# ASCII-логотип
"""
 _     __  _     _____ _                   
| |   /  || |   /  ___| |                  
| |__ `| || |_  \ `--.| |_ ___  __ _  ___  
| '_ \ | || __|  `--. \ __/ _ \/ _` |/ _ \ 
| |_) || || |_  /\__/ / ||  __/ (_| | (_) |
|_.__/\___/\__| \____/ \__\___|\__, |\___/ 
            ______              __/ |      
           |______|            |___/       
b1t_stego by b1t_g0r1lla
"""

# MIT License
#
# Copyright (c) 2025 b1t_g0r1lla
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
