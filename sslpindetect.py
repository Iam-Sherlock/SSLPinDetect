import re
import os
import zipfile
import json
import shutil
import argparse
import time
import subprocess
from tqdm import tqdm
from colorama import Fore, Style, init
from concurrent.futures import ThreadPoolExecutor, as_completed
import mmap

init(autoreset=True)

SSL_WEIGHTS = {
    "TrustManager SSL Pinning": 25,
    "OkHttp3 Certificate Pinning": 35,
    "SSLSocketFactory": 8,
    "Trustkit Certificate Pinning": 40,
    "Conscrypt TrustManagerImpl Pinning": 30,
    "Appcelerator Certificate Pinning": 35,
    "Fabric Certificate Pinning": 35,
    "Conscrypt OpenSSLSocketImpl Pinning": 30,
    "Conscrypt OpenSSLEngineSocketImpl Pinning": 30,
    "Apache Harmony OpenSSLSocketImpl Pinning": 30,
    "PhoneGap Certificate Checker": 30,
    "IBM MobileFirst Certificate Pinning": 40,
    "IBM WorkLight HostNameVerifier Pinning": 35,
    "Conscrypt CertPinManager Pinning": 35,
    "CWAC-Netsecurity CertPinManager Pinning": 35,
    "Worklight Androidgap Pinning Plugin": 35,
    "Netty Fingerprint TrustManager": 35,
    "Squareup Certificate Pinning (OkHTTP<v3)": 35,
    "Squareup OkHostnameVerifier Pinning": 30,
    "Android WebViewClient SSL Pinning": 20,
    "Apache Cordova WebViewClient Pinning": 20,
    "Boye AbstractVerifier Pinning": 25,
    "Apache AbstractVerifier Pinning": 25,
    "Chromium Cronet Pinning": 35,
    "Flutter HttpCertificatePinning": 40,
    "Flutter SslPinningPlugin": 40,
    "Custom Certificate Pinning": 20,
}

ROOT_WEIGHTS = {
    "Root Detection - SU Binary Check": 25,
    "Root Detection - Command Execution": 15,
    "Root Detection - Build Tags": 10,
    "Root Detection - Root Apps": 20,
    "Root Detection - Dangerous Files": 20,
    "Root Detection - RootBeer Library": 35,
    "Root Detection - SafetyNet / Play Integrity": 25,
}

def check_java():
    if os.system("java -version >nul 2>&1") != 0:
        print("Java is not installed or not in PATH. Please install JDK and ensure it's in your system PATH.")
        exit(1)

def check_apktool(apktool_path):
    if not os.path.isfile(os.path.expanduser(apktool_path)):
        raise SystemExit(f"Apktool not found at {apktool_path}")

def extract_apk(apktool_path, apk_path, output_dir, verbose):
    command = [
        "java", "-jar", apktool_path, "d", apk_path, "-o", output_dir
    ]

    try:
        subprocess.run(command, check=True, stdout=subprocess.PIPE if not verbose else None, stderr=subprocess.PIPE if not verbose else None)
        if verbose:
            print("APK successfully decompiled.")
        else:
            print("Processing APK...")
    except subprocess.CalledProcessError as e:
        print(f"Error occurred: {e}")

def load_patterns(pattern_file):
    with open(pattern_file, 'r', encoding='utf-8') as f:
        raw_patterns = json.load(f)

    patterns = {}
    for category, values in raw_patterns.items():
        combined_pattern = "|".join(values)
        patterns[category] = re.compile(combined_pattern)

    return patterns

def detect_frameworks(decompiled_dir):
    frameworks = []
    flutter_files = ["libflutter.so", "libapp.so"]
    flutter_folders = ["flutter_assets"]
    react_files = ["libreactnativejni.so", "index.android.bundle"]
    react_folders = ["assets/react"]

    for root, dirs, files in os.walk(decompiled_dir):
        if any(f in files for f in flutter_files) or any(d in dirs for d in flutter_folders):
            frameworks.append("Flutter")
        if any(f in files for f in react_files) or any(d in dirs for d in react_folders):
            frameworks.append("React Native")

    return set(frameworks)

def process_file(file_path, patterns):
    results = {}
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            with mmap.mmap(f.fileno(), length=0, access=mmap.ACCESS_READ) as mm:
                content = mm.read().decode('utf-8', errors='ignore')
                for category, regex in patterns.items():
                    for match in regex.finditer(content):
                        line_number = content.count('\n', 0, match.start()) + 1
                        line_preview = content[match.start():match.end()].strip()
                        if category not in results:
                            results[category] = []
                        results[category].append((file_path, line_number, line_preview))
    except Exception as e:
        print(f"Error processing file {file_path}: {e}")

    return results

def search_ssl_pinning(smali_dir, patterns):
    smali_files = [
        os.path.join(root, file)
        for root, _, files in os.walk(smali_dir)
        for file in files if file.endswith(".smali")
    ]

    if not smali_files:
        return {}, 0

    results = {}
    match_count = 0
    match_pbar = tqdm(desc=f"{Fore.GREEN}Pattern Matched{Style.RESET_ALL}", position=1, bar_format="{desc}: {n}")

    with ThreadPoolExecutor() as executor:
        futures = {executor.submit(process_file, file, patterns): file for file in smali_files}
        for future in tqdm(as_completed(futures), total=len(smali_files), desc="Scanning Smali Files", position=0):
            file_results = future.result()
            for category, matches in file_results.items():
                if category not in results:
                    results[category] = []
                results[category].extend(matches)
                match_count += len(matches)
                match_pbar.update(len(matches))

    return results, match_count

def summarize_confidence(results):
    ssl_categories = [category for category in results if category in SSL_WEIGHTS]
    root_categories = [category for category in results if category in ROOT_WEIGHTS]

    ssl_score, ssl_label, ssl_reason = build_confidence_summary(results, ssl_categories, SSL_WEIGHTS, "ssl")
    root_score, root_label, root_reason = build_confidence_summary(results, root_categories, ROOT_WEIGHTS, "root")

    return {
        "ssl": {"score": ssl_score, "label": ssl_label, "reason": ssl_reason},
        "root": {"score": root_score, "label": root_label, "reason": root_reason},
    }

def build_confidence_summary(results, categories, weights, summary_type):
    if not categories:
        if summary_type == "ssl":
            return 0, "None", "No SSL-related patterns were matched."
        return 0, "None", "No root-detection patterns were matched."

    score = 0
    evidence = []

    for category in categories:
        score += weights.get(category, 0)
        match_count = len(results.get(category, []))
        file_count = len({file_path for file_path, _, _ in results.get(category, [])})
        evidence.append((weights.get(category, 0), f"{category} ({match_count} hits in {file_count} file(s))"))

    distinct_categories = len(categories)
    if distinct_categories >= 3:
        score += 10
    elif distinct_categories == 2:
        score += 5

    score = min(score, 100)

    if score >= 70:
        label = "High"
    elif score >= 40:
        label = "Medium"
    else:
        label = "Low"

    evidence.sort(reverse=True)
    top_reasons = ", ".join(reason for _, reason in evidence[:3])

    if summary_type == "ssl" and categories == ["SSLSocketFactory"]:
        label = "Low"
        score = min(score, 20)
        top_reasons = "Only generic SSLSocketFactory/HttpsURLConnection usage was found, which is not enough by itself to prove certificate pinning."

    return score, label, top_reasons

def print_confidence_summary(summary):
    print(f"\n{Fore.CYAN}Confidence Summary{Style.RESET_ALL}")
    print(
        f"  - SSL Pinning Confidence: {summary['ssl']['score']}/100 ({summary['ssl']['label']})\n"
        f"\t{summary['ssl']['reason']}"
    )
    print(
        f"  - Root Detection Confidence: {summary['root']['score']}/100 ({summary['root']['label']})\n"
        f"\t{summary['root']['reason']}"
    )

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SSL Pinning Detector for Android APKs by petruknisme")
    parser.add_argument("-f", "--file", required=True, help="Path to the APK file")
    parser.add_argument("-p", "--pattern", default="patterns.json", help="Path to the JSON file containing SSL pinning patterns")
    parser.add_argument("-a", "--apktool", required=True, help="Path to the apktool.jar file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode")
    args = parser.parse_args()

    print(f"{Fore.YELLOW}SSLPinDetect by petruknisme{Style.RESET_ALL}\n")

    check_java()
    check_apktool(args.apktool)

    apk_name = os.path.basename(args.file).replace(".apk", "")
    timestamp = int(time.time())
    output_dir = f"{apk_name}_decompile_{timestamp}"

    extract_apk(args.apktool, args.file, output_dir, args.verbose)

    frameworks = detect_frameworks(output_dir)
    if frameworks:
        print(f"{Fore.BLUE}Detected Frameworks: {', '.join(frameworks)}{Style.RESET_ALL}")
        if "Flutter" in frameworks:
            print(f"{Fore.BLUE}Flutter APK detected. Continuing smali scan for plugin and wrapper code.{Style.RESET_ALL}")

    patterns = load_patterns(args.pattern)
    results, match_count = search_ssl_pinning(output_dir, patterns)

    if not results:
        print("No SSL Pinning patterns detected in smali code.")
    else:
        print(f"{Fore.GREEN}Total Patterns Matched: {match_count}{Style.RESET_ALL}")
        for category, matches in results.items():
            print(f"{Fore.GREEN}Pattern detected: {category}{Style.RESET_ALL}")
            for file_path, line_number, line_preview in matches:
                print(f"  - {file_path}\n\t[Line {line_number}]: {line_preview}")

    print_confidence_summary(summarize_confidence(results))

    shutil.rmtree(output_dir, ignore_errors=True)
