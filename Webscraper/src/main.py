import re
import requests
from helium import *
import time
import iocextract
import requests
import os
import pdfplumber
import shutil

def google_search(query, api_key, cse_id, output_file, pdf_output_file, num_results=100, days=None):
    """Perform a Google Custom Search and separate .pdf links from other results."""
    results = []
    pdf_results = []
    url = "https://www.googleapis.com/customsearch/v1"
    
    for start in range(1, num_results, 10):  # API returns 10 results per request
        params = {
            'q': f'intext:"{query}" (intext:"IP Address" OR intext:"IOCs")',
            'key': api_key,
            'cx': cse_id,
            'num': 10,
            'start': start
        }
        
        # Add date restriction if days is specified
        if days:
            params['dateRestrict'] = f'd{days}'
        
        response = requests.get(url, params=params)
        
        if response.status_code == 200:
            data = response.json()
            for item in data.get("items", []):
                link = item['link']
                if link.endswith('.pdf'):
                    pdf_results.append(link)
                else:
                    results.append(link)
        else:
            print(f"Error: {response.status_code}")
            break  # Stop if an error occurs
    
    # Save all links
    with open(output_file, "w") as file:
        for result in results:
            file.write(result + '\n')
    
    # Save .pdf links separately
    with open(pdf_output_file, "w") as pdf_file:
        for pdf in pdf_results:
            pdf_file.write(pdf + '\n')
    
    return results, pdf_results

def extract_text_from_links(links, output_file):
    """Extracts text from web pages and saves it to a file."""
    browser = start_firefox(headless=False)
    
    with open(output_file, "a", encoding="utf-8") as file:
        for count, link in enumerate(links, start=1):
            try:
                go_to(link)
                curr_body = find_all(S('//body'))[0].web_element.text
                file.write(link + "\n---------\n")
                file.write(curr_body + "\n\n")
                print(f"Processed {count}/{len(links)}: {link}")
                time.sleep(1)  # Adjust delay as needed
            except Exception as e:
                print(f"Error processing {link}: {e}")
        
        file.write("\n\n\nPDFS!~89723\n\n\n")
    
    browser.close()

def extract_iocs_from_file(input_file, output_file):
    """Extracts IOCs (Indicators of Compromise) from a text file and saves them."""
    iocs = set()
    with open(input_file, "r", encoding="utf-8") as file:
        for line in file:
            iocs.update(iocextract.extract_iocs(line, refang=True))
        
    with open(output_file, "w", encoding="utf-8") as file:
        file.write("\n".join(iocs))

def extract_ips_from_ioc(input_file, output_file):
    """Extract IPs from the IOCs. Since iocextract doesn't do this well, I'll use a custom regex"""
    with open(input_file, "r", encoding="utf-8") as file:
        content = file.read()

    pattern = r"\b((?:\d{1,3}\.){3}\d{1,3})\b"
    matches = re.findall(pattern, content)

    with open(output_file, "w", encoding="utf-8") as file:
        for match in matches:
            file.write(match + '\n')

def links_processor(results, body_filename, ioc_filename, ip_filename):
    """Main function to process links and extract malicious IPs from them"""
    if not results:
        print("No results found")
        return
    
    print(f"Extracting text from {len(results)} links...")
    extract_text_from_links(results, body_filename)
    
    print("Extracting IOCs...")
    extract_iocs_from_file(body_filename, ioc_filename)
    
    print("Extracting IP Addresses...")
    extract_ips_from_ioc(ioc_filename, ip_filename)

    print(f"Link processing complete. Results saved to {body_filename}, {ioc_filename} and {ip_filename}.")

def download_pdfs(pdf_urls, temp_dir="temp_pdfs"):
    """Download PDFs from a list of URLs into a specified temporary directory."""
    
    os.makedirs(temp_dir, exist_ok=True)  # Ensure temp directory exists
    downloaded_files_path = []
    
    # Headers to mimic a browser request
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Accept": "application/pdf",
    }

    for url in pdf_urls:
        try:
            response = requests.get(url, headers=headers, stream=True)
            if response.status_code == 200:
                filename = os.path.join(temp_dir, os.path.basename(url))

                with open(filename, "wb") as file:
                    for chunk in response.iter_content(1024):
                        file.write(chunk)

                downloaded_files_path.append(filename)
                print(f"Downloaded: {filename}")
            else:
                print(f"Failed to download {url} - Status code: {response.status_code}")
        except Exception as e:
            print(f"Error downloading {url}: {e}")

    return downloaded_files_path  # Returns the temp directory path and list of downloaded files

def extract_text_from_pdf(pdf_path, output_file):
    text = ""
    try:
        with pdfplumber.open(pdf_path) as pdf:
            for page in pdf.pages:
                text += page.extract_text() or ""  # Handle empty pages
    except Exception as e:
        print(f"Error processing {pdf_path}: {e}")
        return None  # Return None for invalid PDFs

    with open(output_file, "a", encoding="utf-8") as file:
        file.write(text)
    return text

def extract_iocs_from_pdf_text(text):
    return {
        "IP Addresses": re.findall(r'\d{1,3}(?:\[\.\]|\.)\d{1,3}(?:\[\.\]|\.)\d{1,3}(?:\[\.\]|\.)\d{1,3}', text),
    }

def save_pdf_iocs_to_file(iocs, output_file):
    with open(output_file, 'a') as f:
        for _, values in iocs.items():
            if values:  # Only write non-empty categories
                for value in sorted(set(values)):  # Remove duplicates and sort
                    f.write(f"{iocextract.refang_ipv4(value)}\n")

def cleanup_temp_dir(temp_dir="temp_pdfs"):
    """Remove the temporary directory and all its contents."""
    if os.path.exists(temp_dir):
        shutil.rmtree(temp_dir)

def pdf_processor(pdf_results, body_filename, ip_filename):
    """Main function to process pdfs and extract malicious IPs from them"""
    if not pdf_results:
        print("No results found")
        return
    
    print(f"Downloading pdfs from {len(pdf_results)} links...")
    pdf_paths = download_pdfs(pdf_results)

    for pdf_path in pdf_paths:
        print(f"Extracting text from {pdf_path}...")
        text = extract_text_from_pdf(pdf_path, body_filename)
    
        if text is None:
            print(f"Skipping {pdf_path} due to errors.")
            continue
        
        print(f"Extracting IOCs from {pdf_path}...")
        iocs = extract_iocs_from_pdf_text(text)
        
        print(f"Saving IOCs for {pdf_path}...")
        save_pdf_iocs_to_file(iocs, ip_filename)

    cleanup_temp_dir()

    print("Cleaned up temporary PDF files.")
    print(f"PDF processing complete. Results saved to {body_filename} and {ip_filename}.")

def remove_duplicates(input_file):
    mal_ips = set()
    with open(input_file, 'r', encoding='utf-8') as file:
        for line in file:
            mal_ips.add(line.strip())

    with open(input_file, 'w', encoding='utf-8') as file:
        for ip in sorted(mal_ips): 
            file.write(ip + '\n')

def main():
    with open("api_key.txt", "r") as file:
        api_key = file.read().strip()
    
    with open("cse_id.txt", "r") as file:
        cse_id = file.read().strip()
    
    malware_name = input("Enter the malware or campaign you'd like to search for: ").strip()
    days = input("Enter the number of past days to search (press Enter to skip): ").strip() or None
    
    links_filename = f"{malware_name}_links.txt"
    pdf_links_filename = f"{malware_name}_pdf_links.txt"
    body_filename = f"{malware_name}_body.txt"
    ioc_filename = f"{malware_name}_raw_iocs.txt"
    ip_filename = f"{malware_name}_ips.txt"
    
    print(f"Searching Google for: {malware_name}")
    results, pdf_results = google_search(malware_name, api_key, cse_id, links_filename, pdf_links_filename, days=days)

    # For actual links 
    links_processor(results, body_filename, ioc_filename, ip_filename)

    # For pdfs
    pdf_processor(pdf_results, body_filename, ip_filename)

    # Remove duplicates to conserve API usage
    remove_duplicates(ip_filename)

if __name__ == "__main__":
    main()
