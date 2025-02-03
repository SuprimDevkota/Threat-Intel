import requests
from helium import *
import time
import iocextract

def google_search(query, api_key, cse_id, num_results=100):
    """Perform a Google Custom Search and return result links."""
    results = []
    url = "https://www.googleapis.com/customsearch/v1"
    
    for start in range(1, num_results, 10):  # API returns 10 results per request
        params = {
            'q': f'allintext:"IP address" {query}',
            'key': api_key,
            'cx': cse_id,
            'num': 10,
            'start': start
        }
        
        response = requests.get(url, params=params)
        
        if response.status_code == 200:
            data = response.json()
            results.extend(item['link'] for item in data.get("items", []))
        else:
            print(f"Error: {response.status_code}")
            break  # Stop if an error occurs
    
    return results

def extract_text_from_links(links, output_file):
    """Extracts text from web pages and saves it to a file."""
    browser = start_firefox(headless=False)
    
    with open(output_file, "a", encoding="utf-8") as file:
        for count, link in enumerate(links, start=1):
            try:
                go_to(link)
                curr_body = find_all(S('//body'))[0].web_element.text
                file.write(curr_body + "\n\n")
                print(f"Processed {count}/{len(links)}: {link}")
                time.sleep(1)  # Adjust delay as needed
            except Exception as e:
                print(f"Error processing {link}: {e}")
    
    browser.close()

def extract_iocs_from_file(input_file, output_file):
    """Extracts IOCs (Indicators of Compromise) from a text file and saves them."""
    with open(input_file, "r", encoding="utf-8") as file:
        content = file.read()
    
    ips = set(iocextract.extract_iocs(content, refang=True))
    
    with open(output_file, "w", encoding="utf-8") as file:
        file.write("\n".join(ips))

def main():
    with open("api_key.txt", "r") as file:
        api_key = file.read().strip()
    
    with open("cse_id.txt", "r") as file:
        cse_id = file.read().strip()
    
    malware_name = input("Enter the malware or campaign you'd like to search for: ").strip()
    
    text_filename = f"{malware_name}_body.txt"
    ioc_filename = f"{malware_name}_raw_iocs.txt"
    
    print(f"Searching Google for: {malware_name}")
    results = google_search(malware_name, api_key, cse_id)
    
    if not results:
        print("No results found.")
        return
    
    print(f"Extracting text from {len(results)} links...")
    extract_text_from_links(results, text_filename)
    
    print("Extracting IOCs...")
    extract_iocs_from_file(text_filename, ioc_filename)
    
    print(f"Process complete. Results saved to {text_filename} and {ioc_filename}.")

if __name__ == "__main__":
    main()
