import os
import requests
import json
import re
from selenium import webdriver
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.common.by import By
import asyncio
import aiohttp  
import iocextract

# Configure logging
import logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Load API key and CSE ID from files
def load_config(api_key_file, cse_id_file):
    try:
        with open(api_key_file, 'r') as file:
            api_key = file.read().strip()
        with open(cse_id_file, 'r') as file:
            cse_id = file.read().strip()
        return api_key, cse_id
    except Exception as e:
        logging.error(f"Failed to load configuration files: {e}")
        raise

# Google Custom Search function
async def google_search(query, api_key, cse_id, links_file):
    try:
        url = f"https://www.googleapis.com/customsearch/v1?q={query}&key={api_key}&cx={cse_id}"
        headers = {'Content-Type': 'application/json'}
        
        async with aiohttp.ClientSession() as session:
            response = await session.get(url, headers=headers)
            response.raise_for_status()
            data = await response.json()

            links = []
            if 'items' in data:
                for item in data['items']:
                    links.append(item['link'])

            with open(links_file, 'w') as file:
                for link in links:
                    file.write(link + '\n')
            logging.info(f"Saved {len(links)} links to {links_file}")
            return links
    except Exception as e:
        logging.error(f"Error during Google search: {e}")
        raise

# Extract text from links using Selenium
async def extract_text_from_links(links, text_file):
    try:
        options = Options()
        options.headless = True  # Run in headless mode to avoid opening a browser window
        driver = webdriver.Firefox(options=options)

        texts = []
        for link in links:
            try:
                logging.info(f"Extracting text from {link}")
                driver.get(link)
                body_text = driver.find_element(By.TAG_NAME, 'body').text
                texts.append(body_text)
            except Exception as e:
                logging.error(f"Failed to extract text from {link}: {e}")

        with open(text_file, 'w', encoding='utf-8') as file:
            for text in texts:
                file.write(text + '\n')
        logging.info(f"Saved extracted text to {text_file}")
    except Exception as e:
        logging.error(f"Error during text extraction: {e}")
    finally:
        driver.quit()

# Extract IOCs from a text file
def extract_iocs_from_file(input_file, output_file):
    try:
        with open(input_file, 'r', encoding='utf-8') as file:
            content = file.read()
        
        iocs = iocextract.extract(content)
        if not iocs:
            logging.info("No IOCs found in the text")
            return

        with open(output_file, 'w') as file:
            for ioc in iocs:
                file.write(ioc + '\n')
        logging.info(f"Saved {len(iocs)} IOCs to {output_file}")
    except Exception as e:
        logging.error(f"Error during IOC extraction: {e}")

# Extract IPs from extracted IOCs
def extract_ips_from_ioc(input_file, output_file):
    try:
        with open(input_file, 'r') as file:
            iocs = file.readlines()

        ip_pattern = re.compile(r'\b((?:\d{1,3}\.){3}\d{1,3})\b')
        ips = set()
        for ioc in iocs:
            matches = ip_pattern.findall(ioc.strip())
            if matches:
                ips.update(matches)

        if not ips:
            logging.info("No IPs found in the IOCs")
            return

        with open(output_file, 'w') as file:
            for ip in ips:
                file.write(ip + '\n')
        logging.info(f"Saved {len(ips)} unique IPs to {output_file}")
    except Exception as e:
        logging.error(f"Error during IP extraction: {e}")

# Main function
async def main():
    malware_name = input("Enter the malware name: ").strip()
    if not malware_name:
        logging.error("Malware name cannot be empty")
        return

    api_key_file = 'api_key.txt'
    cse_id_file = 'cse_id.txt'
    links_file = 'links.txt'
    text_file = 'text_output.txt'
    iocs_file = 'iocs_output.txt'
    ips_file = 'ips_output.txt'

    try:
        api_key, cse_id = load_config(api_key_file, cse_id_file)
        logging.info("Configuration loaded successfully")

        query = f"malware campaign {malware_name}"
        links = await google_search(query, api_key, cse_id, links_file)

        if not links:
            logging.warning("No links found for the given query")
            return

        await extract_text_from_links(links, text_file)
        extract_iocs_from_file(text_file, iocs_file)
        extract_ips_from_ioc(iocs_file, ips_file)

    except Exception as e:
        logging.error(f"An error occurred in the main function: {e}")

if __name__ == "__main__":
    asyncio.run(main())
