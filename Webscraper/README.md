# Web Scraper for Threat Intelligence

This project is a web scraper designed for gathering threat intelligence from google search results.

## Setup Instructions

Follow these steps to set up the project locally:

### 1. Clone the Repository
First, clone the repository to your local machine:

```bash
git clone -- no-checkout git@github.com:SuprimDevkota/Threat-Intel.git
cd Webscraper
git sparse-checkout init --cone
git sparse-checkout set Webscraper
git checkout
```

### 2. Navigate to the Project Directory
Change into the project directory:

```bash
cd Webscraper/
```

### 3. Create a Virtual Environment
Create a virtual environment to manage the dependencies:

```bash
python -m venv venv # For Windows
python3 -m venv venv # For MacOS/Linux
```

### 4. Activate the Virtual Environment
Activate the virtual environment:

```bash
venv\Scripts\activate # For Windows
source venv/bin/activate # For MacOS/Linux
```

### 5. Install Dependencies
Install the required dependencies listed in requirements.txt:
```bash
pip install -r src/requirements.txt
```

### 6. Navigate to the src Directory and add API Key and CSE ID
```bash
cd src
```
Create two files api_key.txt and cse_id.txt in the src directory:

`api_key.txt`: Your API key for accessing the web scraping services.\
`cse_id.txt`: Your custom search engine ID (CSE ID) for scraping.

### 7.  and run the script
Finally run the script:

```bash
python main.py
```