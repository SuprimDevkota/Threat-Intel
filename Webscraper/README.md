# Web Scraper for Threat Intelligence

This project is a web scraper designed for gathering threat intelligence from google search results.

## Setup Instructions

Follow these steps to set up the project locally:

### 1. Clone the Repository
First, clone the repository to your local machine:

```bash
git clone git@github.com:SuprimDevkota/Threat-Intel.git
```

### 2. Navigate to the Project Directory
Change into the project directory:

```bash
cd Threat-Intel/Webscraper/
```

### 3. Create a Virtual Environment
Create a virtual environment to manage the dependencies:

```bash
python -m venv venv
```

### 4. Activate the Virtual Environment
Activate the virtual environment:

For Windows:
```bash
venv\Scripts\activate
```

For macOS/Linux:
```bash
source venv/bin/activate
```

### 5. Install Dependencies
Install the required dependencies listed in requirements.txt:
```bash
pip install -r src/requirements.txt
```

### 6. Add API Key and CSE ID
Create two files api_key.txt and cse_id.txt in the src directory:

`api_key.txt`: Your API key for accessing the web scraping services.\
`cse_id.txt`: Your custom search engine ID (CSE ID) for scraping.

### 7. Navigate to the src Directory and run the script
Finally, change into the src directory and run the script:

```bash
cd src
python main.py
```