from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
import re
import string
from selenium.common.exceptions import StaleElementReferenceException

def fetch_youtube_links(query):
    # Set up Selenium options
    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--remote-debugging-port=9222")
    chrome_options.add_argument("--user-data-dir=C:/Temp/ChromeUserData")
    chrome_options.add_argument("--enable-logging")
    chrome_options.add_argument("--v=1")

    chrome_driver_path = "C:\\Program Files (x86)\\chromedriver.exe"
    service = Service(chrome_driver_path)
    driver = webdriver.Chrome(service=service, options=chrome_options)

    try:
        url = f'https://www.youtube.com/results?search_query={query}'
        driver.get(url)
        driver.implicitly_wait(30)

        anchor_tags = driver.find_elements(By.TAG_NAME, 'a')

        youtube_video_pattern = re.compile(r'https://www\.youtube\.com/watch\?v=[\w-]+')

        youtube_links = set()
        for tag in anchor_tags:
            try:
                href = tag.get_attribute('href')
                if href:
                    match = youtube_video_pattern.match(href)
                    if match:
                        clean_url = re.sub(r'&.*$', '', match.group())
                        youtube_links.add(clean_url)
            except StaleElementReferenceException:
                continue

        return list(youtube_links)

    finally:
        driver.quit()

def save_links_to_file(links, filename):
    with open(filename, 'a') as file:
        for link in links:
            file.write(link + '\n')

if __name__ == '__main__':
    search_queries = list(string.ascii_lowercase)

    output_filename = 'youtube_links.txt'

    for query in search_queries:
        youtube_links = fetch_youtube_links(query)
        save_links_to_file(youtube_links, output_filename)
        print(f"Saved {len(youtube_links)} links for query '{query}' to {output_filename}")
