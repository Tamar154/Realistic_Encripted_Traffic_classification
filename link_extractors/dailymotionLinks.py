from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import re
import string
from selenium.common.exceptions import StaleElementReferenceException, TimeoutException


def fetch_dailymotion_links(query):
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
        url = f'https://www.dailymotion.com/search/{query}/videos'
        driver.get(url)

        wait = WebDriverWait(driver, 30)
        try:
            wait.until(EC.presence_of_all_elements_located((By.XPATH, '//a[contains(@href, "/video/")]')))
        except TimeoutException:
            print(f"No video links found for query '{query}'")
            return []

        video_links = driver.find_elements(By.XPATH, '//a[contains(@href, "/video/")]')

        dailymotion_links = set()
        for tag in video_links:
            try:
                href = tag.get_attribute('href')
                if href and re.match(r'https://www\.dailymotion\.com/video/[\w-]+', href):
                    dailymotion_links.add(href)
            except StaleElementReferenceException:
                continue
        return list(dailymotion_links)

    finally:
        driver.quit()


def save_links_to_file(links, filename):
    with open(filename, 'a') as file:
        for link in links:
            file.write(link + '\n')


if __name__ == '__main__':
    search_queries = list(string.ascii_lowercase)

    output_filename = 'dailymotion_links.txt'

    for query in search_queries:
        dailymotion_links = fetch_dailymotion_links(query)
        save_links_to_file(dailymotion_links, output_filename)
        print(f"Saved {len(dailymotion_links)} links for query '{query}' to {output_filename}")
