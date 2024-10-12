import json
import os
import re
import shutil
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from scapy.arch import get_if_addr
from scapy.config import conf
from selenium.common import TimeoutException, NoSuchElementException, ElementClickInterceptedException
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
import time
from queue import Queue  # Change from LifoQueue to Queue
from scapy.all import sniff, AsyncSniffer, wrpcap
import pyshark
import random
import subprocess
from urllib.parse import urljoin, urlparse
import platform
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
import os
import pickle
from datetime import datetime
from datetime import timezone
from datetime import timedelta

print(platform.architecture())
# Define the scope for Google Calendar API
SCOPES = ['https://www.googleapis.com/auth/calendar.events']


def get_random_file(directory):
    """
    Selects a random file from the specified directory.

    :param directory: The path to the directory from which to select the file.
    :return: The full path of the randomly selected file.
    """
    try:
        # List all files in the directory
        files = [f for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f))]
        if not files:
            raise Exception("No files found in the directory.")

        # Select a random file
        random_file = random.choice(files)
        return os.path.join(directory, random_file)
    except Exception as e:
        print("Error selecting file:", e)
        return None


class WebCrawler:
    def __init__(self, urls, operation, max_links, headless=False):
        self.sniffer = None
        self.urls = urls  # This is now a list of URLs
        self.max_links = max_links
        self.visited = set()
        self.total_links = 0
        self.queue = Queue()  # Use a FIFO Queue for BFS
        self.download_dir = os.path.abspath("downloads_for_project")  # Ensure absolute path
        self.crawled_links = set()
        self.network_condition = "normal"
        self.operation = operation
        self.success = True

        chrome_options = Options()

        if headless:
            chrome_options.add_argument("--headless")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--mute-audio")

        # Set up Chrome options for automatic file download
        prefs = {
            "download.default_directory": self.download_dir,  # Set absolute download directory
            "download.prompt_for_download": False,  # Disable download prompt
            "download.directory_upgrade": True,
            "safebrowsing.enabled": True,  # Disable Safe Browsing to prevent interference
            "profile.default_content_settings.popups": 0,
        }
        chrome_options.add_experimental_option("prefs", prefs)
        chrome_options.add_argument(
            "user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")

        capabilities = DesiredCapabilities.CHROME
        capabilities['goog:loggingPrefs'] = {'performance': 'ALL', 'browser': 'ALL'}
        chrome_options.set_capability("goog:loggingPrefs", {'performance': 'ALL'})

        # Ensure the download directory exists
        os.makedirs(self.download_dir, exist_ok=True)

        self.driver = webdriver.Chrome(service=ChromeService(),
                                       options=chrome_options)
        self.driver.maximize_window()

    #''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
    def configure_selenium(self):
        # Set up Chrome options for automatic file download
        chrome_options = Options()
        prefs = {
            "download.default_directory": self.download_dir,  # Set download directory
            "download.prompt_for_download": False,  # Disable download prompt
            "download.directory_upgrade": True,
            "safebrowsing.enabled": True,  # Enable safe browsing
            "profile.default_content_settings.popups": 0,
        }
        chrome_options.add_experimental_option("prefs", prefs)
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")

    #'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''

    def save_browser_log(self, logfile):
        print("Retrieving performance logs...")
        logs = self.driver.get_log('performance')  # Retrieves performance logs
        if not logs:
            print("No logs to save.")
        else:
            with open(logfile, 'w', encoding='utf-8') as file:
                for entry in logs:
                    file.write(f"{entry['message']}\n")
            print(f"Logs saved to {logfile}.")

    def fetch_content(self, url):
        try:
            self.driver.get(url)
            time.sleep(3)
            #self.play_videos(url)
            return self.driver.page_source
        except Exception as e:
            print(f"Failed to fetch {url}: {e}")
            return None

    def play_videos(self, url):
        try:
            #   self.play_cnn_video()
            parsed_url = urlparse(url)
            if "youtube.com" in parsed_url.netloc:
                self.play_youtube_video()
            else:
                self.play_generic_video(url)
        except Exception as e:
            print(f"Failed to play video on {url}: {e}")

    def play_youtube_video(self):
        try:
            play_button = WebDriverWait(self.driver, 20).until(
                EC.element_to_be_clickable((By.CSS_SELECTOR, 'button.ytp-large-play-button'))
            )
            play_button.click()
            time.sleep(5)
            self.success = True
        except Exception as e:
            self.success = False
            print(f"Failed to play YouTube video: {e}")

    def check_element_presence(self, dynamic_xpath):
        # Check if the element is present in the DOM
        elements = self.driver.find_elements(By.XPATH, dynamic_xpath)
        print(f"Elements found: {len(elements)}")
        for i, element in enumerate(elements):
            print(f"Element {i} - ID: {element.get_attribute('id')}")
        return len(elements) > 0

    def play_generic_video(self, url):
        if "cnn.com" in url:
            try:
                # Load the URL
                self.driver.get(url)

                # Wait for the page to load completely
                WebDriverWait(self.driver, 10).until(
                    EC.presence_of_element_located((By.TAG_NAME, "body"))
                )

                # Define a more specific XPath based on the class observed in the screenshot
                specific_xpath = '//button[contains(@class, "pui_center-controls_big-play-toggle")]'

                # Wait for the element to be present and clickable
                element = WebDriverWait(self.driver, 25).until(
                    EC.element_to_be_clickable((By.XPATH, specific_xpath))
                )

                # Click the element
                element.click()
                print("Element found and clicked using the specific XPath.")
                self.success = True

            except TimeoutException:
                print("The specified element was not found within the given time frame.")
                self.success = False


            except Exception as e:
                print(f"An error occurred: {e}")

        if "bbc.com" in url:
            try:
                # Load the BBC video page
                self.driver.get(url)

                # Wait for the page to load completely
                WebDriverWait(self.driver, 10).until(
                    EC.presence_of_element_located((By.TAG_NAME, "body"))
                )

                # Define the XPath based on the data-testid attribute observed
                video_xpath = '//button[@data-testid="custom-cta"]'

                # Wait for the element to be present and clickable
                element = WebDriverWait(self.driver, 25).until(
                    EC.element_to_be_clickable((By.XPATH, video_xpath))
                )

                # Click the video play button
                element.click()
                print("BBC video play button found and clicked.")
                self.success = True
            except TimeoutException:
                print("The specified element was not found within the given time frame.")
                self.success = False

            except Exception as e:
                print(f"An error occurred: {e}")

        if "techcrunch.com" in url:
            try:

                # Allow the page to load
                time.sleep(5)  # Adjust as necessary for your connection speed

                # Locate the embedded YouTube video iframe
                iframe = self.driver.find_element(By.XPATH, "//iframe[contains(@src, 'youtube.com')]")

                # Switch to the iframe context

                self.driver.switch_to.frame(iframe)

                # Locate the play button within the iframe and click it
                play_button = self.driver.find_element(By.CSS_SELECTOR, "button.ytp-large-play-button")
                play_button.click()
                print("video clicked")

            except TimeoutException:
                print("The specified element was not found within the given time frame.")
                self.success = False

            except Exception as e:
                print(f"An error occurred: {e}")

        if "israelhayom.co.il" in url:
            try:
                # Load the video page
                self.driver.get(url)

                # Wait for the page to load completely
                WebDriverWait(self.driver, 10).until(
                    EC.presence_of_element_located((By.TAG_NAME, "body"))
                )

                # Define the XPath based on the button class observed in the screenshot
                play_button_xpath = '//button[contains(@class, "vjs-big-play-button")]'

                # Wait for the element to be present and clickable
                element = WebDriverWait(self.driver, 25).until(
                    EC.element_to_be_clickable((By.XPATH, play_button_xpath))
                )

                # Click the play button
                element.click()
                print("Video.js play button found and clicked.")
                self.success = True

            except TimeoutException:
                print("The specified element was not found within the given time frame.")
                self.success = False
            except Exception as e:
                print(f"An error occurred: {e}")

    def handle_iframes(self):
        try:
            iframe_elements = self.driver.find_elements(By.TAG_NAME, 'iframe')
            for iframe in iframe_elements:
                self.driver.switch_to.frame(iframe)
                video_elements = self.driver.find_elements(By.XPATH, '//*[@id="movie_player"]/div[4]/button')
                for video in video_elements:
                    self.attempt_to_play_video(video)
                self.driver.switch_to.default_content()
        except Exception as e:
            print(f"Error handling iframes: {e}")

    def attempt_to_play_video(self, video):
        try:
            if video.get_attribute('paused') == 'true':
                self.driver.execute_script("arguments[0].play();", video)
                print("Playing video via JavaScript execution.")
                time.sleep(5)  # Wait for some video to play
        except Exception as e:
            print(f"Error while trying to play video: {e}")

    def extract_links(self, html, base_url):
        soup = BeautifulSoup(html, 'html.parser')
        links = set()
        for anchor in soup.find_all('a', href=True):
            href = anchor['href']
            full_url = urljoin(base_url, href)
            if self.is_valid_url(full_url):
                links.add(full_url)
        return links

    def is_valid_url(self, url):
        parsed = urlparse(url)
        return bool(parsed.netloc) and bool(parsed.scheme)

    def categorize_url(self, url):
        parsed_url = urlparse(url)
        netloc = parsed_url.netloc.lower()
        path = parsed_url.path.lower()

        print(f"Categorizing URL: {url}")

        if (any(video_keyword in netloc for video_keyword in
                ['youtube', 'vimeo', 'dailymotion', 'netflix', 'hulu', 'cnn', 'bbc', 'video', 'videos', 'israelhayom'
                 ])
                and operation == 'video'):
            category = "video"
            attribution = "VOD"
        elif 'zoom.us' in netloc or 'zoom.com' in netloc:
            category = "messaging"
            attribution = "real-time"
        elif 'slack.com' in netloc or 'teams.microsoft.com' in netloc or 'skype.com' in netloc or 'whatsapp.com' in netloc or 'telegram.org' in netloc:
            category = "messaging"
            attribution = "chat"
        elif 'webrtc.org' in netloc:
            category = "messaging"
            attribution = "real-time"
        elif 'file.io' in netloc or "Ufile.io" in netloc or "GoFile.io" in netloc or "Guru99.com" in netloc:
            category = "upload"
            attribution = "file-upload"
        elif any(path.endswith(ext) for ext in
                 ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.csv', '.zip', '.tar', '.gz', '.rar', '.exe']):
            category = "file"
            attribution = "file download"
        elif self.operation == "download":
            category = "file"
            attribution = "file download"
        else:
            category = "other"
            attribution = "browsing"

        print(f"URL categorized as Category: {category}, Attribution: {attribution}")
        return category, attribution

    def download_file(self, url, retries=1):
        filename = urlparse(url).path.split('/')[-1]
        local_filename = os.path.join(self.download_dir, filename)
        logfile = os.path.join(self.download_dir, f'download_log_{filename.replace(".", "_")}.txt')

        print(f"Downloading file from: {url}")
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })

        for attempt in range(retries):
            try:
                with session.get(url, stream=True, allow_redirects=True) as r:
                    r.raise_for_status()
                    total_size = int(r.headers.get('Content-Length', 0))
                    downloaded_size = 0
                    with open(local_filename, 'wb') as f:
                        for chunk in r.iter_content(chunk_size=8192):
                            if chunk:
                                f.write(chunk)
                                downloaded_size += len(chunk)

                    # Log after each attempt, regardless of outcome
                    self.save_browser_log(logfile)

                    if downloaded_size == total_size:
                        print(f"Successfully downloaded file: {local_filename}")
                        break
                    else:
                        print(f"Download incomplete: {downloaded_size}/{total_size} bytes downloaded.")
                        if attempt < retries - 1:
                            print(f"Retrying download... (Attempt {attempt + 1}/{retries})")
            except requests.exceptions.RequestException as e:
                print(f"Failed to download {url}: {e}")
                if attempt < retries - 1:
                    print(f"Retrying download... (Attempt {attempt + 1}/{retries})")

            # Log after each attempt, including after the last one, regardless of its success
            self.save_browser_log(logfile)

    def apply_random_network_conditions(self):
        conditions = [
            "normal",
            "delay --time 200ms",
            "drop --rate 10%",
            "throttle --rate 1Mbps",
            "duplicate --rate 5%",
            "corrupt --rate 5%"
        ]
        chosen_condition = random.choice(conditions)
        self.network_condition = chosen_condition
        if chosen_condition == "normal":
            print("Applying normal network conditions.")
            subprocess.call([r"clumsy.exe", "-stop"])
        else:
            print(f"Applying network condition: {chosen_condition}")
            subprocess.call([r"clumsy.exe", chosen_condition])

    def close(self):
        if self.driver:
            print("Closing the WebDriver.")
            self.driver.quit()

    def organize_pcap(self, pcap_file, url, timestamp):
        try:
            metadata = self.extract_pcap_metadata(pcap_file)
        except Exception as e:
            print(f"Failed to extract metadata from {pcap_file}: {e}")
            metadata = {"network_conditions": self.network_condition}

        application_name = self.extract_application_name(url)
        category, attribution = self.categorize_url(url)
        network_conditions = metadata.get("network_conditions", self.network_condition)
        date = timestamp.split('_')[0]

        # Define new folder structure based on application name
        vod_folder = os.path.join("Data", attribution)
        application_folder = os.path.join(vod_folder, application_name)
        network_conditions_folder = os.path.join(application_folder, network_conditions)
        date_folder = os.path.join(network_conditions_folder, date)

        # Create directories if they don't exist
        try:
            for folder in [vod_folder, application_folder, network_conditions_folder, date_folder]:
                os.makedirs(folder, exist_ok=True)
        except Exception as e:
            print(f"Failed to create directories for {date_folder}: {e}")
            return

        print(f"Organizing pcap file: {pcap_file} into {date_folder}")

        # Move the pcap file
        destination_pcap_file = os.path.join(date_folder, os.path.basename(pcap_file))
        try:
            shutil.move(pcap_file, destination_pcap_file)
            print(f"Moved {pcap_file} to {destination_pcap_file}")
        except Exception as e:
            print(f"Failed to move pcap file {pcap_file} to {date_folder}: {e}")
            return

        # Save the metadata to a text file with the same name as the pcap file
        metadata_file = destination_pcap_file.replace(".pcap", ".txt")
        try:
            with open(metadata_file, "w") as f:
                f.write(f"URL: {url}\n")
                f.write(f"Application: {application_name}\n")
                f.write(f"Category: {category}\n")
                f.write(f"Attribution: {attribution}\n")
                f.write(f"Date: {date}\n")
                for key, value in metadata.items():
                    f.write(f"{key}: {value}\n")
            print(f"Saved metadata to {metadata_file}")
        except Exception as e:
            print(f"Failed to save metadata file for {pcap_file}: {e}")

        # Save browser log in the same directory as the pcap file
        # log_file = destination_pcap_file.replace(".pcap", "_browser_log.txt")
        # try:
        #     self.save_browser_log(log_file)
        #     print(f"Logs saved to {log_file}.")
        # except Exception as e:
        #     print(f"Failed to save browser logs to {log_file}: {e}")

    def extract_application_name(self, url):
        # Parse the URL to get components
        parsed_url = urlparse(url)
        # Extract the domain name (netloc) and split it by dots
        domain_parts = parsed_url.netloc.split('.')
        # Check if it's a common SLD+TLD format; adjust indexing based on your needs
        if len(domain_parts) > 2:
            # Exclude subdomains if present (common for sites like 'www')
            return '.'.join(domain_parts[-2:])
        elif len(domain_parts) == 2:
            # Directly use the domain if it's just a second-level and top-level domain
            return '.'.join(domain_parts)
        else:
            # Fallback if the URL is somehow unusual or malformed
            return "Unknown"

    def extract_pcap_metadata(self, pcap_file):
        cap = pyshark.FileCapture(pcap_file, only_summaries=True)
        return {"network_conditions": self.network_condition}

    def wait_for_download_completion(self, download_dir, expected_filename=None, timeout=60):
        """
        Monitors the download directory to detect when downloads are complete.
        If an expected filename is provided, it looks specifically for that file.
        Otherwise, it waits until no temporary download files are detected.

        :param download_dir: Directory where files are being downloaded.
        :param expected_filename: The expected filename of the completed download, if known.
        :param timeout: Maximum time to wait in seconds (default is 60 seconds).
        :return: True if the file is found or downloads complete within the timeout, False otherwise.
        """
        start_time = time.time()
        temp_extensions = ['.crdownload', '.part', '.tmp']  # Common temporary download extensions

        print(f"Monitoring {download_dir} for completion...")

        while time.time() - start_time < timeout:
            # List all current files in the download directory
            current_files = os.listdir(download_dir)

            # Check if the expected file is found, if specified
            if expected_filename:
                expected_file_path = os.path.join(download_dir, expected_filename)
                if os.path.exists(expected_file_path):
                    print(f"Detected completed file: {expected_filename}")
                    return True

            # Check for temporary files to detect ongoing downloads
            downloading = any(file.endswith(tuple(temp_extensions)) for file in current_files)

            if not downloading:
                # If no temporary files are found, consider the download complete
                print("No active temporary files detected. Download appears complete.")
                return True

            # Wait briefly before checking again
            time.sleep(1)

        # Final check after timeout to see if the expected file has appeared
        if expected_filename and os.path.exists(os.path.join(download_dir, expected_filename)):
            print(f"Final check: {expected_filename} is present.")
            return True

        print("Download completion check timed out.")
        return False

    def download_files(self, content, base_url):
        # Use BeautifulSoup for more reliable HTML parsing
        soup = BeautifulSoup(content, 'html.parser')

        # Extract all anchor tags with href attributes
        links = soup.find_all('a', href=True)

        for link in links:
            # Get the href attribute value
            file_url = link['href']

            # Clean and validate the URL
            file_url = urljoin(base_url, file_url)  # Ensure the URL is absolute
            parsed_url = urlparse(file_url)

            # Check if the URL is valid and points to a downloadable file type
            if not parsed_url.scheme or not parsed_url.netloc or not file_url.lower().endswith(
                    ('.zip', '.pdf', '.exe', '.tar.gz', '.rar', '.7z', '.docx', '.xlsx', '.jpg', '.png', '.mp3', '.mp4',
                     '.csv', '.ico', '.json')):
                print(f"Skipping invalid or non-downloadable URL: {file_url}")
                continue

            print(f"Attempting to download file from URL: {file_url}")

            try:
                # Close the browser if it is already open
                if self.driver:
                    self.close_browser()

                # Reinitialize the browser before each download attempt
                self.__init__(self.urls, self.operation, self.max_links)  # This re-applies the correct settings

                # Apply network conditions and start capturing traffic
                unique_identifier = f"{int(time.time())}"
                timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
                pcap_file = f"download_traffic_{unique_identifier}_{timestamp}.pcap"

                self.apply_random_network_conditions()
                self.start_capture(unique_identifier)

                # Navigate to the file URL using the fresh WebDriver session
                self.driver.get(file_url)

                # Wait for the download to start (adjust this as necessary)
                WebDriverWait(self.driver, 10).until(
                    EC.presence_of_element_located((By.TAG_NAME, 'body'))
                )

                # Wait until the file appears in the download directory
                self.wait_for_download_completion(self.download_dir, timeout=60)

                print(f"Downloaded {file_url} to {self.download_dir}")

            except Exception as e:
                print(f"Failed to download {file_url} using Selenium: {e}")

            finally:
                # Stop the capture regardless of download success or failure
                print("Stopping traffic capture.")
                captured_packets = self.stop_capture()

                # Only save the captured packets, log, and organize metadata if the download was successful
                if captured_packets:
                    wrpcap(pcap_file, captured_packets)
                    print(f"Traffic for {file_url} download recorded in {pcap_file}")
                    self.organize_pcap(pcap_file, file_url, timestamp)  # Ensure PCAP file is organized properly

                # Save browser log
                log_file = f"download_log_{unique_identifier}.txt"
                self.save_browser_log(log_file)
                print(f"Logs saved to {log_file}.")

                # Close the browser after download attempt
                self.close_browser()

            # Verify download completion and log
            print("Files in download directory:", os.listdir(self.download_dir))

    def download_and_capture(self, url, retries=5):
        filename = urlparse(url).path.split('/')[-1]
        local_filename = os.path.join(self.download_dir, filename)
        print(f"Starting traffic capture for download: {url}")
        unique_identifier = f"{int(time.time())}_download"

        # Start the sniffer before initiating the download
        print("Starting sniffer...")
        sniffer = AsyncSniffer()
        sniffer.start()

        # Download the file
        try:
            session = requests.Session()
            session.headers.update({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            })

            for attempt in range(retries):
                try:
                    with session.get(url, stream=True, allow_redirects=True) as r:
                        r.raise_for_status()
                        total_size = int(r.headers.get('Content-Length', 0))
                        downloaded_size = 0
                        with open(local_filename, 'wb') as f:
                            for chunk in r.iter_content(chunk_size=8192):
                                if chunk:
                                    f.write(chunk)
                                    downloaded_size += len(chunk)
                        if downloaded_size == total_size:
                            print(f"Successfully downloaded file: {local_filename}")
                            break
                        else:
                            print(f"Download incomplete: {downloaded_size}/{total_size} bytes downloaded.")
                            if attempt < retries - 1:
                                print(f"Retrying download... (Attempt {attempt + 1}/{retries})")
                except requests.exceptions.RequestException as e:
                    print(f"Failed to download {url}: {e}")
                    if attempt < retries - 1:
                        print(f"Retrying download... (Attempt {attempt + 1}/{retries})")

        finally:
            # Stop the sniffer after download is completed
            print("Stopping sniffer...")
            sniffer.stop()
            captured_packets = sniffer.results

            # Save the captured packets to a .pcap file
            timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
            pcap_file = f"download_traffic_{timestamp}_{unique_identifier}.pcap"
            if captured_packets:
                wrpcap(pcap_file, captured_packets)
                print(f"Traffic for {url} download recorded in {pcap_file}")
                self.organize_pcap(pcap_file, url, timestamp)
            else:
                print("No packets captured for download")

    def click_and_download(self, url):
        print(f"Click and download from: {url}")
        try:
            self.driver.get(url)
            time.sleep(3)  # wait for the page and elements to load

            # Prepare for packet capture
            unique_identifier = f"{int(time.time())}_click"
            timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
            pcap_file = f"download_traffic_{timestamp}_{unique_identifier}.pcap"

            # Start the sniffer
            print("Starting packet capture")
            self.start_capture(unique_identifier)

            # Click the download buttons
            download_buttons = self.driver.find_elements(By.XPATH, "//*[contains(text(), 'Download')]")
            for button in download_buttons:
                button.click()
                time.sleep(5)  # Short sleep to ensure downloads start

            # Wait for downloads to complete
            print("Waiting for downloads to complete")
            download_dir = self.download_dir
            self.wait_for_download_completion(download_dir)
            print(f"Downloaded from: {url}")

            # Stop the sniffer and get results
            captured_packets = self.stop_capture()

            # Save the captured packets if any were captured
            if captured_packets:
                wrpcap(pcap_file, captured_packets)
                print(f"Traffic for {url} download recorded in {pcap_file}")
                self.organize_pcap(pcap_file, url, timestamp)
            else:
                print("No packets captured for download")

        except Exception as e:
            print(f"Failed to interact and download from {url}: {e}")
            # Stop the sniffer and get results
            captured_packets = self.stop_capture()

            # Save the captured packets if any were captured
            if captured_packets:
                wrpcap(pcap_file, captured_packets)
                print(f"Traffic for {url} download recorded in {pcap_file}")
            else:
                print("No packets captured for download")

    def download_embedded_content(self):
        try:
            # Check for iframe
            iframe_elements = self.driver.find_elements(By.TAG_NAME, 'iframe')
            for iframe in iframe_elements:
                src = iframe.get_attribute('src')
                if self.is_valid_url(src) and self.is_downloadable(src):
                    self.download_and_capture(src)
                    return

            # Check for embed tag
            embed_elements = self.driver.find_elements(By.TAG_NAME, 'embed')
            for embed in embed_elements:
                src = embed.get_attribute('src')
                if self.is_valid_url(src) and self.is_downloadable(src):
                    self.download_and_capture(src)
                    return

            # Check for object tag
            object_elements = self.driver.find_elements(By.TAG_NAME, 'object')
            for obj in object_elements:
                data = obj.get_attribute('data')
                if self.is_valid_url(data) and self.is_downloadable(data):
                    self.download_and_capture(data)
                    return

            print("No downloadable embedded content found.")
        except Exception as e:
            print(f"Failed to download embedded content: {e}")

    def start_crawling(self, operation):
        try:
            if operation.lower() == 'download':
                self.crawl_for_downloads()
            elif operation.lower() == 'browse':
                self.crawl_for_browsing()
            elif operation.lower() == 'video':
                self.crawl_for_video()
            elif operation.lower() == 'upload':
                self.crawl_for_upload()
            elif operation.lower() == 'meeting':
                self.crawl_for_meeting()


            else:
                print("Invalid operation specified. Please choose from 'downloading', 'browsing', or 'video'.")
        finally:
            self.close()

    def wait_for_downloads(self):
        # Poll the download directory to check for the completion of downloads
        while True:
            if not any([filename.endswith(".crdownload") for filename in os.listdir(self.download_dir)]):
                break
            print("Waiting for downloads to complete...")
            time.sleep(2)  # Wait a bit before checking again

    def crawl_for_downloads(self):
        for url in self.urls:
            self.queue.put(url)

        while not self.queue.empty() and self.total_links < self.max_links:
            url = self.queue.get()
            if url in self.visited:
                self.queue.task_done()
                continue

            print(f"Crawling: {url}")
            self.visited.add(url)
            self.total_links += 1

            content = self.fetch_content(url)
            if content:
                # timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
                # log_file = f"browser_log_{self.total_links}_{timestamp}.txt"
                # self.save_browser_log(log_file)
                # print(f"Browser log for {url} saved in {log_file}")

                # Extract links from the page and download files individually
                links = self.extract_links(content, url)
                self.download_files(content, url)  # This method now handles traffic capture and browser reopening

                for link in links:
                    if link not in self.visited:
                        self.queue.put(link)
                self.crawled_links.update(links)

            self.queue.task_done()
            self.close_browser()  # Ensure the browser is closed after processing the URL

    def close_browser(self):
        if self.driver:
            self.driver.quit()
            self.driver = None
            print("Browser closed.")

    def open_browser(self):
        # Initialize the browser (e.g., Chrome) with GUI
        options = webdriver.ChromeOptions()
        self.driver = webdriver.Chrome(service=ChromeService(), options=options)
        print("Browser opened with GUI.")

    def crawl_for_browsing(self):
        for url in self.urls:
            self.queue.put(url)

        while not self.queue.empty() and self.total_links < self.max_links:
            url = self.queue.get()
            if url in self.visited:
                self.queue.task_done()
                continue

            print(f"Crawling: {url}")
            self.visited.add(url)
            self.total_links += 1

            print(f"Applying network conditions and starting traffic capture for {url}")
            self.apply_random_network_conditions()

            unique_identifier = f"{self.total_links}_{int(time.time())}"

            # Close the browser if it's already open to ensure a fresh session
            self.close_browser()

            # Reopen the browser for a fresh session before starting capture
            self.open_browser()

            # Start capturing traffic
            self.start_capture(unique_identifier)
            content = self.fetch_content(url)
            if content:
                timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
                pcap_file = f"web_traffic_{self.total_links}_{timestamp}_{unique_identifier}.pcap"

                # Save browser log
                log_file = f"browser_log_{self.total_links}_{timestamp}_{unique_identifier}.txt"
                self.save_browser_log(log_file)
                print(f"Browser log for {url} saved in {log_file}")

                # Ensure correct directory is used for logs
                directory = os.path.dirname(pcap_file)
                log_file = os.path.join(directory, log_file)

                # Wait to capture enough traffic, adjust the sleep time as needed
                time.sleep(30)

                # Stop capturing traffic and save it
                captured_packets = self.stop_capture()
                if captured_packets:
                    wrpcap(pcap_file, captured_packets)
                    print(f"Traffic for {url} recorded in {pcap_file}")
                    self.organize_pcap(pcap_file, url, timestamp)
                else:
                    print(f"No packets captured for {url}")

                # Extract and queue additional links
                links = self.extract_links(content, url)
                for link in links:
                    if link not in self.visited:
                        self.queue.put(link)
                self.crawled_links.update(links)

            # Mark the URL as processed
            self.queue.task_done()

            # Close the browser after processing the URL to ensure clean state for the next capture
            self.close_browser()

    def crawl_for_video(self):
        for url in self.urls:
            self.queue.put(url)

        while not self.queue.empty() and self.total_links < self.max_links:
            url = self.queue.get()
            if url in self.visited:
                self.queue.task_done()
                continue

            print(f"Crawling: {url}")
            self.visited.add(url)
            self.total_links += 1

            print(f"Applying network conditions for {url}")
            self.apply_random_network_conditions()

            self.close_browser()  # Close any previous browser session
            self.open_browser()  # Open a new browser session

            unique_identifier = f"{self.total_links}_{int(time.time())}"
            print(f"Starting traffic capture for {url}")
            self.start_capture(unique_identifier)

            content = self.fetch_content(url)

            if content:
                self.play_videos(url)
                if self.success is True:
                    print("Waiting 60 seconds to capture traffic while the video plays...")
                    time.sleep(60)  # Delay to allow video streaming data capture

            captured_packets = self.stop_capture()

            if captured_packets and getattr(self, 'success', True):
                timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
                pcap_file = f"web_traffic_{self.total_links}_{timestamp}_{unique_identifier}.pcap"

                log_file = f"browser_log_{self.total_links}_{timestamp}_{unique_identifier}.txt"
                self.save_browser_log(log_file)
                print(f"Browser log for {url} saved in {log_file}")

                wrpcap(pcap_file, captured_packets)
                print(f"Traffic for {url} recorded in {pcap_file}")
                self.organize_pcap(pcap_file, url, timestamp)
            else:
                print(f"No packets captured for {url} or success is {getattr(self, 'success', False)}")
                self.success = True

            # Extract and prioritize video-related links
            links = self.extract_links(content, url)
            video_links = self.filter_video_links(links)

            for link in video_links:
                if link not in self.visited:
                    self.queue.put(link)
            self.crawled_links.update(video_links)

            self.queue.task_done()

    def filter_video_links(self, links):
        """Filters links to prioritize those likely containing video content."""
        video_keywords = ['video', 'watch', 'play', 'stream', 'media', 'movie', 'clip', 'tv']
        video_links = []

        for link in links:
            # Check if any keyword is in the URL path or query
            if any(keyword in link.lower() for keyword in video_keywords):
                video_links.append(link)

        return video_links

    def start_capture(self, unique_identifier):
        # Get the IP address of the current machine
        local_ip = get_if_addr(conf.iface)

        # Set up a BPF filter to capture traffic only to and from the local machine
        filter_str = f"host {local_ip}"

        # Initialize and start the sniffer with the specified filter
        self.sniffer = AsyncSniffer(filter=filter_str)
        self.sniffer.start()
        print(f"Started sniffing traffic for {unique_identifier} on IP {local_ip}")

    def stop_capture(self):
        # Implement stopping of traffic capture and return captured packets
        self.sniffer.stop()
        captured_packets = self.sniffer.results  # Access the results property
        return captured_packets

    def upload_file_selenium(self, url,
                             directory=r'C:\Users\ליאור\PycharmProjects\MeetingCrawler\downloads_for_project'):
        """
        Automates the file upload process on a webpage using Selenium, selecting a random file from the specified directory.

        :param url: The URL of the webpage with the file upload form.
        :param directory: The path to the directory containing files to upload.
        """
        file_path = get_random_file(directory)
        if not file_path:
            print("No file selected. Exiting.")
            return

        # options = Options()
        # Uncomment to see browser actions
        # options.add_argument("--headless")  # Remove this if you want to see the browser actions

        driver = webdriver.Chrome()

        try:
            driver.get(url)
            print("Page loaded. Waiting for file input element...")
            WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.CSS_SELECTOR, "input[type='file']")))

            file_input = driver.find_element(By.CSS_SELECTOR, "input[type='file']")
            file_input.send_keys(file_path)
            print(f"File '{os.path.basename(file_path)}' selected for upload.")

            # Determine the site based on URL or page elements
            current_url = driver.current_url

            # Logic for the first site
            if "file.io" in current_url and "ufile.io" not in current_url and "gofile.io" not in current_url:
                print("Detected first site. Waiting for confirmation text...")
                WebDriverWait(driver, 120).until(
                    EC.text_to_be_present_in_element((By.TAG_NAME, "body"), "Your file is ready to share!")
                )
                print(f"File '{os.path.basename(file_path)}' uploaded successfully on the first site!")
                self.success = True

                # Logic for the second site - looking for specific text
            elif "ufile.io" in current_url:
                print("Detected second site. Waiting for confirmation text...")
                WebDriverWait(driver, 120).until(
                    EC.text_to_be_present_in_element((By.TAG_NAME, "body"),
                                                     "Done! Your file is available via the following URL:")
                )
                print(f"File '{os.path.basename(file_path)}' uploaded successfully on the second site!")
                self.success = True
            elif "gofile.io" in current_url:
                print("Detected second site. Waiting for confirmation text...")
                WebDriverWait(driver, 120).until(
                    EC.text_to_be_present_in_element((By.TAG_NAME, "body"),
                                                     "Your files have been successfully uploaded")
                )
                print(f"File '{os.path.basename(file_path)}' uploaded successfully on the third site!")
                self.success = True
            else:
                print("Site not recognized. Please check the URL or element selectors.")


        except Exception as e:
            print("An error occurred during the upload process:", e)
            self.success = False

        finally:
            driver.quit()

    def crawl_for_upload(self):
        # Repeat the entire process `max_links` times
        for _ in range(self.max_links):
            # Add all URLs to the queue each time we start the loop
            for url in self.urls:
                self.queue.put(url)

                # Initialize the WebDriver (e.g., Chrome) once
                #driver = webdriver.Chrome()

                # Process each URL until the queue is empty

                print(f"Crawling: {url}")
                self.visited.add(url)

                print(f"Applying network conditions and starting traffic capture for {url}")
                self.apply_random_network_conditions()

                unique_identifier = f"{self.total_links}_{int(time.time())}"

                # Start capturing traffic
                self.start_capture(unique_identifier)
                # Handle file upload using the dedicated method, passing the existing driver
                self.upload_file_selenium(url)

                if self.success is True:

                    timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
                    pcap_file = f"web_traffic_{self.total_links}_{timestamp}_{unique_identifier}.pcap"

                    # Save browser log
                    log_file = f"browser_log_{self.total_links}_{timestamp}_{unique_identifier}.txt"
                    self.save_browser_log(log_file)
                    print(f"Browser log for {url} saved in {log_file}")

                    # Ensure correct directory is used for logs
                    directory = os.path.dirname(pcap_file)
                    log_file = os.path.join(directory, log_file)

                    # Stop capturing traffic and save it
                    captured_packets = self.stop_capture()
                    if captured_packets:
                        wrpcap(pcap_file, captured_packets)
                        print(f"Traffic for {url} recorded in {pcap_file}")
                        self.organize_pcap(pcap_file, url, timestamp)
                    else:
                        print(f"No packets captured for {url}")

                # Mark the URL as processed
                self.queue.task_done()
                self.success = True
            # Close the browser after processing all URLs

    def authenticate_google(self):
        creds = None
        if os.path.exists('token.json'):
            creds = Credentials.from_authorized_user_file('token.json', SCOPES)
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                flow = InstalledAppFlow.from_client_secrets_file(
                    'credentials.json', SCOPES)
                creds = flow.run_local_server(port=60411)  # Dynamic port handling
            with open('token.json', 'w') as token:
                token.write(creds.to_json())
        return creds

    def create_google_meet_event(self):
        creds = self.authenticate_google()
        service = build('calendar', 'v3', credentials=creds)

        event = {
            'summary': 'Google Meet Event',
            'description': 'Meeting with team',
            'start': {
                'dateTime': (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat(),
                'timeZone': 'UTC',
            },
            'end': {
                'dateTime': (datetime.now(timezone.utc) + timedelta(minutes=40)).isoformat(),
                'timeZone': 'UTC',
            },
            'conferenceData': {
                'createRequest': {
                    'conferenceSolutionKey': {
                        'type': 'hangoutsMeet'
                    },
                    'requestId': 'some-random-string'
                }
            },
            'attendees': [
                {'email': 'example@example.com'}
            ],
        }

        event = service.events().insert(calendarId='primary', body=event, conferenceDataVersion=1).execute()
        print('Google Meet link:', event['hangoutLink'])
        return event['hangoutLink']

    def send_chat_message(self, driver, message="hello world"):
        try:
            # Step 1: Find and click the chat icon/button to open the chat window
            WebDriverWait(self.driver, 20).until(
                EC.element_to_be_clickable((By.XPATH, '//*[contains(@aria-label, "Chat with everyone")]'))
            ).click()

            # Step 2: Locate the chat input box
            chat_input = WebDriverWait(self.driver, 20).until(
                EC.visibility_of_element_located((By.XPATH, '//textarea[@aria-label="Send a message"]'))
            )

            # Step 3: Type the message and send it
            for i in range(10):
                chat_input.send_keys(message)
                chat_input.send_keys(Keys.ENTER)  # Press Enter to send the message
                print(f"Message '{message}' sent successfully.")
                time.sleep(3)
        except Exception as e:
            print(f"Failed to send the chat message: {e}")

    def turn_off_camera(self, driver):
        try:
            # Wait for the "Turn off camera" button to become clickable and click it
            WebDriverWait(self.driver, 20).until(
                EC.element_to_be_clickable((By.XPATH, '//*[contains(@aria-label, "Turn off camera")]'))
            ).click()
            print("Camera turned off successfully.")
        except Exception as e:
            print(f"Failed to turn off the camera: {e}")

    def turn_off_mic(self, driver):
        try:
            # Wait for the "Turn off camera" button to become clickable and click it
            WebDriverWait(self.driver, 20).until(
                EC.element_to_be_clickable((By.XPATH, '//*[contains(@aria-label, "Turn off microphone")]'))
            ).click()
            print("Camera turned off successfully.")
        except Exception as e:
            print(f"Failed to turn off the camera: {e}")

    def join_google_meet_with_profile(self, meet_link):
        chrome_options = Options()
        chrome_options.add_argument("--user-data-dir=C:/Users/ליאור/AppData/Local/Google/Chrome/User Data")
        chrome_options.add_argument("--profile-directory=Default")  # Use your default Chrome profile

        self.driver = webdriver.Chrome(service=Service('chromedriver.exe'), options=chrome_options)

        # Open the Google Meet link
        self.driver.get(meet_link)

        # Wait for the page to load and try to join the meeting
        try:
            time.sleep(5)  # Adjust as necessary for your network speed
            # Use the updated find_element method with By.XPATH
            join_button = self.driver.find_element(By.XPATH, '//*[contains(text(),"Join now")]')
            join_button.click()
            print("Successfully joined the meeting.")
        except Exception as e:
            print(f"Failed to join: {e}")

        self.turn_off_camera(self.driver)
        self.turn_off_mic(self.driver)
        self.send_chat_message(self.driver)
        # Keep the browser open for a while (adjust as needed)
        time.sleep(60)
        self.driver.quit()

    def crawl_for_meeting(self):
        for _ in range(self.max_links):
            meet_link = self.create_google_meet_event()

            self.queue.put(meet_link)
            self.visited.add(meet_link)

            print(f"Crawling: {meet_link}")
            print(f"Applying network conditions and starting traffic capture for {meet_link}")

            self.apply_random_network_conditions()

            unique_identifier = f"{self.total_links}_{int(time.time())}"

            self.start_capture(unique_identifier)

            self.join_google_meet_with_profile(meet_link)

            if self.success is True:
                timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
                pcap_file = f"web_traffic_{self.total_links}_{timestamp}_{unique_identifier}.pcap"

                log_file = f"browser_log_{self.total_links}_{timestamp}_{unique_identifier}.txt"
                #self.save_browser_log(log_file)
                print(f"Browser log for {meet_link} saved in {log_file}")

                directory = os.path.dirname(pcap_file)
                log_file = os.path.join(directory, log_file)

                captured_packets = self.stop_capture()
                if captured_packets:
                    wrpcap(pcap_file, captured_packets)
                    print(f"Traffic for {meet_link} recorded in {pcap_file}")
                    self.organize_pcap(pcap_file, meet_link, timestamp)
                else:
                    print(f"No packets captured for {meet_link}")

            self.queue.task_done()
            self.success = True


if __name__ == "__main__":
    # Load URLs from a JSON file
    with open('videos.json', 'r') as file:
        urls = json.load(file)

    operation = 'meeting'

    max_links = 1  #Adjust this number as needed

    crawler = WebCrawler(urls, operation, max_links, headless=False)
    crawler.start_crawling(operation)
