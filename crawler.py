import os
import shutil
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

from scapy.arch import get_if_addr
from scapy.config import conf
from selenium import webdriver
from selenium.webdriver.chrome.service import Service as ChromeService
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
import time
from queue import LifoQueue
from scapy.all import sniff, AsyncSniffer, wrpcap
from datetime import datetime
import pyshark
import random
import subprocess
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
from urllib.parse import urlparse


class WebCrawler:
    def __init__(self, base_url, operation, max_links, headless=False):
        self.base_url = base_url
        self.max_links = max_links
        self.visited = set()
        self.total_links = 0
        self.queue = LifoQueue()
        self.download_dir = os.path.join(os.getcwd(), "downloads")
        self.crawled_links = set()
        self.network_condition = "normal"
        self.operation = operation

        chrome_options = Options()
        if headless:
            chrome_options.add_argument("--headless")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--mute-audio")

        prefs = {
            "download.default_directory": self.download_dir,
            "download.prompt_for_download": False,
            "download.directory_upgrade": True,
            "safebrowsing.enabled": True
        }
        chrome_options.add_experimental_option("prefs", prefs)

        # Enable browser logging
        capabilities = DesiredCapabilities.CHROME
        capabilities['goog:loggingPrefs'] = {'performance': 'ALL', 'browser': 'ALL'}
        chrome_options.set_capability("goog:loggingPrefs", {'performance': 'ALL'})

        self.driver = webdriver.Chrome(service=ChromeService(ChromeDriverManager().install()), options=chrome_options)
        os.makedirs(self.download_dir, exist_ok=True)

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
            self.play_videos(url)
            return self.driver.page_source
        except Exception as e:
            print(f"Failed to fetch {url}: {e}")
            return None

    def play_videos(self, url):
        try:
            parsed_url = urlparse(url)
            if "youtube.com" in parsed_url.netloc:
                self.play_youtube_video()
            else:
                self.play_generic_video()
        except Exception as e:
            print(f"Failed to play video on {url}: {e}")

    def play_youtube_video(self):
        try:
            play_button = WebDriverWait(self.driver, 10).until(
                EC.element_to_be_clickable((By.CSS_SELECTOR, 'button.ytp-large-play-button'))
            )
            play_button.click()
            time.sleep(5)
        except Exception as e:
            print(f"Failed to play YouTube video: {e}")

    def play_generic_video(self):
        try:
            # handle iframes as video might be embedded in an iframe
            iframe_elements = self.driver.find_elements(By.TAG_NAME, 'iframe')
            for iframe in iframe_elements:
                self.driver.switch_to.frame(iframe)
                video_elements = self.driver.find_elements(By.TAG_NAME, 'video')
                for video in video_elements:
                    self.attempt_to_play_video(video)
                self.driver.switch_to.default_content()

            # handle any video elements outside of iframes
            video_elements = self.driver.find_elements(By.TAG_NAME, 'video')
            for video in video_elements:
                self.attempt_to_play_video(video)
        except Exception as e:
            print(f"Failed to play generic video: {e}")

    def attempt_to_play_video(self, video):
        try:
            if video.get_attribute('paused') == 'true':
                self.driver.execute_script("arguments[0].play();", video)
                time.sleep(5)
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

        if any(video_keyword in netloc for video_keyword in ['youtube', 'vimeo', 'dailymotion', 'netflix', 'hulu']):
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

    def sniff_traffic(self, timeout=30, identifier=""):
        captured_packets = []

        def packet_callback(packet):
            captured_packets.append(packet)

        print(f"Starting sniffing for {timeout} seconds with identifier {identifier}...")
        sniffer = AsyncSniffer(prn=packet_callback, store=0)
        sniffer.start()
        time.sleep(timeout)
        sniffer.stop()
        print(f"Sniffing complete. Captured {len(captured_packets)} packets.")
        return captured_packets

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

        # Extract the application name
        application_name = self.extract_application_name(url)

        category, attribution = self.categorize_url(url)
        network_conditions = metadata.get("network_conditions", self.network_condition)
        date = timestamp.split('_')[0]

        # Define folder structure based on application name
        vod_folder = os.path.join("Data", attribution)
        application_folder = os.path.join(vod_folder, application_name)
        # attribution_folder = os.path.join(application_folder, attribution)
        network_conditions_folder = os.path.join(application_folder, network_conditions)
        date_folder = os.path.join(network_conditions_folder, date)

        # Create directories if don't exist
        for folder in [vod_folder, application_folder, network_conditions_folder, date_folder]:
            os.makedirs(folder, exist_ok=True)

        print(f"Organizing pcap file: {pcap_file} into {date_folder}")

        # Move the pcap file
        destination_pcap_file = os.path.join(date_folder, os.path.basename(pcap_file))
        try:
            shutil.move(pcap_file, destination_pcap_file)
            print(f"Moved {pcap_file} to {date_folder}")
        except Exception as e:
            print(f"Failed to move pcap file {pcap_file} to {date_folder}: {e}")

        # Save the metadata to a text file
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

    def extract_application_name(self, url):
        # Parse the URL to get components
        parsed_url = urlparse(url)
        domain_parts = parsed_url.netloc.split('.')
        if len(domain_parts) > 2:
            return '.'.join(domain_parts[-2:])
        elif len(domain_parts) == 2:
            return '.'.join(domain_parts)
        else:
            return "Unknown"

    def extract_pcap_metadata(self, pcap_file):
        cap = pyshark.FileCapture(pcap_file, only_summaries=True)
        return {"network_conditions": self.network_condition}

    def download_files(self, html, base_url):
        soup = BeautifulSoup(html, 'html.parser')
        for anchor in soup.find_all('a', href=True):
            href = anchor['href']
            full_url = urljoin(base_url, href)
            if self.is_downloadable(full_url):
                self.download_and_capture(full_url)
            elif "download" in full_url.lower():
                self.click_and_download(full_url)
            else:
                self.download_embedded_content()

    def is_downloadable(self, url):
        downloadable_extensions = ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.csv', '.zip', '.tar', '.gz', '.rar',
                                   '.exe']
        return any(url.endswith(ext) for ext in downloadable_extensions)

    def download_and_capture(self, url, retries=5):
        local_filename = os.path.join(self.download_dir, url.split('/')[-1])
        print(f"Starting traffic capture for download: {url}")
        unique_identifier = f"{int(time.time())}_download"

        # Start the sniffer
        sniffer = AsyncSniffer()
        sniffer.start()

        # Download the file
        downloaded = self.download_file(url, retries)

        # Stop the sniffer
        sniffer.stop()
        captured_packets = sniffer.results

        print(f"Sniffing complete. Captured {len(captured_packets)} packets.")

        timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        pcap_file = f"download_traffic_{timestamp}_{unique_identifier}.pcap"
        if captured_packets:
            wrpcap(pcap_file, captured_packets)
            print(f"Traffic for {url} download recorded in {pcap_file}")
            self.organize_pcap(pcap_file, url, timestamp)

    def wait_for_download_completion(self, download_dir, timeout=300):
        start_time = time.time()
        while any(fname.endswith('.crdownload') for fname in os.listdir(download_dir)):
            if time.time() - start_time > timeout:
                raise TimeoutError("Download did not complete within the given timeout period")
            time.sleep(1)
        print("Download completed")

    def click_and_download(self, url):
        print(f"Click and download from: {url}")
        try:
            self.driver.get(url)
            time.sleep(3)

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
                time.sleep(5)

            print("Waiting for downloads to complete")
            download_dir = self.download_dir
            self.wait_for_download_completion(download_dir)
            print(f"Downloaded from: {url}")

            # Stop the sniffer
            captured_packets = self.stop_capture()

            # Save the captured packets
            if captured_packets:
                wrpcap(pcap_file, captured_packets)
                print(f"Traffic for {url} download recorded in {pcap_file}")
                self.organize_pcap(pcap_file, url, timestamp)
            else:
                print("No packets captured for download")

        except Exception as e:
            print(f"Failed to interact and download from {url}: {e}")
            # Stop the sniffer
            captured_packets = self.stop_capture()

            # Save the captured packets
            if captured_packets:
                wrpcap(pcap_file, captured_packets)
                print(f"Traffic for {url} download recorded in {pcap_file}")
            else:
                print("No packets captured for download")

        except Exception as e:
            print(f"Failed to interact and download from {url}: {e}")

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
            else:
                print("Invalid operation specified. Please choose from 'downloading', 'browsing', or 'video'.")
        finally:
            self.close()

    def crawl_for_downloads(self):
        self.queue.put(self.base_url)
        while not self.queue.empty() and self.total_links < self.max_links:
            url = self.queue.get()
            if url in self.visited:
                self.queue.task_done()
                continue

            print(f"Crawling: {url}")
            self.visited.add(url)
            self.total_links += 1

            unique_identifier = f"{self.total_links}_{int(time.time())}"
            content = self.fetch_content(url)
            if content:
                timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')

                # Save browser log
                log_file = f"browser_log_{self.total_links}_{timestamp}_{unique_identifier}.txt"
                self.save_browser_log(log_file)
                print(f"Browser log for {url} saved in {log_file}")

                links = self.extract_links(content, url)
                self.download_files(content, url)
                for link in links:
                    if link not in self.visited:
                        self.queue.put(link)
                self.crawled_links.update(links)

            self.queue.task_done()

    def crawl_for_browsing(self):
        self.queue.put(self.base_url)
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

            self.start_capture(unique_identifier)
            content = self.fetch_content(url)
            if content:
                timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
                pcap_file = f"web_traffic_{self.total_links}_{timestamp}_{unique_identifier}.pcap"

                # Save browser log
                log_file = f"browser_log_{self.total_links}_{timestamp}_{unique_identifier}.txt"
                self.save_browser_log(log_file)
                print(f"Browser log for {url} saved in {log_file}")

                time.sleep(30)
                captured_packets = self.stop_capture()
                if captured_packets:
                    wrpcap(pcap_file, captured_packets)
                    print(f"Traffic for {url} recorded in {pcap_file}")
                    self.organize_pcap(pcap_file, url, timestamp)
                else:
                    print(f"No packets captured for {url}")

                links = self.extract_links(content, url)
                for link in links:
                    if link not in self.visited:
                        self.queue.put(link)
                self.crawled_links.update(links)

            self.queue.task_done()

    def crawl_for_video(self):
        self.queue.put(self.base_url)
        while not self.queue.empty() and self.total_links < self.max_links:
            url = self.queue.get()
            if url in self.visited:
                self.queue.task_done()
                continue

            print(f"Crawling: {url}")
            self.visited.add(url)
            self.total_links += 1

            # Apply network conditions
            print(f"Applying network conditions for {url}")
            self.apply_random_network_conditions()

            # Start capturing traffic right before loading the URL
            unique_identifier = f"{self.total_links}_{int(time.time())}"
            print(f"Starting traffic capture for {url}")
            self.start_capture(unique_identifier)

            # Fetch content after starting the capture
            content = self.fetch_content(url)

            if content:
                # If content is successfully fetched, play videos if any
                self.play_videos(url)
                time.sleep(60)  # Delay for 60 seconds to allow video streaming data capture

            # Stop the capture
            captured_packets = self.stop_capture()

            if captured_packets:
                timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
                pcap_file = f"web_traffic_{self.total_links}_{timestamp}_{unique_identifier}.pcap"

                # Save browser log
                log_file = f"browser_log_{self.total_links}_{timestamp}_{unique_identifier}.txt"
                self.save_browser_log(log_file)
                print(f"Browser log for {url} saved in {log_file}")

                wrpcap(pcap_file, captured_packets)
                print(f"Traffic for {url} recorded in {pcap_file}")
                self.organize_pcap(pcap_file, url, timestamp)
            else:
                print("No packets captured for {url}")

            links = self.extract_links(content, url)
            for link in links:
                if link not in self.visited:
                    self.queue.put(link)
            self.crawled_links.update(links)

            self.queue.task_done()

    def start_capture(self, unique_identifier):
        # Get current IP address
        local_ip = get_if_addr(conf.iface)

        # Set up a BPF filter to capture traffic only to and from the local machine
        filter_str = f"host {local_ip}"

        # Initialize and start the sniffer with the specified filter
        self.sniffer = AsyncSniffer(filter=filter_str)
        self.sniffer.start()
        print(f"Started sniffing traffic for {unique_identifier} on IP {local_ip}")

    def stop_capture(self):
        self.sniffer.stop()
        captured_packets = self.sniffer.results
        return captured_packets


if __name__ == "__main__":
    # start_url = 'https://www.mozilla.org/en-US/firefox/new/'
    # operation = "download"

    # start_url = 'https://edition.cnn.com/'
    # operation = "browse"

    # start_url = 'https://www.youtube.com/watch?v=M5QY2_8704o&pp=ygULcHJvZ3JhbW1pbmc%3D'
    # operation = "video"

    start_url = 'https://www.dailymotion.com/video/x83icxp'
    operation = "video"

    # start_url = 'https://www.who.int/docs/default-source/coronaviruse/risk-comms-updates/update-28-covid-19-what-we-know.pdf'
    # make it search urls like above and then process of downloading (not in one run)?

    # start_url = 'https://www.google.com/search?q=Covid-19+Filetype%3Apdf&oq=Covid-19+Filetype%3Apdf&gs_lcrp=EgZjaHJvbWUyBggAEEUYOdIBBzkzNGowajeoAgiwAgE&sourceid=chrome&ie=UTF-8'
    # operation = "download"
    max_links = 1

    crawler = WebCrawler(start_url, operation, max_links, headless=False)
    crawler.start_crawling(operation)
