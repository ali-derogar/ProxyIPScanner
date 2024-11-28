from random import choice
from time import sleep
from traceback import format_exc
from requests import Session
import requests
from requests.exceptions import Timeout, ReadTimeout, ConnectTimeout
from ip_validator.exceptions import ProxyException
from config import BaseUrl
from celery.utils.log import get_task_logger
# from .logs import Logger

logger = get_task_logger(__name__)

user_agents = [
    'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:129.0) Gecko/20100101 Firefox/129.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:115.0) Gecko/20100101 Firefox/115.0',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:110.0) Gecko/20100101 Firefox/110.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:108.0) Gecko/20100101 Firefox/108.0',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.110 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.5672.126 Safari/537.36',
    'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:100.0) Gecko/20100101 Firefox/100.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0'
]

class BaseUrlBlacklist:

    def __init__(self, proxies: dict = None, link_change_ip: str = None) -> None:
        """
        Initializes the BaseUrlBlacklist class with proxy settings and optional link to change IP.

        Args:
            proxies (dict): Proxy settings for the session. Defaults to None.
            link_change_ip (str): API link to change the IP address. Defaults to None.
        """
        logger.info("Initializing BaseUrlBlacklist class")
        self.retry_count = 0
        self.link_change_ip = link_change_ip
        self.session = Session()
        self.session.proxies = proxies
        self.ip = None
        
        self.session.headers.update({
            'User-Agent': choice(user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'DNT': '1',
            'Sec-GPC': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Priority': 'u=0, i',
        })
        logger.debug(f"Initialized BaseUrlBlacklist with IP: {self.ip}, Proxies: {proxies}")

    def change_ip(self):
        """
        Attempts to change the IP address by calling a specified API link. Retries the process up to three times if an error occurs.
    
        Returns:
            str: The new IP address if changed successfully.
            bool: False if the IP change is not successful.
    
        Raises:
            ProxyException: If the IP change fails after retries.
        """
        for _ in range(3):
            logger.info(f"[change_ip] Executed with link: {self.link_change_ip}")
            try:
                response = requests.get(self.link_change_ip)
                logger.info(f"[change_ip] Response: {response.text}")
                response = response.json()
                break
            except Exception as e:
                logger.error(f"[change_ip] Error: {format_exc()}")
                sleep(10)

        try:
            response
        except NameError:
            raise ProxyException("Failed to change IP after retries!")
        
        try:
            if response.get("IP"):
                self.ip = response.get("IP")
                logger.info(f"IP changed successfully to {self.ip}")
            elif response.get("success"):
                logger.info(f"IP change success: {response.get('success')}")
                return response.get("success")
            elif response.get("left"):
                time_s = int(response["left"]) + 3
                logger.info(f"Waiting {time_s} seconds before retrying IP change")
                sleep(time_s)
                return self.change_ip()
            else:
                logger.warning("IP change failed, returning False")
                return False
        except KeyError as e:
            logger.error(f"Invalid response during IP change: {response} - KeyError: {str(e)}")
            sleep(10)
            return self.change_ip()

    def get_initial_cookies(self) -> dict:
        """
        Retrieves initial cookies from the BaseUrl login page.

        Returns:
            dict: Counts of listed and not listed statuses if successful.
            None: If an SSL error occurs.

        Raises:
            Timeout: If the request times out.
            ReadTimeout: If the request read times out.
            ConnectTimeout: If the request connection times out.
            SSLError: If an SSL error occurs.
        """
        try:
            self.change_ip() if self.retry_count != 0 else ...
            logger.info("Retrieving initial cookies from BaseUrl login page")
            
            response = self.session.get(BaseUrl, timeout=30)
            if response.status_code != 200:
                logger.warning(f"Non-200 status code received: {response.status_code}")
                raise requests.exceptions.SSLError("Non-200 status code received")
            else:
                logger.info("Initial cookies retrieved successfully")
                return {"listed_count": 0, "not_listed_count": 100}
            
        except (Timeout, ReadTimeout, ConnectTimeout) as e:
            logger.debug(f"Timeout error while retrieving initial cookies: {e}")
            raise e
        except requests.exceptions.SSLError as e:
            logger.debug(f"SSL error while retrieving initial cookies: {e}")
            raise requests.exceptions.SSLError("SSL error occurred")

    def __call__(self) -> dict:
        """
        Executes the process of retrieving initial cookies and processing them.

        Returns:
            dict: Counts of listed and not listed statuses if successful.
            dict: Default counts if the process fails.
        """
        try:
            logger.info("Starting BaseUrlBlacklist process")
            response = self.get_initial_cookies()

            if response:
                logger.info(f"BaseUrlBlacklist process completed successfully: {response}")
                return response
            else:
                logger.error("BaseUrlBlacklist process failed, returning default counts")
                return {"listed_count": 0, "not_listed_count": 0}

        except (requests.exceptions.SSLError ,Timeout, ReadTimeout, ConnectTimeout) as e:
            logger.info(f"IP blocked during BaseUrlBlacklist process, IP: {self.ip}, Retry count: {self.retry_count}")
            self.retry_count += 1
            if self.retry_count < 10 and self.link_change_ip:
                logger.info("Retrying BaseUrlBlacklist process")
                return self()
            else:
                logger.error("Max retries reached, returning default counts")
                return {"listed_count": 0, "not_listed_count": 0}

        except Exception as e:
            logger.error(f"Unexpected error during BaseUrlBlacklist process: {format_exc()}")
            return {"listed_count": 0, "not_listed_count": 0}
