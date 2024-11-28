import csv
from random import choice
import re
from time import sleep, time
from traceback import format_exc
from requests import Session
import requests
from Crypto.Cipher import AES
from datetime import datetime, timedelta
from requests.exceptions import Timeout , ReadTimeout , ConnectTimeout
from ip_validator.exceptions import ProxyException
from celery.utils.log import get_task_logger
logger = get_task_logger(__name__)


def get_user_agent():
    
    user_agent = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Safari/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; AS; rv:11.0) like Gecko",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36",
        "Mozilla/5.0 (Linux; Android 10; SM-G970F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Mobile Safari/537.36"
    ]
    return choice(user_agent)

def to_numbers(hex_string):
    """
    Converts a hexadecimal string to a list of integers (byte values).

    Args:
        hex_string (str): A string containing hexadecimal digits.

    Returns:
        list: A list of integers representing byte values.
    """
    logger.debug(f"Converting hex string to numbers: {hex_string}")
    return [int(hex_string[i:i+2], 16) for i in range(0, len(hex_string), 2)]

def to_hex(byte_array):
    """
    Converts a list of byte values (integers) to a hexadecimal string.

    Args:
        byte_array (list): A list of integers representing byte values.

    Returns:
        str: A hexadecimal string.
    """
    hex_str = ''.join(['{:02x}'.format(b) for b in byte_array])
    logger.debug(f"Converted byte array to hex string: {hex_str}")
    return hex_str


def decrypt_aes(ciphertext, mode, key, iv):
    """
    Decrypts a given ciphertext using AES with the specified mode, key, and IV.

    Args:
        ciphertext (bytes): The encrypted data to be decrypted.
        mode (int): The mode of operation for AES.
        key (bytes): The secret key used for decryption.
        iv (bytes): The initialization vector used for decryption.

    Returns:
        bytes: The decrypted data.
    """
    logger.debug(f"Decrypting data with AES, mode={mode}, key={key}, iv={iv}")
    cipher = AES.new(key, mode, iv)
    decrypted = cipher.decrypt(ciphertext)
    return decrypted

def get_BPC(hex_pattern, response):
    """
    Extracts hex strings from the response, decrypts them, and returns the decrypted value.

    Args:
        hex_pattern (Pattern): A compiled regular expression pattern to find hex strings.
        response (Response): The HTTP response containing the hex strings.

    Returns:
        str: The decrypted hexadecimal string.
    """
    hex_strings = hex_pattern.findall(response.text)
    logger.debug(f"Extracted hex strings: {hex_strings}")

    if len(hex_strings) == 3:
        hex_a, hex_b, hex_c = hex_strings
        logger.debug(f"hex_a: {hex_a}, hex_b: {hex_b}, hex_c: {hex_c}")
    else:
        logger.error("Error: Could not find exactly three hex strings")
        return None

    a = to_numbers(hex_a)
    b = to_numbers(hex_b)
    c = to_numbers(hex_c)

    decrypted = decrypt_aes(bytes(c), AES.MODE_CBC, bytes(a), bytes(b))

    decrypted_hex = to_hex(decrypted)
    logger.debug(f"Decrypted hex string: {decrypted_hex}")
    return decrypted_hex


class Blacklistmaster:
    """
    A class to interact with the Blacklistmaster website to check if an IP address is listed.

    Attributes:
        ip (str): The IP address to check.
        proxies (dict): Proxy settings for the session.
    """

    name_pattern = r'name="([^"]*)"'
    value_pattern = r'value="([^"]*)"'
    hex_pattern = re.compile(r'toNumbers\("([a-f0-9]+)"\)')

    def __init__(self, proxies:dict=None , link_change_ip:str=None , use_change_ip:bool=None , default_ip:str=None) -> None:
        """
        Initializes the Blacklistmaster class with IP address and proxy settings.

        Args:
            ip (str): The IP address to check.
            proxies (dict): Proxy settings for the session.
        """
        logger.info("Initializing Blacklistmaster class")
        self.retry_count = 0
        self.normal = True
        self.link_change_ip = link_change_ip
        self.session = Session()
        self.session.proxies = proxies
        if default_ip and not use_change_ip:
            self.ip = default_ip 
        else:
            self.change_ip()
        self.session.headers.update({
            'User-Agent': get_user_agent(),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Alt-Used': 'www.blacklistmaster.com',
            'Origin': 'https://www.blacklistmaster.com',
            'DNT': '1',
            'Sec-GPC': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Priority': 'u=1'
            }
        )
        logger.debug(f"Initialized Blacklistmaster with IP: {self.ip}, Proxies: {proxies}")

    
    def change_ip(self):
        """
        Changes the IP address by calling a specified API link. Retries the process up to three times if an error occurs.
    
        Returns:
            str: The new IP address if changed successfully.
            bool: False if the IP change is not successful.
    
        Raises:
            ProxyException: If the IP change fails after retries.
        """
        for _ in range(3):
            logger.info(f"[change_ip] executed, link ==> {self.link_change_ip}")
            try:
                response = requests.get(self.link_change_ip)
                logger.info(f"[change_ip] response ==> {response.text} ")
                response = response.json()
                break
            except:
                logger.error(f"[change_ip] Error ==> {format_exc()}")
                sleep(10)

        try:
            response
        except:
            raise ProxyException("Can't change ip!")
        try:
            if response.get("IP"):
                self.ip = response.get("IP")
            elif response.get("success"):
                return response.get("success")
            elif response.get("left"):
                time_s = int(response["left"]) + 3
                sleep(time_s)
                return self.change_ip()
            else:
                return False
        except KeyError:
            logger.error(f"INVALID RESPONSE change_ip: {response}")
            sleep(10)
            return self.change_ip()


    def get_google_captcha(self,data_sitekey=None,page_url=None):
        """
        This part of the code changed :)
        """
        print("Loading and solving the reCAPTCHA based on the provided data_sitekey and page_url.")
        print("data_sitekey:", data_sitekey)
        print("page_url:", page_url)
        return input("Please enter the reCAPTCHA token: ")

    def get_initial_cookies(self) -> None:
        """
        Retrieves initial cookies from the Blacklistmaster website.
        """
        logger.info("Getting initial cookies from Blacklistmaster")
        response = self.session.get('https://www.blacklistmaster.com/',timeout=15 , allow_redirects=False)
        logger.debug(f"Session cookies after initial request: {self.session.cookies.get_dict()}")
        logger.debug(f"Session headers: {self.session.headers}")

        for i in range(1, 4):
            if "Checking your browser" in response.text:
                decrypted_hex = get_BPC(hex_pattern=self.hex_pattern, response=response)
                logger.debug(f"BPC={decrypted_hex};")
                self.session.cookies.update({"BPC": decrypted_hex})

                logger.info(f"[get_initial_cookies] => Attempt {i}")
                params = {
                    'attempt': str(i),
                }
                response = self.session.get('https://www.blacklistmaster.com/', params=params,timeout=15, allow_redirects=False)
                logger.debug(f"Initial cookies response status code: {response.status_code}")

                
            elif "https://www.google.com/recaptcha/api.js" in response.text:
                data_sitekey = response.text.split("data-sitekey=")[1].split('></div></td></tr>')[0].split('"')[1]
                response_text = response.text.split('<input type="hidden" name=')[1].split("/>")[0]
                response_text = '<input type="hidden" name=' + response_text + "/>"

                name_match = re.search(self.name_pattern, response_text)
                value_match = re.search(self.value_pattern, response_text)

                if name_match and value_match:
                    self.name_key = name_match.group(1)
                    self.value_key = value_match.group(1)

                    logger.info(f"Name: {self.name_key}")
                    logger.info(f"Value: {self.value_key}")
                else:
                    logger.error("Name and value not found in the response")
                
                self.normal = False

                for _ in range(10):
                    try:
                        token_recaptcha = self.get_google_captcha(
                            data_sitekey=data_sitekey,
                            page_url="https://www.blacklistmaster.com/"
                        )
                        return token_recaptcha
                    except Exception as e:
                        logger.info(f"Exception during captcha handling: {e}")
            else:

                response_text = response.text.split('<input type="hidden" name=')[1].split("/>")[0]
                response_text = '<input type="hidden" name=' + response_text + "/>"

                name_match = re.search(self.name_pattern, response_text)
                value_match = re.search(self.value_pattern, response_text)

                if name_match and value_match:
                    self.name_key = name_match.group(1)
                    self.value_key = value_match.group(1)

                    logger.info(f"Name: {self.name_key}")
                    logger.info(f"Value: {self.value_key}")
                else:
                    logger.info("Name and value not found in the response")
                    raise ValueError("Name and value not found in the response")
                
                self.normal = False
                break


    def get_credential(self, count=0) -> None:
        """
        Retrieves hidden input name and value from the Blacklistmaster form.
        
        Args:
            count (int): The number of retry attempts made. Defaults to 0.
        """
        try:
            logger.info("Getting credentials from Blacklistmaster")
            params = {
                't': self.ip,
            }
            response = self.session.post('https://www.blacklistmaster.com/check', params=params ,allow_redirects=False,timeout=15)
            if response.status_code != 200:
                raise requests.exceptions.SSLError("SSLError")
            for i in range(1, 4):
                if "Checking your browser" in response.text:
                    logger.info(f"[get_credential] = > {i}")
                    params = {
                        't': self.ip,
                        'attempt': str(i),
                    }
                    response = self.session.post('https://www.blacklistmaster.com/check', params=params,allow_redirects=False,timeout=15)
                    if response.status_code != 200:
                        raise requests.exceptions.SSLError("SSLError")
                else:
                    break

            response_text = response.text.split('<input type="hidden" name=')[1].split("/>")[0]
            response_text = '<input type="hidden" name=' + response_text + "/>"

            name_match = re.search(self.name_pattern, response_text)
            value_match = re.search(self.value_pattern, response_text)

            if name_match and value_match:
                self.name_key = name_match.group(1)
                self.value_key = value_match.group(1)

                logger.info(f"Name: {self.name_key}")
                logger.info(f"Value: {self.value_key}")
            else:
                logger.info("Name and value not found in the response")
                raise ValueError("Name and value not found in the response")
        
        except (Timeout , ReadTimeout , ConnectTimeout) as e:
            raise e
        except requests.exceptions.SSLError as e:
            raise requests.exceptions.SSLError("SSLError")
        except:
            if count < 2:
                return self.get_credential(count=count+1)

    def accept_cookie_consent(self):
        """
        Simulates the acceptance of the cookie consent.
        """
        expire = datetime.now() + timedelta(days=90)
        expire_str = expire.strftime("%a, %d-%b-%Y %H:%M:%S GMT")
        cookie = f"here; expires={expire_str}; path=/"

        # Manually add the cookie to the session headers
        if 'Cookie' in self.session.headers:
            self.session.headers['cookieCompliancyAccepted'] += cookie
        else:
            self.session.headers.update({'cookieCompliancyAccepted': cookie})

        # Debugging: logger.info the current cookies in the session headers
        logger.info(f"Updated session headers: {self.session.headers}")
        logger.info(f"Session cookies: {self.session.cookies.get_dict()}")


    def get_token(self, g_recaptcha=None, count=0) -> None:
        """
        Retrieves the token required for checking the IP address listing on Blacklistmaster.

        Args:
            g_recaptcha (str, optional): The reCAPTCHA token if required. Defaults to None.
            count (int): The number of retry attempts made. Defaults to 0.

        Returns:
            str: The token if retrieved successfully.
            bool: False if the token retrieval fails after retries.
        """
        try:
            headers = {
                'Accept-Language': 'en-US,en;q=0.5',
                'Content-Type': 'application/x-www-form-urlencoded',
                'Referer': 'https://www.blacklistmaster.com/',
            }
            self.session.headers.update(headers)
            logger.info("Getting token from Blacklistmaster")
            data = {
                'ip': self.ip,
                'list_type': 'IP',
                self.value_key: self.name_key,
            }
            if g_recaptcha:
                data.update({'g-recaptcha-response': g_recaptcha})
            logger.info(self.session.cookies.get_dict())
            response = self.session.post('https://www.blacklistmaster.com/check', data=data,allow_redirects=False,timeout=15)
            if response.status_code != 200:
                raise requests.exceptions.SSLError("SSLError")
            
            if "Captcha verification error" in response.text:
                logger.info("Captcha verification error")

                if count < 3:
                    return self.get_token(g_recaptcha=g_recaptcha, count=count + 1)
                else:
                    logger.info("Failed to get token after multiple attempts.")
                    return False

            self.token = response.text.split("token=")[1].split(")")[0].split('"')[0]
            logger.info(f"Token retrieved: {self.token}")
            return self.token
        
        except (Timeout , ReadTimeout , ConnectTimeout) as e:
            raise e
        except requests.exceptions.SSLError as e:
            raise requests.exceptions.SSLError("SSLError")
        except Exception as e:
            if "list index out of range" in str(e):
                logger.info(f"Exception during token retrieval: ip is blocked ...")
                return False
            logger.info(f"Exception during token retrieval: {e}")
            if count < 3:
                return self.get_token(g_recaptcha=g_recaptcha, count=count + 1)
            else:
                logger.info("Failed to get token after multiple attempts.")
                return False
    

    def check_ip(self) -> dict:
        """
        Checks if the IP address is listed on Blacklistmaster.

        Returns:
            dict: Counts of listed and not listed statuses.
        """
        logger.info("Checking IP on Blacklistmaster")
        params = {
            'token': self.token,
        }

        self.session.headers.update(
            {
                'X-Requested-With': 'XMLHttpRequest',
                'Alt-Used': 'www.blacklistmaster.com',
                'Referer': f'https://www.blacklistmaster.com/check?t={self.ip}',
            }
        )

        response = self.session.get('https://www.blacklistmaster.com/blacklistcheck/result.php', params=params,timeout=15, allow_redirects=False)

        listed_pattern = r'<span style="color:red">([A-Za-z]+)</span></td></tr>'
        not_listed_pattern = r'<span style="color:green">([A-Za-z ]+)</span></td></tr>'

        listed_matches = re.findall(listed_pattern, response.text)
        not_listed_matches = re.findall(not_listed_pattern, response.text)

        listed_count = len(listed_matches)
        not_listed_count = len(not_listed_matches)

        logger.info(f"Listed count: {listed_count}")
        logger.info(f"Not listed count: {not_listed_count}")

        return {"listed_count": listed_count, "not_listed_count": not_listed_count}

    def __call__(self) -> dict:
        """
        Executes the process of getting initial cookies, retrieving credentials, getting the token, and checking the IP.

        Returns:
            dict: Counts of listed and not listed statuses.
            bool: False if the process fails.
    """
        try:
            logger.info("Starting Blacklistmaster process")
            g_recaptcha = self.get_initial_cookies()

            if self.normal:
                response = self.get_credential()
                response = self.get_token()
            else:
                response = self.get_token(g_recaptcha)

            if response:
                response = self.check_ip()
                logger.info(f"Blacklistmaster process result: {response}")
                return response
            else:
                logger.error("Blacklistmaster process failed.")
                return {"listed_count": 0, "not_listed_count": 0}
        
        except (Timeout , ReadTimeout , ConnectTimeout) as e:
            logger.error(f"timeout ip_validator : {e}")
            return {"listed_count": 0, "not_listed_count": 0}

        except requests.exceptions.SSLError as e:
            logger.info(f"this ip is blocked in ip_validator {self.ip} retry_count : {self.retry_count}")
            self.retry_count += 1
            if self.retry_count < 10 and self.link_change_ip:
                return self()
            else:
                return {"listed_count": 0, "not_listed_count": 0}

        except Exception as e:
            logger.error(f"Exception during Blacklistmaster process: {format_exc()}")
            return {"listed_count": 0, "not_listed_count": 0}
        
    def get_csv_report(self,count=10):
        """
        Generates a CSV report of IP analysis results using the Blacklistmaster service.
    
        Args:
            proxies_link (str): The proxy link to use for the requests.
            link_change_ip (str): The link to use for changing the IP address.
        """
        logger.info("Generating CSV report for IP analysis results")
        csv_file_path = f"report_proxy_{int(time())}.csv"
        with open(csv_file_path, "w", newline="") as csvfile:
            fieldnames = ["ip", "Analysis Date","Blacklistmaster"]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for _ in range(count):

                try:
                    self.change_ip()
                    result_Blacklistmaster = self.__call__()
                    logger.info(result_Blacklistmaster)
                    logger.info(f"[test_proxy_result] => {result_Blacklistmaster}")
                    result_for_write = [self.ip , datetime.now() ,result_Blacklistmaster]
                    writer.writerow(dict(zip(fieldnames, result_for_write)))
                except Exception as e:
                    logger.error(f"Exception during proxy test: {format_exc()}")
                    continue

    def test_proxy_result(self,count=10):
        """
        Tests the proxy results by checking IP status using the Blacklistmaster service.
    
        Args:
            proxies_link (str): The proxy link to use for the requests.
            link_change_ip (str): The link to use for changing the IP address.
        """
        for _ in range(count):

            try:
                self.change_ip()    
                result_Blacklistmaster = self.__call__()
                logger.info(self.ip)
                logger.info(f"[test_proxy_result] => {result_Blacklistmaster}")

            except Exception as e:
                logger.error(f"Exception during proxy test: {format_exc()}")
                continue

            self.use_change_ip = False

# ------------------------------------------------------------------------------------------------------------------

if __name__ == "__main__":

    for _ in range(1):

        proxies_link = "http://---:---.*.*.*.*:*"
        link_change_ip = "http://****.example.com:*/api/changeIP?apiToken=*"
        try:
            proxies = {"http": proxies_link, "https": proxies_link}
            BB = Blacklistmaster(proxies=proxies,link_change_ip=link_change_ip,use_change_ip=True)
            result_Blacklistmaster = BB.get_csv_report(count=1)
            logger.info(result_Blacklistmaster)

        except Exception as e:
            logger.error(f"Exception in main execution loop: {format_exc()}")
            continue