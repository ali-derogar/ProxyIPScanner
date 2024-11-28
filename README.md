# This project is solely for testing and increasing skills, research, and practice, and any misuse of it is the responsibility of the user.

# BaseUrlBlacklist Checker
* Base Url can be any web-site url

This project provides a Python implementation for interacting with the BaseUrl website to check if an IP address is listed on blacklists. The implementation managing proxies, changing IP addresses, and generating CSV reports.

## Clone

   ```sh
   git clone https://github.com/ali-derogar/ProxyIPScanner.git
   ```

 **Install the required dependencies:**
   ```sh
   pip install -r requirements.txt
   ```
   
## Features

- **IP Address Blacklist Check:** Checks if an IP address is listed on BaseUrl.
- **Proxy Management:** Supports the use of proxies to make requests.
- **CSV Reporting:** Generates a CSV report with the analysis results.

## Installation


## Usage

1. **BaseUrlBlacklist:**
   - This class interacts with the BaseUrl website.

   ```python
      test = BaseUrlBlacklist(proxies=None, link_change_ip=None)
   ```

    - proxies: (dict) Proxy settings for the session.
    - link_change_ip: (str) API link for changing IP address.
---

1. **Methods:**

   - change_ip(): Changes the IP address using the specified API link.
   - get_initial_cookies(): Retrieves initial cookies from the BaseUrlBlacklist website.
   - check_ip(): Checks if the IP address is listed on BaseUrlBlacklist.
   - get_csv_report(count=10): Generates a CSV report of IP analysis results.
   - test_proxy_result(count=10): Tests the proxy results by checking IP status.
---
1. **Fast Usage:**
   ```python

    proxies_link = "http://---:---.*.*.*.*:*"
    link_change_ip = "http://****.example.com:*/api/changeIP?apiToken=*"
    proxies = {"http": proxies_link, "https": proxies_link}

    test = BaseUrlBlacklist(proxies=proxies, link_change_ip=link_change_ip)
    test()

    # response -> {} or {"listed_count": ?, "not_listed_count": ?}
   ```

2. **Generate CSV Report:**
   ```python

    proxies_link = "http://---:---.*.*.*.*:*"
    link_change_ip = "http://****.example.com:*/api/changeIP?apiToken=*"
    proxies = {"http": proxies_link, "https": proxies_link}

    make temp.json file => like this >>>
    {
       "BG": {
           "http://---:---.*.*.*.*:*": "http://****.example.com:*/api/changeIP?apiToken=*"
       },
       "CO": {
           "http://---:---.*.*.*.*:*": "http://****.example.com:*/api/changeIP?apiToken=*"
       },
       "US": {
           "http://---:---.*.*.*.*:*": "http://****.example.com:*/api/changeIP?apiToken=*"
       },
       "GH": {
           "http://---:---.*.*.*.*:*": "http://****.example.com:*/api/changeIP?apiToken=*"
       },
       "NL": {
           "http://---:---.*.*.*.*:*": "http://****.example.com:*/api/changeIP?apiToken=*"
       },
    }
    after than run this func => 
    from ip_validator.get_csv_result import make_csv
    make_csv()
    # response -> csv file
   ```


3. **Dependencies:**
   ```text
   - requests
   - pycryptodome
   - celery
   ```

4. **Logger Type:**
   ```text
   - celery
   ```


# Blacklistmaster Checker

This project provides a Python implementation for interacting with the Blacklistmaster website to check if an IP address is listed on blacklists. The implementation includes managing proxies, changing IP addresses, and generating CSV reports.

## Features

- **IP Address Blacklist Check:** Checks if an IP address is listed on Blacklistmaster.
- **Proxy Management:** Supports the use of proxies to make requests.
- **AES Decryption:** Decrypts data using AES for secure communication.
- **CSV Reporting:** Generates a CSV report with the analysis results.

## Usage

1. **Blacklistmaster:**
   - This class interacts with the Blacklistmaster website.

   ```python
      test = Blacklistmaster(proxies=None, link_change_ip=None, use_change_ip=None, default_ip=None)
   ```

    - proxies: (dict) Proxy settings for the session.
    - link_change_ip: (str) API link for changing IP address.
    - use_change_ip: (bool) Flag to use IP change.
    - default_ip: (str) Default IP address.
---

2. **Methods:**

   - change_ip(): Changes the IP address using the specified API link.
   - get_google_captcha(data_sitekey=None, page_url=None): Retrieves token.
   - get_initial_cookies(): Retrieves initial cookies from the Blacklistmaster website.
   - get_credential(count=0): Retrieves hidden input name and value from the form.
   - accept_cookie_consent(): Simulates acceptance of the cookie consent.
   - get_token(g_recaptcha=None, count=0): Retrieves the token required for checking the IP address.
   - check_ip(): Checks if the IP address is listed on Blacklistmaster.
   - get_csv_report(count=10): Generates a CSV report of IP analysis results.
   - test_proxy_result(count=10): Tests the proxy results by checking IP status.
---
3. **Fast Usage:**
   ```python

    proxies_link = "http://---:---.*.*.*.*:*"
    link_change_ip = "http://****.example.com:*/api/changeIP?apiToken=*"
    proxies = {"http": proxies_link, "https": proxies_link}

    test = Blacklistmaster(proxies=proxies, link_change_ip=link_change_ip, use_change_ip=True)
    test()

    # response -> {} or {"listed_count": ?, "not_listed_count": ?}
   ```

4. **Generate CSV Report:**
   ```python

    proxies_link = "http://---:---.*.*.*.*:*"
    link_change_ip = "http://****.example.com:*/api/changeIP?apiToken=*"
    proxies = {"http": proxies_link, "https": proxies_link}

    test = Blacklistmaster(proxies=proxies, link_change_ip=link_change_ip, use_change_ip=True)
    test.get_csv_report(count=1)
    # response -> csv file
   ```

4. **Check Action With Logger:**
   ```python

    proxies_link = "http://---:---.*.*.*.*:*"
    link_change_ip = "http://****.example.com:*/api/changeIP?apiToken=*"
    proxies = {"http": proxies_link, "https": proxies_link}

    test = Blacklistmaster(proxies=proxies, link_change_ip=link_change_ip, use_change_ip=True)
    test.test_proxy_result(count=1)
   ```


5. **Dependencies:**
   ```text
   - requests
   - pycryptodome
   - celery
   ```

6. **Logger Type:**
   ```text
   - celery
   ```
