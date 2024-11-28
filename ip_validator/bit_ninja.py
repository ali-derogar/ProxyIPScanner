from requests import Session



class Bitninja:

    def __init__(self ,ip , proxies_link ,email = "example@gmail.com" , password = ">*****;RTTvD") -> None:
        proxies = {"http": proxies_link, "https": proxies_link}
        self.session = Session()
        self.session.proxies = proxies
        self.email = email
        self.password = password
        self.ip = ip

    def login(self ,):

        url = 'https://api.bitninja.io/v2/authentication/login/credentials'
        headers = {
            'accept': 'application/json',
            'Content-Type': 'application/json'
        }
        data = {
            "email": self.email,
            "password": self.password
        }

        response = self.session.post(url, headers=headers, json=data)

        print(response.status_code)
        self.accessToken = response.json()["accessToken"]
        self.refreshToken = response.json()["refreshToken"]
    
    def check_ip(self):

        url = 'https://api.bitninja.io/v2/firewall/ip/check'
        headers = {
            'accept': 'application/json',
            'Authorization': f'Bearer {self.accessToken}'
        }
        params = {
            'ip': self.ip
        }
        response = self.session.get(url, headers=headers, params=params)
        print(response.status_code)
        return response.json()["message"]["listedOn"][0]["details"]

    def update_credential(self):

        headers = {
            'accept': 'application/json',
            'Content-Type': 'application/json',
        }

        json_data = {
            'refreshToken': self.refreshToken,
        }

        response = self.session.post('https://api.bitninja.io/v2/authentication/login/refreshToken', headers=headers, json=json_data)

        self.accessToken = response.json()["accessToken"]
        self.refreshToken = response.json()["refreshToken"]
        print(response.status_code)

    def __call__(self):
        self.login()
        response = self.check_ip()
        return response
    

