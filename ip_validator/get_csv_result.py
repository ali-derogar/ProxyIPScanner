import asyncio
from json import loads
from ip_validator.url_ip_validator import BaseUrlBlacklist
import csv

async def check_proxy(country, proxies_link, link_change_ip):
    success_count = 0
    for _ in range(20): 
        proxies = {"http": proxies_link, "https": proxies_link}
        BB = BaseUrlBlacklist(proxies=proxies, link_change_ip=link_change_ip)
        result_Blacklistmaster = await asyncio.to_thread(BB)
        if result_Blacklistmaster["not_listed_count"] > 0:
            success_count += 1
    return {'country': country, 'success_count': success_count, 'proxies_link': proxies_link, 'link_change_ip': link_change_ip}

async def make_csv():
    proxy_file = loads(open("temp.json").read())
    tasks = []

    for country, proxies in proxy_file.items():
        for proxies_link, link_change_ip in proxies.items():
            tasks.append(check_proxy(country, proxies_link, link_change_ip))

    results = await asyncio.gather(*tasks)

    with open("result.csv", "w", newline='') as csvfile:
        fieldnames = ['country', 'success_count', 'proxies_link', 'link_change_ip']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)
        
    print("finished")

if __name__ == "__main__":
    asyncio.run(make_csv())
