import scrapy
from scrapy import signals 
import requests



jsonDic = {}
url_prefix = "https://iotanalytics.unsw.edu.au/"
class MUDSpider(scrapy.Spider):
    name = 'MUDSpider'
    
    start_urls = ['https://iotanalytics.unsw.edu.au/mudprofiles']
    

    @classmethod
    def from_crawler(cls, crawler, *args, **kwargs):
        spider = super(MUDSpider, cls).from_crawler(crawler, *args, **kwargs)
        crawler.signals.connect(spider.spider_closed, signal=signals.spider_closed)
        crawler.signals.connect(spider.spider_opend, signal=signals.spider_opened)
        return spider

    def parse(self, response):
        url = response.url
        names = response.css("a[href*=mud]::text").extract()
        json_urls = response.css("a[href*=mud]")
        for i in range(1,len(names)-1):
            name = names[i].strip().replace(' ','')
            json_url = json_urls[i].css("a::attr(href)").extract_first()
            jsonDic[name] = json_url
            

    def spider_closed(self, spider, reason):
        for name, url in jsonDic.items():
            with open('MUD_File/'+name+'.json','w') as outfile:
                outfile.write(requests.get(url_prefix + url, verify=False).text)

    def spider_opend(self, spider):
        pass
