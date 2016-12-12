#-*- coding: utf-8 -*-
from bs4 import BeautifulSoup
import GlobalVar
import urllib2
import random
class redhat_analyze():
    global sys
    def __init__(self, url, name, sys_key):
        self.url = url
        self.sys_key = sys_key
        self.app = name

    def start_analyze(self):
        return self.__send_request2redhat()

    def __send_request2redhat(self):
        tries = 5
        req = urllib2.Request(self.url)
        req.add_header('User-Agent', random.choice(GlobalVar.useragents))
        while tries:
            try:
                return self.__redhat_page_analyze(urllib2.urlopen(req).read())
            except:
                tries -= 1
                continue
        print u'访问' + self.url + u'异常'

    def __redhat_search_cve_plan(self):
        return GlobalVar.search_cve_plan(self.url.split('/')[-1])

    def __redhat_refer_page_analyze(self, url, key):
        req = urllib2.Request(url)
        req.add_header('User-Agent', random.choice(GlobalVar.useragents))
        try:
            page = urllib2.urlopen(req).read()
        except urllib2.HTTPError, e:
            print e.code
        soup = BeautifulSoup(page, 'html.parser')
        res = soup.find_all('a', attrs={'name': 'Red Hat Enterprise Linux Server (v. ' + key[-1] + ')'}, limit=1)
        if len(res) == 0:
            res = soup.find_all('a', attrs={'name':'Red Hat Enterprise Linux (v. ' +  key[-1] + ' server)'}, limit=1)
        if res:
            arch = res[0].find_next('strong', string='x86_64:')
            ver = arch.find_next('td').get_text()
            if ver:
                value = ver.split('.')
                # 切割例如openssh-6.6.1p1-25.el7_2.x86_64.rpm后三个点的内容
                map(lambda x: value.pop(), [x for x in range(3)])
                return '.'.join(value)
        return ''

    def __redhat_page_analyze(self, page):
        print u'正在分析' + u' 系统:'+ self.sys_key + u' 应用:' + self.app + u' 漏洞公告:' + self.url
        soup = BeautifulSoup(page, 'html.parser')
        tables = soup.find_all('table',
                               attrs={'class': 'table feature-table', 'xmlns:xs': 'http://www.w3.org/2001/XMLSchema'})
        key = sys[self.sys_key][0]
        if tables:
            for table in tables:
                for child in table.descendants:
                    if child.find(key) >= 0:
                        if child.parent.next_sibling.next_sibling.get_text().find('RHSA') >= 0:
                            #print child.parent.next_sibling.next_sibling.a['href']
                            version = self.__redhat_refer_page_analyze(child.parent.next_sibling.next_sibling.a['href'], key)
                            if version:
                                return key + u':' + self.app + u'升级到' + version + u'版本或者更高版本；下载链接：' + self.url + '\n'
                        if child.find_next('td', string='Will not fix'):
                            node = child.find_next('td', string='Will not fix')
                            not_fix = node.find_previous_sibling('th', attrs={'headers':'th-platform'}).string
                            if not_fix:
                                if int(not_fix[-1]) == int(key[-1]):
                                    break
                        if child.find_next('td', string='Not affected'):
                            node = child.find_next('td', string='Not affected')
                            not_affect = node.find_previous_sibling('th', attrs={'headers':'th-platform'}).string
                            if not_affect:
                                if int(not_affect[-1]) == int(key[-1]):
                                    return u'不受影响'
        return u'REDHAT官网未提供' + key + u'的安装补丁,' + self.__redhat_search_cve_plan()