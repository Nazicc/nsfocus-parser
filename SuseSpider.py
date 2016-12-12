#-*- coding: utf-8 -*-:w
from bs4 import BeautifulSoup
import GlobalVar
import urllib2
import random
import re

class suse_analyze():
    global sys
    def __init__(self, url, name, sys_key):
        self.url = url
        self.sys_key = sys_key
        self.app = name

    def start_analyze(self):
        return self.__send_request2suse()

    def __send_request2suse(self):
        tries = 5
        req = urllib2.Request(self.url)
        req.add_header('User-Agent', random.choice(GlobalVar.useragents))
        while tries:
            try:
                return self.__suse_page_analyze(urllib2.urlopen(req).read())
            except:
                tries -= 1
                continue
        print u'Try ' + self.url + u' Failed'

    def __suse_search_cve_plan(self):
        return GlobalVar.search_cve_plan(self.url.split('/')[-1])

    def __suse_page_analyze(self, page):
        found_handle = False
        plan = ''
        soup = BeautifulSoup(page, 'html.parser')
        release = soup.find_all('h3', string='List of released packages', limit=1)
        print u'正在分析' + u' 系统:'+ self.sys_key + u' 应用:' + self.app + u' 漏洞公告:' + self.url
        if release:
            for item1 in release[0].next_element.next_element.next_element.next_element.next_element.next_siblings:
                try:
                    #for child in item1.children:
                    for child in item1.descendants:
                        for i in range(0, len(sys[self.sys_key])):
                            #if child.string.strip().find(sys[self.sys_key][i]) >= 0:
                            if child.find(sys[self.sys_key][i]) >= 0:
                                code = child.find_next('code', text = re.compile(self.app + ' >='))
                                pattern = re.compile("(?<=.=).*")
                                m = pattern.search(code.string.strip())
                                handle_string = sys[self.sys_key][i] + u':' + self.app + u'升级到' + str(m.group()).strip() + u'版本或者更高版本；下载链接：' + self.url + '\n'
                                if plan.find(handle_string) < 0:
                                    plan += handle_string
                                found_handle = True
                                break
                except:
                    continue
        if found_handle:
            if len(sys[self.sys_key]) > 1:
                plan += u'SUSE官网未提供' + self.sys_key + u'其他版本的安装补丁' + self.__suse_search_cve_plan()
            return plan
        note = soup.find_all('h4', string='Note from the SUSE Security Team')
        if note:
            string = note[0].next_element.next_element.string
            if string.find('This issue does not affect') >= 0:
                pattern = re.compile('[SLE ]{4}[\d]{1,2}')
                m = re.findall(pattern, string)
                if m:
                    for not_affect in m:
                        if self.sys_key.find(not_affect.strip().split(' ')[1]) >= 0:
                            return u'不受影响'
                pattern = re.compile('SUSE Linux Enterprise Server [\d]{1,2}')
                m = re.findall(pattern, string)
                if m:
                    for not_affect in m:
                        try:
                            if self.sys_key.find(not_affect.split(' ')[-1]) >= 0:
                                return u'不受影响'
                            if string.find('older') >= 0:
                                if int(self.sys_key.split(' ')[1]) <= int(not_affect.split(' ')[-1]):
                                    return u'不受影响'
                        except:
                            return u'解析失败，未曾学习过的词法'
                return u'解析失败，未曾学习过的词法'
            elif string.find('Please see') >= 0:
                ref_cve = note[0].next_element.next_element.next_element.string
                origin_url = self.url
                self.url = GlobalVar.suse_prefix + ref_cve.split(' ')[1]
                ref_handle = self.start_analyze()
                if ref_handle:
                    return ref_handle + u'参考链接:' + origin_url
                return ''
        return u'SUSE官网未提供' + self.sys_key + u'的安装补丁,' + self.__suse_search_cve_plan()