#-*- coding: utf-8 -*-
from bs4 import BeautifulSoup
import GlobalVar
import urllib2

class cve_analyze():
    def __init__(self):
        self.vul2url = GlobalVar.get_vul2url_dict()
        self.vul2plan = {}

    def get_plan(self):
        for item in self.vul2url:
            app = self.__find_app(item)
            if self.vul2url[item]:
                handle = self.__url_req(self.vul2url[item])
                self.vul2plan[item] = u'建议将' + app + u'升级到' + handle
            else:
                self.vul2plan[item] = u'无方案'
        return self.vul2plan

    #词法分析
    def __before(self, s):
        try:
            i = s.rindex('before') + len('before ')
        except:
            return ''
        version = ''
        while s[i] != ' ' and i < len(s) - 1:
            if s[i] == ',':
                break
            version += s[i]
            i += 1
        try:
            value = int(version.split('.')[0])
            return version + u'版本或者更高版本'
        except:
            self.__before(s[0:s.rindex('before')])

    def __through(self, s):
        i = s.rindex('through') + len('through ')
        string = ''
        version = ''
        while s[i] != ' ' and i < len(s) - 1:
            if s[i] == ',':
                break
            string += s[i]
            i += 1
        value = string.split('.')
        try:
            value[-1] = str(int(value[-1]) + 1)
        except:
            return ''
        version = '.'.join(value)
        return version + u'版本或者更高版本'

    def __allows(self, s, keyword):
        i = s.rindex(keyword)
        i -= 1
        end = i
        version = ''
        while s[i] != ' ' and i < len(s) - 1:
            i -= 1
        value = s[i + 1:end + 1].split('.')
        try:
            value[-1] = str(int(value[-1]) + 1)
        except:
            if value[-1] == 'x':
                value[-1] = '0'
                try:
                    value[-2] = str(int(value[-2]) + 1)
                except:
                    return ''
        version = '.'.join(value)
        return version + u'版本或者更高版本'

    def __earlier(self, s):
        i = s.rindex(' and earlier')
        i -= 1
        end = i
        version = ''
        while s[i] != ' ' and i < len(s) - 1:
            i -= 1
        value = s[i + 1:end + 1].split('.')
        try:
            value[-1] = str(int(value[-1]) + 1)
        except:
            return s[i + 1: end + 1] + u'以上版本'
        version = '.'.join(value)
        return version + u'版本或者更高版本'

    def __find_app(self, vul):
        if vul.find('MySQL') >= 0 or vul.find('SQL') >= 0:
            return 'MySQL'

        if vul.find('Oracle') >= 0 and vul.find('MySQL') < 0:
            return 'Oracle'

        if vul.find('Samba') >= 0:
            return 'Samba'

        if vul.find('nginx') >=0 or vul.find('Nginx') >= 0:
            return 'nginx'

        if vul.find('Apache Tomcat') >=0:
            return 'Apache Tomcat'

        if vul.find('Apache') >=0 and vul.find('Tomcat') < 0:
            return 'Apache'

        if vul.find('NTPD') >=0 or vul.find('ntpd') >= 0:
            return 'ntpd'

        if vul.find('PHP') >=0:
            return 'PHP'

        if vul.find('ftp') >=0:
            return 'ftp'

        if vul.find('HP') >=0:
            return 'HP'

        if vul.find('Serv-U') >=0:
            return 'Serv-U'

        if vul.find('OpenSSH') >=0:
            return 'OpenSSH'

        if vul.find('OpenSSL') >=0:
            return 'OpenSSL'

        if vul.find('yaSSL') >=0:
            return 'yaSSL'

        return u'建议'

    def __url_req(self, url):
        print '正在分析CVE漏洞版本信息'
        print url
        string = ''
        app = ''
        ret = ''
        req = urllib2.Request(url)
        resp = urllib2.urlopen(req)
        page = resp.read()
        soup = BeautifulSoup(page, 'html.parser')
        ds = soup.find_all('th', string = 'Description')

        for item in ds:
            string = item.next_element.next_element.next_element.next_element.next_element.next_element.string
            if string.find('before') >= 0:
                ret = self.__before(string)
                if ret:
                    return ret

            elif string.find('through') >= 0:
                ret = self.__through(string)
                if ret:
                    return ret

            elif string.find(' and earlier') >= 0:
                ret = self.__earlier(string)
                if ret:
                    return ret

            elif string.find('allows') >= 0:
                if string.find(' allows') >= 0:
                    ret = self.__allows(string, ' allows')
                else:
                    ret = self.__allows(string, 'allows')
                if ret:
                    return ret
            return string