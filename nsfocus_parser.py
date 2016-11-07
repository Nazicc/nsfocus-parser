#-*- coding: utf-8 -*-
from optparse import OptionParser
from bs4 import BeautifulSoup
import urllib2
import xlwt
import xlrd
import re
import random

global sys
global plan_list
global vul_db
global cve_plan
cve_plan = {}
sys = {}
plan_list = {}
vul_db = {}

app_list = ['ntp', 'samba', 'openssh', 'openssl', 'php']
suse_prefix = 'https://www.suse.com/zh-cn/security/cve/'
redhat_prefix = 'https://access.redhat.com/security/cve/'

useragents = [
    "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30)",
    "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322)",
    "Googlebot/2.1 (http://www.googlebot.com/bot.html)",
    "Opera/9.20 (Windows NT 6.0; U; en)",
    "Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.1.1) Gecko/20061205 Iceweasel/2.0.0.1 (Debian-2.0.0.1+dfsg-2)",
    "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; FDM; .NET CLR 2.0.50727; InfoPath.2; .NET CLR 1.1.4322)",
    "Opera/10.00 (X11; Linux i686; U; en) Presto/2.2.0",
    "Mozilla/5.0 (Windows; U; Windows NT 6.0; he-IL) AppleWebKit/528.16 (KHTML, like Gecko) Version/4.0 Safari/528.16",
    "Mozilla/5.0 (compatible; Yahoo! Slurp/3.0; http://help.yahoo.com/help/us/ysearch/slurp)", # maybe not
    "Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.13) Gecko/20101209 Firefox/3.6.13"
    "Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 5.1; Trident/5.0)",
    "Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727)",
    "Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 6.0)",
    "Mozilla/4.0 (compatible; MSIE 6.0b; Windows 98)",
    "Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.2.3) Gecko/20100401 Firefox/4.0 (.NET CLR 3.5.30729)",
    "Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.8) Gecko/20100804 Gentoo Firefox/3.6.8",
    "Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.7) Gecko/20100809 Fedora/3.6.7-1.fc14 Firefox/3.6.7",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)",
    "YahooSeeker/1.2 (compatible; Mozilla 4.0; MSIE 5.5; yahooseeker at yahoo-inc dot com ; http://help.yahoo.com/help/us/shop/merchant/)"
]

def sys_keyword_install():
    sys['SUSE 9'] = map(lambda x: 'SUSE LINUX ' + str(x + 9), [0.1 * i for i in range(4)])
    sys['SUSE 10'] = map(lambda x: 'SUSE LINUX ' + str(x + 10), [0.1 * i for i in range(4)])
    map(lambda x: sys.setdefault('SUSE 10', []).append(x),
        map(lambda x: 'SUSE Linux Enterprise Server 10 SP' + str(x), [x for x in range(1, 5)]))
    map(lambda x: sys.setdefault('SUSE 11', []).append(x),
        map(lambda x: 'SUSE Linux Enterprise Server 11 SP' + str(x), [x for x in range(1, 5)]))
    map(lambda x: sys.setdefault('SUSE 12', []).append(x),
        map(lambda x: 'SUSE Linux Enterprise Server 12 SP' + str(x), [x for x in range(1, 5)]))
    map(lambda x: sys.setdefault('SUSE 10 SP' + str(x), []).append('SUSE Linux Enterprise Server 10 SP' + str(x)),
        [x for x in range(1, 5)])
    map(lambda x: sys.setdefault('SUSE 11 SP' + str(x), []).append('SUSE Linux Enterprise Server 11 SP' + str(x)),
        [x for x in range(1, 5)])
    map(lambda x: sys.setdefault('REDHAT ' + str(x), []).append('Red Hat Enterprise Linux ' + str(x)),
        [x for x in range(3, 8)])

class redhat_analyze():
    def __init__(self, url, name, sys_key):
        self.url = url
        self.sys_key = sys_key
        self.app = name

    def start_analyze(self):
        return self.__send_request2redhat()

    def __send_request2redhat(self):
        tries = 5
        req = urllib2.Request(self.url)
        req.add_header('User-Agent', random.choice(useragents))
        while tries:
            try:
                return self.__redhat_page_analyze(urllib2.urlopen(req).read())
            except:
                tries -= 1
                continue
        print u'访问' + self.url + u'异常'

    def __redhat_search_cve_plan(self):
        for item in vul_db:
            if vul_db[item][4] == self.url.split('/')[-1]:
                return cve_plan[item]

    def __redhat_refer_page_analyze(self, url, key):
        req = urllib2.Request(url)
        req.add_header('User-Agent', random.choice(useragents))
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


class suse_analyze():
    def __init__(self, url, name, sys_key):
        self.url = url
        self.sys_key = sys_key
        self.app = name

    def start_analyze(self):
        return self.__send_request2suse()

    def __send_request2suse(self):
        tries = 5
        req = urllib2.Request(self.url)
        req.add_header('User-Agent', random.choice(useragents))
        while tries:
            try:
                return self.__suse_page_analyze(urllib2.urlopen(req).read())
            except:
                tries -= 1
                continue
        print u'Try ' + self.url + u' Failed'

    def __suse_search_cve_plan(self):
        for item in vul_db:
            if vul_db[item][4] == self.url.split('/')[-1]:
                return cve_plan[item]

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
                self.url = suse_prefix + ref_cve.split(' ')[1]
                ref_handle = self.start_analyze()
                if ref_handle:
                    return ref_handle + u'参考链接:' + origin_url
                return ''
        return u'SUSE官网未提供' + self.sys_key + u'的安装补丁,' + self.__suse_search_cve_plan()

class cve_analyze():
    def __init__(self, vul2url):
        self.vul2url = vul2url
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

class nsfocus_parser():
    def __init__(self, filename, target, source):
        self.file = filename
        self.target = target
        self.source = source
        self.f = xlwt.Workbook()
        self.sheet1 = self.f.add_sheet(u'漏洞类型', cell_overwrite_ok=False)
        self.sheet2 = self.f.add_sheet(u'主机漏洞', cell_overwrite_ok=False)
        self.total_soup = BeautifulSoup(open(self.file).read().decode('utf-8', 'ignore'), 'html.parser')
        self.vul = {}
        self.host_map = {}
        self.handle_map = {}

    def save_file(self):
        self.f.save(self.target)
        print '漏洞分析报告： %s 已生成' % self.target

    def get_vul2url_dict(self):
        url_prefix = 'http://cve.mitre.org/cgi-bin/cvename.cgi?name='
        vul2url = {}
        for item in self.vul:
            if self.vul[item][4]:
                vul2url[item] = url_prefix + self.vul[item][4]
            else:
                vul2url[item] = ''
        return vul2url

    def read_source(self):
        print '正在解析资产表：%s' % self.source
        print '请等待...'
        with xlrd.open_workbook(self.source) as data:
            table = data.sheet_by_name(u'主机')
            for value in table.row_values(0):
                if  value == u'DCN公网IP地址':
                    host_index = table.row_values(0).index(value)
                if  value == u'业务归属科室':
                    keshi_index = table.row_values(0).index(value)
                if  value == u'所属业务系统':
                    suoshu_index = table.row_values(0).index(value)
                if  value == u'操作系统版本':
                    sys_index = table.row_values(0).index(value)
            for i in range(1, table.nrows):
                self.host_map.setdefault(table.row_values(i)[host_index], []).append(table.row_values(i)[keshi_index])
                self.host_map.setdefault(table.row_values(i)[host_index], []).append(table.row_values(i)[suoshu_index])
                self.host_map.setdefault(table.row_values(i)[host_index], []).append(table.row_values(i)[sys_index])
        print '资产解析完成\n'

    def parser_file(self):
        print '正在解析Nsfocus扫描报告: %s' % self.file
        print '请等待...'
        vul_table = self.total_soup.find_all('table', class_ = 'cmn_table', id = 'vulDataTable')
        for item in vul_table:
            list = item.find_all('a', class_ = re.compile('vul-v[hm]'))
            for item1 in list:
                hosts = []
                cve = ''
                handle_strings = ''
                state_strings = ''
                scan_type = ''
                vul_name = item1.string.strip()
                if vul_name.find(u'原理扫描'):
                    scan_type = u'可利用漏洞'
                else:
                    scan_type = u'版本扫描'
                if self.vul.has_key(vul_name):
                    continue
                if item1['class'][0] == u'vul-vh':
                    self.vul.setdefault(vul_name, []).append(u'高')
                elif item1['class'][0]== u'vul-vm':
                    self.vul.setdefault(vul_name, []).append(u'中')
                self.vul.setdefault(vul_name, []).append(item1.find_next('td', class_ = re.compile('numLink[HighMd]+')).string.strip())
                cmn_children = item1.find_next('table', class_ = 'cmn_table plumb').children
                for child in cmn_children:
                    res = ''
                    if len(child)==1:
                        continue
                    if child.get_text().find(u'受影响主机') >0:
                        res = child.find_next('td', string = '受影响主机')
                        for vul_host in res.next_element.next_element.next_element.children:
                            if vul_host.string.strip():
                                hosts.append(vul_host.string.strip())
                                continue
                        '''
                        if res and len(hosts) == 0:
                            #print res.next_sibling.next_sibling.string.strip('\n\t ').strip(u' ').split(u' ')
                            hosts = res.next_sibling.next_sibling.string.strip('\n\t ').strip(u' ').split(u' ')
                            #hosts.append(vul_host.string.strip())
                        '''
                    if child.get_text().find(u'详细描述') >= 0:
                        res = child.find_next('td', string = '详细描述')
                        if res and state_strings == '':
                            for string in res.next_sibling.next_sibling.stripped_strings:
                                state_strings += string
                                state_strings += '\n'
                            continue

                    if child.get_text().find(u'解决办法') >= 0:
                        res = child.find_next('td', string = '解决办法')
                        if res and handle_strings == '':
                            for string in res.next_sibling.next_sibling.stripped_strings:
                                handle_strings += string
                                handle_strings += '\n'
                            continue
                    if child.get_text().find(u'CVE编号') >= 0:
                        res = child.find_next('td', string = 'CVE编号', recursive=False)
                        if res and cve == '':
                            cve = res.next_sibling.next_sibling.next_element.next_element.string.strip()
                            break
                self.vul.setdefault(vul_name, []).append(handle_strings)
                self.vul.setdefault(vul_name, []).append(state_strings)
                self.vul.setdefault(vul_name, []).append(cve)
                self.vul.setdefault(vul_name, []).append(scan_type)
                found_app = False
                for app in app_list:
                    if vul_name.upper().find(app.upper()) >= 0:
                        found_app = True
                        break
                if len(hosts):
                    cve_sys_list = []
                    for host in hosts:
                        if not self.host_map.has_key(host):
                            print 'Not find host ' + host + '\n'
                            continue
                        self.vul.setdefault(vul_name, []).append(host)
                        new_key = ''
                        if found_app:
                            new_key = self.__get_system_key(host)
                            if new_key in cve_sys_list:
                                pass
                            else:
                                if new_key:
                                    cve_sys_list.append(new_key)
                    if len(cve_sys_list) and cve:
                        for new_sys in cve_sys_list:
                            #print 'cve: ' + cve + ' system: ' + new_sys
                            plan_list.setdefault(cve, []).append({new_sys:''})
        print '扫描报告解析完成\n'
        return self.vul

    def output_vul_file(self):
        print '正在导出漏洞类型分析报告'
        row = 1
        col = 0
        self.sheet1.write(0, 0, u'漏洞描述')
        self.sheet1.write(0, 1, u'威胁等级')
        self.sheet1.write(0, 2, u'出现次数')
        self.sheet1.write(0, 3, u'解决方案')
        for item in self.vul:
            self.sheet1.write(row, col, item)
            for i in range(0, 3):
                col += 1
                self.sheet1.write(row, col, self.vul[item][i])
            col = 0
            row += 1

    def __get_system_key(self, ip):
        if self.host_map[ip][2].upper().find('REDHAT') >= 0:
            tmp = self.host_map[ip][2].upper().split(' ')
            if len(tmp) == 2:
                tmp[-1] = str(int(float(tmp[-1])))
                return ' '.join(tmp)
            if len(tmp) == 3:
                tmp[-2] = str(int(float(tmp[-2])))
                tmp.pop()
                return ' '.join(tmp)
        elif self.host_map[ip][2].upper().find('SUSE') >= 0:
            return self.host_map[ip][2].upper()
        return ''

    def __make_final_policy(self, ip, vul_name):
        if vul_name.find('Oracle') >= 0 and vul_name.find('mysql') < 0  and vul_name.find('MySQL') < 0:
            return u'迁移到最新版本Oracle并更新Opatch补丁'
        key = self.__get_system_key(ip)
        if plan_list.has_key(self.vul[vul_name][4]):
            for item in plan_list[self.vul[vul_name][4]]:
                if item.keys()[0] == key:
                    return item[item.keys()[0]]
        else:
            return cve_plan[vul_name]

    def output_host_file(self):
        print '正在导出主机漏洞分析报告'
        self.sheet2.write(0, 0, u'IP')
        self.sheet2.write(0, 1, u'科室')
        self.sheet2.write(0, 2, u'业务')
        self.sheet2.write(0, 3, u'操作系统版本')
        self.sheet2.write(0, 4, u'漏洞名称')
        self.sheet2.write(0, 5, u'CVE编号')
        self.sheet2.write(0, 6, u'漏洞详情')
        self.sheet2.write(0, 7, u'危险等级')
        self.sheet2.write(0, 8, u'漏洞分类')
        self.sheet2.write(0, 9, u'加固方案')
        self.sheet2.write(0, 10, u'加固建议')
        row = 1
        col = 0
        for item in self.vul:
            for i in range(6, len(self.vul[item])):
                #ip
                self.sheet2.write(row, col, self.vul[item][i])
                #科室
                col += 1
                self.sheet2.write(row, col, self.host_map[self.vul[item][i]][0])
                #业务
                col += 1
                self.sheet2.write(row, col, self.host_map[self.vul[item][i]][1])
                #操作系统版本
                col += 1
                self.sheet2.write(row, col, self.host_map[self.vul[item][i]][2])
                #漏洞名称
                col += 1
                self.sheet2.write(row, col, item)
                #CVE编号
                col += 1
                self.sheet2.write(row, col, self.vul[item][4])
                #漏洞详情
                col += 1
                self.sheet2.write(row, col, self.vul[item][3])
                #危险等级
                col += 1
                self.sheet2.write(row, col, self.vul[item][0])
                #漏洞分类
                col += 1
                self.sheet2.write(row, col, self.vul[item][5])
                #加固方案
                col += 1
                self.sheet2.write(row, col, self.vul[item][2])
                #加固建议
                col += 1
                self.sheet2.write(row, col, self.__make_final_policy(self.vul[item][i], item))
                row += 1
                col = 0

def CmdParser():
    usage = 'Parser nsfocus report tool v1.0'
    opt = OptionParser(usage)
    opt.add_option('-f', '--filename', dest = 'file', type = 'string', help = 'nsfocus report')
    opt.add_option('-s', '--source', dest = 'source', type = 'string', help = 'source file')
    opt.add_option('-o', '--output', dest = 'target', type = 'string', help = 'output excel')
    option, args = opt.parse_args()
    return option

def find_app_name(cve):
    for item in vul_db:
        if vul_db[item][4] == cve:
            for app in app_list:
                if item.upper().find(app.upper()) >= 0:
                    return app

def start_system_plan():
    for cve in plan_list:
        for item in plan_list[cve]:
            if item.keys()[0].find('REDHAT') >= 0:
                redhat_a = redhat_analyze(redhat_prefix + cve, find_app_name(cve), item.keys()[0])
                item[item.keys()[0]] = redhat_a.start_analyze()
            if item.keys()[0].find('SUSE') >= 0:
                suse_a = suse_analyze(suse_prefix + cve, find_app_name(cve), item.keys()[0])
                item[item.keys()[0]] = suse_a.start_analyze()

if __name__ == '__main__':
    cmd = CmdParser()
    sys_keyword_install()
    report = nsfocus_parser(cmd.file, cmd.target, cmd.source)

    report.read_source()
    vul_db = report.parser_file()

    cve = cve_analyze(report.get_vul2url_dict())
    cve_plan = cve.get_plan()
    start_system_plan()

    report.output_vul_file()
    report.output_host_file()
    report.save_file()

