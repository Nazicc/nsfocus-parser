#-*- coding: utf-8 -*-
from bs4 import BeautifulSoup
import GlobalVar
import xlwt
import xlrd
import re

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

    def save_file(self):
        self.f.save(self.target)
        print '漏洞分析报告： %s 已生成' % self.target

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

    def __insert_affect_host(self, node):
        name = node.string.strip()
        snode = node.find_next('td', string = u'受影响主机')
        for child in snode.next_element.next_element.next_element.children:
            host = child.string.strip()
            if host:
                if not host in self.vul[name][6]:
                    self.vul[name][6].append(host)

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
                if self.vul.has_key(vul_name):
                    self.__insert_affect_host(item1)
                    continue
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
                self.vul.setdefault(vul_name, []).append([])
                found_app = False
                for app in GlobalVar.app_list:
                    if vul_name.upper().find(app.upper()) >= 0:
                        found_app = True
                        break
                if not len(self.host_map) and len(hosts):
                    self.vul[vul_name][6] = hosts
                    continue
                if len(hosts):
                    cve_sys_list = []
                    for host in hosts:
                        if not self.host_map.has_key(host):
                            print 'Not find host ' + host + '\n'
                            continue
                        self.vul[vul_name][6].append(host)
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
                            GlobalVar.plan_list.setdefault(cve, []).append({new_sys:''})
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
        if GlobalVar.plan_list.has_key(self.vul[vul_name][4]):
            for item in GlobalVar.plan_list[self.vul[vul_name][4]]:
                if item.keys()[0] == key:
                    return item[item.keys()[0]]
        else:
            return GlobalVar.cve_plan[vul_name]

    def only_convert2excel(self):
        print '正在导出主机漏洞分析报告'
        self.sheet2.write(0, 0, u'IP')
        self.sheet2.write(0, 1, u'漏洞名称')
        self.sheet2.write(0, 2, u'CVE编号')
        self.sheet2.write(0, 3, u'漏洞详情')
        self.sheet2.write(0, 4, u'危险等级')
        self.sheet2.write(0, 5, u'漏洞分类')
        self.sheet2.write(0, 6, u'加固方案')
        row = 1
        col = 0
        for item in self.vul:
            for i in range(len(self.vul[item][6])):
                #ip
                self.sheet2.write(row, col, self.vul[item][6][i])
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
                row += 1
                col = 0

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
            for i in range(len(self.vul[item][6])):
                #ip
                self.sheet2.write(row, col, self.vul[item][6][i])
                #科室
                col += 1
                self.sheet2.write(row, col, self.host_map[self.vul[item][6][i]][0])
                #业务
                col += 1
                self.sheet2.write(row, col, self.host_map[self.vul[item][6][i]][1])
                #操作系统版本
                col += 1
                self.sheet2.write(row, col, self.host_map[self.vul[item][6][i]][2])
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
                self.sheet2.write(row, col, self.__make_final_policy(self.vul[item][6][i], item))
                row += 1
                col = 0