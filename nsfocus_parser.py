#-*- coding: utf-8 -*-
from optparse import OptionParser
from bs4 import BeautifulSoup
import xlwt
import xlrd

class nsfocus_parser():
    def __init__(self, filename, target, source):
        self.file = filename
        self.target = target
        self.source = source
        self.f = xlwt.Workbook()
        self.sheet1 = self.f.add_sheet(u'漏洞类型', cell_overwrite_ok=False)
        self.sheet2 = self.f.add_sheet(u'主机漏洞', cell_overwrite_ok=False)
        self.total_soup = BeautifulSoup(open(self.file).read().decode('utf-8', 'ignore'), 'html.parser')
        self.vul_vh = {}
        self.vul_vm = {}
        self.host_map = {}

    def save_file(self):
        self.f.save(self.target)
        print '漏洞分析报告： %s 已生成' % self.target

    def read_source(self):
        print '正在解析资产表：%s' % self.source
        print '请等待...'
        data = xlrd.open_workbook(self.source)
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
            list = item.find_all('a', class_ = 'vul-vh')
            for item1 in list:
                hosts = []
                cve = ''
                handle_strings = ''
                state_strings = ''
                scan_type = ''
                if item1.string.find(u'原理扫描'):
                    scan_type = u'可利用漏洞'
                else:
                    scan_type = u'版本扫描'
                self.vul_vh.setdefault(item1.string, []).append(u'高')
                #威胁数量
                self.vul_vh.setdefault(item1.string, []).append(item1.parent.next_sibling.next_sibling.string.strip())
                for item2 in item1.next_elements:
                    if item2.string == u'解决办法' and item2.next_element.next_element.next_element.name:
                        for string in item2.next_element.next_element.next_element.stripped_strings:
                            handle_strings += string
                            handle_strings += '\n'
                    if item2.string == u'详细描述' and item2.next_element.next_element.name:
                        for string in item2.next_element.next_element.stripped_strings:
                            state_strings += string
                            state_strings += '\n'
                        #print state_strings
                    if item2.string == u'CVE编号':
                        cve = item2.next_element.next_element.next_element.next_element.next_element.string.strip()
                        self.vul_vh.setdefault(item1.string, []).append(handle_strings)
                        self.vul_vh.setdefault(item1.string, []).append(state_strings)
                        self.vul_vh.setdefault(item1.string, []).append(cve)
                        self.vul_vh.setdefault(item1.string, []).append(scan_type)
                        if len(hosts):
                            for host in hosts:
                                self.vul_vh.setdefault(item1.string, []).append(host)
                        break
                        #print item2.next_element.next_element.next_element.next_element.next_element.string.strip()
                    if item2.string == u'受影响主机':
                        if item2.next_element.next_element.name:
                            #print item2.next_element.next_element.name
                            for child in item2.next_element.next_element.children:
                                if child.string.strip():
                                    hosts.append(child.string.strip())
                                    #print child.string.strip()
            list = item.find_all('a', class_ = 'vul-vm')
            for item1 in list:
                hosts = []
                cve = ''
                handle_strings = ''
                state_strings = ''
                scan_type = ''
                if item1.string.find(u'原理扫描'):
                    scan_type = u'可利用漏洞'
                else:
                    scan_type = u'版本扫描'
                self.vul_vm.setdefault(item1.string, []).append(u'中')
                #威胁数量
                self.vul_vm.setdefault(item1.string, []).append(item1.parent.next_sibling.next_sibling.string.strip())
                for item2 in item1.next_elements:
                    if item2.string == u'解决办法' and item2.next_element.next_element.next_element.name:
                        for string in item2.next_element.next_element.next_element.stripped_strings:
                            handle_strings += string
                            handle_strings += '\n'
                    if item2.string == u'CVE编号':
                        cve = item2.next_element.next_element.next_element.next_element.next_element.string.strip()
                        self.vul_vm.setdefault(item1.string, []).append(handle_strings)
                        self.vul_vm.setdefault(item1.string, []).append(state_strings)
                        self.vul_vm.setdefault(item1.string, []).append(cve)
                        self.vul_vm.setdefault(item1.string, []).append(scan_type)
                        if len(hosts):
                            for host in hosts:
                                self.vul_vm.setdefault(item1.string, []).append(host)
                        break
                    if item2.string == u'受影响主机':
                        if item2.next_element.next_element.name:
                            #print item2.next_element.next_element.name
                            for child in item2.next_element.next_element.children:
                                if child.string.strip():
                                    hosts.append(child.string.strip())
                                    #print child.string.strip()
        print '扫描报告解析完成\n'

    def output_vul_file(self):
        print '正在导出漏洞分析报告'
        row = 1
        col = 0
        self.sheet1.write(0, 0, u'漏洞描述')
        self.sheet1.write(0, 1, u'威胁等级')
        self.sheet1.write(0, 2, u'出现次数')
        self.sheet1.write(0, 3, u'解决方案')
        for item in self.vul_vh:
            self.sheet1.write(row, col, item)
            for i in range(0, 3):
                col += 1
                self.sheet1.write(row, col, self.vul_vh[item][i])
            col = 0
            row += 1
        col = 0
        for item in self.vul_vm:
            self.sheet1.write(row, col, item)
            for i in range(0, 3):
                col += 1
                self.sheet1.write(row, col, self.vul_vm[item][i])
            col = 0
            row += 1

    def output_host_file(self):
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
        row = 1
        col = 0
        for item in self.vul_vh:
            for i in range(6, len(self.vul_vh[item])):
                #ip
                self.sheet2.write(row, col, self.vul_vh[item][i])
                #科室
                col += 1
                self.sheet2.write(row, col, self.host_map[self.vul_vh[item][i]][0])
                #业务
                col += 1
                self.sheet2.write(row, col, self.host_map[self.vul_vh[item][i]][1])
                #操作系统版本
                col += 1
                self.sheet2.write(row, col, self.host_map[self.vul_vh[item][i]][2])
                #漏洞名称
                col += 1
                self.sheet2.write(row, col, item)
                #CVE编号
                col += 1
                self.sheet2.write(row, col, self.vul_vh[item][4])
                #漏洞详情
                col += 1
                self.sheet2.write(row, col, self.vul_vh[item][3])
                #危险等级
                col += 1
                self.sheet2.write(row, col, self.vul_vh[item][0])
                #漏洞分类
                col += 1
                self.sheet2.write(row, col, self.vul_vh[item][5])
                #加固方案
                col += 1
                self.sheet2.write(row, col, self.vul_vh[item][2])
                row += 1
                col = 0
        col = 0
        for item in self.vul_vm:
            for i in range(6, len(self.vul_vm[item])):
                #ip
                self.sheet2.write(row, col, self.vul_vm[item][i])
                #科室
                col += 1
                self.sheet2.write(row, col, self.host_map[self.vul_vm[item][i]][0])
                #业务
                col += 1
                self.sheet2.write(row, col, self.host_map[self.vul_vm[item][i]][1])
                #操作系统版本
                col += 1
                self.sheet2.write(row, col, self.host_map[self.vul_vm[item][i]][2])
                #漏洞名称
                col += 1
                self.sheet2.write(row, col, item)
                #CVE编号
                col += 1
                self.sheet2.write(row, col, self.vul_vm[item][4])
                #漏洞详情
                col += 1
                self.sheet2.write(row, col, self.vul_vm[item][3])
                #危险等级
                col += 1
                self.sheet2.write(row, col, self.vul_vm[item][0])
                #漏洞分类
                col += 1
                self.sheet2.write(row, col, self.vul_vm[item][5])
                #加固方案
                col += 1
                self.sheet2.write(row, col, self.vul_vm[item][2])
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

if __name__ == '__main__':
    cmd = CmdParser()
    report = nsfocus_parser(cmd.file, cmd.target, cmd.source)
    report.read_source()
    report.parser_file()
    report.output_vul_file()
    report.output_host_file()
    report.save_file()

