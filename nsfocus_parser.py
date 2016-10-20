#-*- coding: utf-8 -*-
from optparse import OptionParser
from bs4 import BeautifulSoup
import xlwt

class nsfocus_parser():
    def __init__(self, filename, target):
        self.file = filename
        self.target = target
        self.f = xlwt.Workbook()
        self.sheet1 = self.f.add_sheet(u'sheet1', cell_overwrite_ok=False)
        self.total_soup = BeautifulSoup(open(self.file).read().decode('utf-8', 'ignore'), 'html.parser')
        self.vul_vh = {}
        self.vul_vm = {}

    def parser_file(self):
        print 'Start Parser File: %s' % self.file
        vul_table = self.total_soup.find_all('table', class_ = 'cmn_table', id = 'vulDataTable')
        for item in vul_table:
            list = item.find_all('a', class_ = 'vul-vh')
            for item1 in list:
                self.vul_vh.setdefault(item1.string, []).append(u'高')
                #威胁数量
                self.vul_vh.setdefault(item1.string, []).append(item1.parent.next_sibling.next_sibling.string.strip())
                for item2 in item1.next_elements:
                    strings = ''
                    if item2.string == u'解决办法':
                        for string in item2.next_element.next_element.next_element.stripped_strings:
                            strings += string
                            strings += '\n'
                        self.vul_vh.setdefault(item1.string, []).append(strings)
                        break
            list = item.find_all('a', class_ = 'vul-vm')
            for item1 in list:
                self.vul_vm.setdefault(item1.string, []).append(u'中')
                #威胁数量
                self.vul_vm.setdefault(item1.string, []).append(item1.parent.next_sibling.next_sibling.string.strip())
                for item2 in item1.next_elements:
                    strings = ''
                    if item2.string == u'解决办法':
                        for string in item2.next_element.next_element.next_element.stripped_strings:
                            strings += string
                            strings += '\n'
                        self.vul_vm.setdefault(item1.string, []).append(strings)
                        break
        print 'Parser Done !'

    def output_file(self):
        row = 1
        col = 0
        self.sheet1.write(0, 0, u'漏洞描述')
        self.sheet1.write(0, 1, u'威胁等级')
        self.sheet1.write(0, 2, u'出现次数')
        self.sheet1.write(0, 3, u'解决方案')
        for item in self.vul_vh:
            self.sheet1.write(row, col, item)
            for i in range(0, len(self.vul_vh[item])):
                col += 1
                self.sheet1.write(row, col, self.vul_vh[item][i])
            col = 0
            row += 1
        col = 0
        for item in self.vul_vm:
            self.sheet1.write(row, col, item)
            for i in range(0, len(self.vul_vm[item])):
                col += 1
                self.sheet1.write(row, col, self.vul_vm[item][i])
            col = 0
            row += 1
        self.f.save(self.target)
        print 'Generate Report %s Done' % self.target


def CmdParser():
    usage = 'Parser nsfocus report tool v1.0'
    opt = OptionParser(usage)
    opt.add_option('-f', '--filename', dest = 'file', type = 'string', help = 'nsfocus report')
    opt.add_option('-o', '--output', dest = 'target', type = 'string', help = 'output excel')
    option, args = opt.parse_args()
    return option

if __name__ == '__main__':
    cmd = CmdParser()
    report = nsfocus_parser(cmd.file, cmd.target)
    report.parser_file()
    report.output_file()
