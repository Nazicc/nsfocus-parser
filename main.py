from optparse import OptionParser
import CveSpider
import RedhatSpider
import SuseSpider
import NsfocusReportParser
import GlobalVar

def CmdParser():
    usage = 'Parser nsfocus report tool v1.0'
    opt = OptionParser(usage)
    opt.add_option('-f', '--filename', dest = 'file', type = 'string', help = 'nsfocus report')
    opt.add_option('-s', '--source', action = 'store', dest = 'source', type = 'string', help = 'source file')
    opt.add_option('-o', '--output', dest = 'target', type = 'string', help = 'output excel')
    option, args = opt.parse_args()
    return option

def find_app_name(cve):
    for item in vul_db:
        if vul_db[item][4] == cve:
            for app in GlobalVar.app_list:
                if item.upper().find(app.upper()) >= 0:
                    return app

def start_system_plan():
    for cve in GlobalVar.plan_list:
        for item in GlobalVar.plan_list[cve]:
            if item.keys()[0].find('REDHAT') >= 0:
                redhat_a = RedhatSpider.redhat_analyze(GlobalVar.redhat_prefix + cve, find_app_name(cve), item.keys()[0])
                item[item.keys()[0]] = redhat_a.start_analyze()
            if item.keys()[0].find('SUSE') >= 0:
                suse_a = SuseSpider.suse_analyze(GlobalVar.suse_prefix + cve, find_app_name(cve), item.keys()[0])
                item[item.keys()[0]] = suse_a.start_analyze()

if __name__ == '__main__':
    cmd = CmdParser()
    GlobalVar.sys_keyword_install()
    report = NsfocusReportParser.nsfocus_parser(cmd.file, cmd.target, cmd.source)

    if cmd.source != None:
        report.read_source()

    vul_db = report.parser_file()

    if cmd.source != None:
        cve = CveSpider.cve_analyze()
        cve_plan = cve.get_plan()
        start_system_plan()
        report.output_host_file()
    else:
        report.only_convert2excel()

    report.output_vul_file()
    report.save_file()
