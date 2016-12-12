cve_plan = {}
sys = {}
plan_list = {}
vul_db = {}

app_list = ['ntp', 'samba', 'openssh', 'openssl', 'php']
suse_prefix = 'https://www.suse.com/zh-cn/security/cve/'
redhat_prefix = 'https://access.redhat.com/security/cve/'
cve_prefix = 'http://cve.mitre.org/cgi-bin/cvename.cgi?name='

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
    global sys
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

def search_cve_plan(cve):
    global vul_db
    for item in vul_db:
       if vul_db[item][4] == cve:
           return cve_plan[item]

def get_vul2url_dict():
    global vul_db
    vul2url = {}
    for item in vul_db:
        if vul_db[item][4]:
            vul2url[item] = cve_prefix + vul_db[item][4]
        else:
            vul2url[item] = ''
    return vul2url