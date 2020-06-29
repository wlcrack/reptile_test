# -*- coding: UTF-8 -*-

import os, time
from html.parser import HTMLParser
import requests,sys,sqlite3,codecs
import multiprocessing
import getopt

tmp_name = {
  1:'Windows系列',            2:'Unix/Linux系列',
  3:'网络设备和防火墙',       4:'网络信息收集',
  8:'存活主机扫描',           9:'高危漏洞扫描',
  10:'端口扫描',              11:'远程服务版本信息收集',
  12:'全部漏洞扫描',          15:'Exploit DB漏洞扫描',
  16:'Metasploit漏洞扫描',    17:'Exploit Pack漏洞扫描',
  18:'原理扫描',              20:'国产系统和软件漏洞扫描',
  21:'虚拟化漏洞',            22:'Oracle数据库',
  23:'Mysql数据库',           24:'Mssql数据库',
  25:'DB2数据库',             26:'SYBASE数据库',
  27:'大数据漏洞',               28:'紧急漏洞',
  29:'方程式泄漏工具漏洞扫描',   30:'云计算漏洞扫描',
  31:'物联网漏洞',               32:'远程办公软件漏洞',
  99:'DNS检测',                  98:'Apache Tomcat文件包含漏洞(CVE-2020-1938)',
}

val_name = {
  'System':   '系统',       'CVE%20Year': 'CVE年份',
  'Services': '服务',       'Application':'应用',
  'Threat':   '威胁',       'Time':        '时间',
}

val = ['System', 'CVE%20Year', 'Services', 'Application', 'Threat', 'Time']
#tmpid_proc1 = [1,2,3,4,8,9,10,11,12,15,16,17,18,20,21,22,23,24,25,26,27,28,29,30,31,32,98,99,]
#tmpid_proc1 = [12,15,16,17,18,20,21,22,23,24,25,26,27,28,29,30,31,32,98,99,] #ALL   Start
tmpid_proc1 = [1,2,3,4,8,9,10,11,]

DEFAULT_USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36'
DEFAULT_COOKIE     = 'your self cookie'

headers = {
    "User-Agent": DEFAULT_USER_AGENT,
    "Cookie": DEFAULT_COOKIE,
    "Connection":"close",
}

class MyHtmlParser(HTMLParser):
    
    def __init__(self, tempid, type, name, limitid, detaile_name):
        HTMLParser.__init__(self)
        self.tempid = tempid
        self.type = type
        self.id = ''
        self.info_dict = {tempid:[], 'type':type}
        self.name = name 
        self.limit = ''
        self.limitid = limitid
        self.detaile_name = detaile_name
    
    def return_info(self):
        return self.info_dict
    
    def handle_starttag(self, tag, attrs):
        
        if tag == 'div':
            for attr in attrs:
                if attr[0] == 'id':
                    self.id = attr[1]
                elif attr[0] == 'limit':
                    self.limit = attr[1]
    
    def handle_endtag(self, tag):
        pass
 
    def handle_data(self, data):
        
        if self.name == 'vul_id':
            self.info_dict[self.tempid].append(tuple([self.id, data, self.limitid, self.detaile_name], ))
            self.id = ''
        else:
            start = data.find('[')
            end = data.find(']')
            
            if start > 0:
                num = data[start+1:end]
                if int(num) != 0:
                    if self.name == 'catgory':
                        #self.info_dict[self.tempid].append(self.id)
                        self.info_dict[self.tempid].append(tuple([self.id, data[:start]], ))
                        self.id = ''
                    elif self.name == 'thread_level':
                        #get leve high midle low
                        self.info_dict[self.tempid].append(tuple([self.id, self.limit, self.detaile_name], ))
                        self.id = ''

class CVE_INFO_PARSER(HTMLParser):

    def __init__(self):
        HTMLParser.__init__(self)
        self.need_data = False
        self.data_dict = {'date':'', 'cve':'', 'cnnvd':''}
        
    def return_info(self):
        return self.data_dict
        
    def handle_starttag(self, tag, attrs):
        if tag == 'td':
            self.need_data = True
    
    def handle_data(self, data):
        if self.need_data:
            try:
                find_time = time.strptime(data, "%Y-%m-%d")
                self.data_dict['date'] = data
            except:
                pass
            if 'cve' == data.lower()[:3]:
                self.data_dict['cve'] = data
            elif 'cnnvd' == data.lower()[:5]:
                self.data_dict['cnnvd'] = data
        
        self.need_data = False

def data_into_sqlite(sqllite_queue):
    print("[+] start handle data into sqlite pid :{0} ....".format(os.getpid()))
    
    try:
        conn=sqlite3.connect("cve_info.db")
        conn.executescript('PRAGMA encoding = "UTF-8";')
        cursor = conn.cursor()
    except Exception as e:
        print("SQLITE CONNECT FAILED: "+str(e))
        sys.exit(0)
    
    sqlcnt = 0
    while True:
        try:
            sql = ''
            s = sqllite_queue.get(timeout = 120)
            tempname = s[0]
            tempid = s[1]
            valname = s[2]
            val = s[3]
            vulid = s[4]
            name = s[5]
            date = s[6]
            cve = s[7]
            cnnvd = s[8]
            
            level = s[9]
            detaile_name = s[10]
            
            sqlcnt += 1
            sql = 'insert into cve_info'
            sql = sql + '(tempname, tempid, valname, val, category, threatLevel, vulid, limitid, name, date, cve, cncve, cnnvd, detaile_name) '
            val = "values('{0}', '{1}', '{2}', '{3}', '', '', '{4}', '{5}', '{6}', '{7}', '{8}', '', '{9}', '{10}');".format(tempname, tempid, valname, val, vulid, level, name, date, cve, cnnvd, detaile_name)
            sql = sql + val
            #print(sql)
            conn.execute(sql)
            if sqlcnt == 30:
                print('[+] commit sqlite success...')
                conn.commit()
                sqlcnt = 0
        except Exception as e:
            print('WRITE SQLITE ERROR:', str(e))
            try:
                if sql:
                    with codecs.open('sqlinfo.txt', 'a+', 'utf-8') as w:
                        w.write(sql + '\n')
            except Exception as e:
                pass
            break
    
    conn.commit()
    conn.close()
    
    print("[+] finished handle data into sqlite pid :{0} ....".format(os.getpid()))

def crawl_cve_info(cve_info_queue, sqllite_queue):

    print("[+] start crawl cve info pid :{0} ....".format(os.getpid()))
    
    with codecs.open('pid.txt', 'a+', 'utf-8') as w:
        w.write('crawl_cve_info:' +str(os.getpid())+ '\n')

    while True:
        try:
            vul_id_info = cve_info_queue.get(timeout = 120)  
            if vul_id_info:
                print('[+] get vuln id info success...')
                
                keys_list = vul_id_info.keys()
                
                for key in keys_list:
                    if key != 'type':
                        temp_id_key = key
                    else:
                        type_key = key
                
                type = vul_id_info[type_key]
                
                generator = (x for x in vul_id_info[temp_id_key])
                
                request_cnt = 0
                
                for item in generator:
                    
                    request_cnt += 1
                    
                    if request_cnt == 5:
                        #time.sleep(3)
                        request_cnt = 0
                    
                    vul_id = item[0]
                    name = item[1].strip()
                    level = item[2]
                    detaile_name = item[3].strip()
                    cve_url = 'https://ip/template/show_vul_desc?id={0}'.format(vul_id)
                    #print(cve_url)
                    
                    #request for 4 times
                    response = None
                    
                    try:
                        requests.adapters.DEFAULT_RETRIES = 4
                        s = requests.session()
                        #s.keep_alive = False
                        response = s.get(cve_url, headers=headers, timeout=60, verify=False)
                        #time.sleep(0.5)
                        parser = CVE_INFO_PARSER()
                        parser.feed(response.text)
                        cve_info_dict = parser.return_info()
                        cve_info_list = list()
                        name = name.replace('\'', '\"')
                        cve_info_list.append(tmp_name[temp_id_key])
                        cve_info_list.append(temp_id_key)
                        cve_info_list.append(val_name[type])
                        cve_info_list.append(type)
                        cve_info_list.append(vul_id)
                        cve_info_list.append(name)
                        cve_info_list.append(cve_info_dict['date'])
                        cve = cve_info_dict['cve'].replace('\'', '\"')
                        cve_info_list.append(cve)
                        cnnvd = cve_info_dict['cnnvd'].replace('\'', '\"')
                        cve_info_list.append(cnnvd)
                        cve_info_list.append(level)
                        cve_info_list.append(detaile_name)
                        #print(cve_info_list)
                        sqllite_queue.put(cve_info_list)
                        
                        #close()
                        response.close()
                        s.close()
                        del(response)
                    except :
                        print ("[-] crawl_cve_info request error:", str(e))
                        try:
                            with codecs.open('crawl_cve_info.txt', 'a+', 'utf-8') as w:
                                w.write(str(type) + '\t'+ str(temp_id_key) + '\t' + str(item[2]) + '\t' + cve_url + '\n')
                        except Exception as e:
                            pass
                        continue
                    
        except Exception as e:
            print("[+] finished crawl cve info pid :{0} ....".format(os.getpid()))
            break

def crawl_vulid(thread_level_queue, cve_info_queue):
    
    print("[+] start crawl vuln id pid :{0} ....".format(os.getpid()))
    
    with codecs.open('pid.txt', 'a+', 'utf-8') as w:
        w.write('crawl_vulid:' +str(os.getpid())+ '\n')
    
    while True:
        try:
            vul_id_info = thread_level_queue.get(timeout = 120)
            #print(vul_id_info)
            
            if vul_id_info:
                print("[+] get thread level info success...")
                
                keys_list = vul_id_info.keys()
                
                for key in keys_list:
                    if key != 'type':
                        temp_id_key = key
                    else:
                        type_key = key
                
                type = vul_id_info[type_key]
                
                generator = (x for x in vul_id_info[temp_id_key])
                
                request_cnt = 0
                
                for tup_id in generator:
                    
                    request_cnt += 1
                    
                    if request_cnt == 5:
                        #time.sleep(3)
                        request_cnt = 0
                    
                    id = tup_id[0]
                    level = tup_id[1]
                    name = tup_id[2]
                    
                    vul_id_url = 'https://ip/template/getTreeHtml?val={0}&temp_id={1}&conditions=is_dangerous=&op_type=showStemp&&checked=true&id={2}&offset=0&limit={3}'.format(type, temp_id_key, id, level)
                    #print(vul_id_url)
                    
                    response = None
                    try:
                        requests.adapters.DEFAULT_RETRIES = 4
                        s = requests.session()
                        #s.keep_alive = False
                        response = s.get(vul_id_url, headers=headers, timeout=60, verify=False)
                        #time.sleep(0.5)
                        parse = MyHtmlParser(temp_id_key, type, 'vul_id', level, name)
                        parse.feed(response.text)
                        thread_leve = parse.return_info()
                        #print(thread_leve)
                        cve_info_queue.put(thread_leve)
                        response.close()
                        s.close()
                        del(response)
                        
                    except:
                        print ("[-] crawl_vulid request error:", str(e))
                        try:
                            with codecs.open('crawl_vulid.txt', 'a+', 'utf-8') as w:
                                w.write(str(type) + '\t'+ str(temp_id_key) + '\t'+ str(id) + '\t'+ str(level) + '\t'+ vul_id_url + '\n')
                        except Exception as e:
                            pass
                        
                        continue

        except Exception as e:
            print("[+] finished crawl vuln id pid :{0} ....".format(os.getpid()))
            break

def crawl_thread_level(catgory_queue, thread_level_queue):
    
    print("[+] start crawl thread_level pid :{0} ....".format(os.getpid()))
    
    with codecs.open('pid.txt', 'a+', 'utf-8') as w:
        w.write('crawl_thread_level:' +str(os.getpid())+ '\n')

    while True:
        try:
            type = ''
            temp_id = ''
            info = catgory_queue.get(timeout = 120)
            #print(info)
            if info:
                print("[+] get catgory info success...")
                
                keys_list = info.keys()
                for key in keys_list:
                    
                    if key != 'type':
                        temp_id = key
                    else:
                        type = key
                
                type = info[type]
                
                generator = (x for x in info[temp_id])
                
                request_cnt = 0
                
                for item in generator:
                    
                    request_cnt += 1
                    
                    id = item[0]
                    name = item[1]
                    
                    if request_cnt == 5:
                        #time.sleep(3)
                        request_cnt = 0
                
                    response = None
                    thread_lelev_url = 'https://ip/template/getTreeHtml?val={0}&temp_id={1}&conditions=is_dangerous=&op_type=showStemp&&checked=true&id={2}&offset=0&limit=3'.format(type, temp_id, id)
                    #print(thread_lelev_url)
                    
                    try:
                        requests.adapters.DEFAULT_RETRIES = 4
                        s = requests.session()
                        #s.keep_alive = False
                        response = s.get(thread_lelev_url, headers=headers, timeout=60, verify=False)
                        #time.sleep(0.5)
                        parse = MyHtmlParser(temp_id, type, 'thread_level', '', name)
                        parse.feed(response.text)
                        thread_leve = parse.return_info()
                        #print(thread_leve)
                        thread_level_queue.put(thread_leve)
                        
                        response.close()
                        s.close()
                        del(response)
                    except:
                        print ("[-] crawl_thread_level request error:", str(e))
                        try:
                            with codecs.open('crawl_thread_level.txt', 'a+', 'utf-8') as w:
                                w.write(str(type) + '\t'+ str(temp_id) + '\t'+ str(id) + '\t' + thread_lelev_url + '\n')
                        except Exception as e:
                            pass
                        
                        continue
        
        except Exception as e:
            print("[+] finished crawl thread_level pid :{0} ....".format(os.getpid()))
            break
            
def crawl_catgroy(queue, tempids, vals):
    
    print("[+] start crawl catgroy pid :{0} ....".format(os.getpid()))
    
    with codecs.open('pid.txt', 'a+', 'utf-8') as w:
        w.write('crawl_catgroy:' +str(os.getpid())+ '\n')
    
    reqcnt = 0
    
    for item_tmpid in tempids:
        for item_val in vals:
            
            reqcnt += 1
            
            if reqcnt == 5:
                #time.sleep(3)
                reqcnt = 0
            
            url = 'https://ip/template/getTreeHtml?val={0}&temp_id={1}&conditions=is_dangerous=&op_type=showStemp&'.format(item_val, item_tmpid)
            
            try:
                requests.adapters.DEFAULT_RETRIES = 4
                s = requests.session()
                #s.keep_alive = False
                response = s.get(url, headers=headers, timeout=60, verify=False)
                #time.sleep(0.5)
                par = MyHtmlParser(item_tmpid, item_val, 'catgory', '', '')
                par.feed(response.text)
                info = par.return_info()
                queue.put(info)
                
                #close
                response.close()
                s.close()
                del(response)
            except :
                print ("[-] crawl_catgroy request error:", str(e))
                try:
                    with codecs.open('crawl_catgroy.txt', 'a+', 'utf-8') as w:
                        w.write(str(e) + '\t' + url + '\n')
                except Exception as e:
                    pass
                    
                continue
                
    print("[+] finished crawl catgroy pid :{0} ....".format(os.getpid()))


def usage():
    print('Usage:')
    print('\t -h|--host    Crawling host for request')
    print('\t -p|--port    Crawling port for request')
    #print('\t -u|--url     Crawling url')
    print('\t -a|--agent   Crawling use user-agent')
    print('\t -c|--cookie  Crawling cookie for request')
    print('\t -v|--version Crawling version')
    print('\t -t|--type    ')


def version():
    print('NSFOCUS Crawling BUG model 0.1')

if __name__ == '__main__':
    '''
    opts,args = getopt.getopt(sys.argv[1:],'-h:-p:-a:-c:-f:-v',['host','port', 'agent', 'cookie', 'file', 'version'])
    
    host = ''; port = 443; agent = DEFAULT_USER_AGENT;
    
    for opt_name,opt_value in opts:
        if opt_name in ('-h', '--host'):
            host = opt_value
        elif opt_name in ('-p', '--port'):
            port = opt_value
        elif opt_name in ('-a', '--agent'):
            agent = opt_value
        elif opt_name in ('-c', '--cookie'):
            cookie = opt_value
        elif opt_name in ('-f', '--file'):
            filename = opt_value
    '''
    
    #add process manager
    manager = multiprocessing.Manager()
    
    #add manager share queue 
    catgory_queue = manager.Queue()
    
    #get cpu count to init process
    cpu_cnt = multiprocessing.cpu_count()
    
    #init process poll by core
    pool = multiprocessing.Pool(processes = cpu_cnt)
    
    
    #handle catgory data
    catgory_queue = multiprocessing.Queue()
    craw_cat = multiprocessing.Process(target=crawl_catgroy, args=(catgory_queue, tmpid_proc1, val, ))
    #craw_cat = multiprocessing.Process(target=crawl_catgroy, args=(catgory_queue, [1, ], ['System'], ))
    craw_cat.start()
    
    #handle thread_level data
    thread_level_queue = multiprocessing.Queue()
    craw_thread = multiprocessing.Process(target=crawl_thread_level, args=(catgory_queue, thread_level_queue, ))
    craw_thread.start()
    craw_thread1 = multiprocessing.Process(target=crawl_thread_level, args=(catgory_queue, thread_level_queue, ))
    craw_thread1.start()
    craw_thread2 = multiprocessing.Process(target=crawl_thread_level, args=(catgory_queue, thread_level_queue, ))
    craw_thread2.start()


    #handle vul id data
    cve_info_queue = multiprocessing.Queue()
    craw_vulid = multiprocessing.Process(target=crawl_vulid, args=(thread_level_queue, cve_info_queue, ))
    craw_vulid.start()
    craw_vulid1 = multiprocessing.Process(target=crawl_vulid, args=(thread_level_queue, cve_info_queue, ))
    craw_vulid1.start()
    craw_vulid2 = multiprocessing.Process(target=crawl_vulid, args=(thread_level_queue, cve_info_queue, ))
    craw_vulid2.start()
    craw_vulid3 = multiprocessing.Process(target=crawl_vulid, args=(thread_level_queue, cve_info_queue, ))
    craw_vulid3.start()
    craw_vulid4 = multiprocessing.Process(target=crawl_vulid, args=(thread_level_queue, cve_info_queue, ))
    craw_vulid4.start()
    
    #handle cve_info
    sqllite_queue = multiprocessing.Queue()
    crawl_cve = multiprocessing.Process(target=crawl_cve_info, args=(cve_info_queue, sqllite_queue, ))
    crawl_cve.start()
    crawl_cve1 = multiprocessing.Process(target=crawl_cve_info, args=(cve_info_queue, sqllite_queue, ))
    crawl_cve1.start()
    crawl_cve2 = multiprocessing.Process(target=crawl_cve_info, args=(cve_info_queue, sqllite_queue, ))
    crawl_cve2.start()
    crawl_cve3 = multiprocessing.Process(target=crawl_cve_info, args=(cve_info_queue, sqllite_queue, ))
    crawl_cve3.start()
    crawl_cve4 = multiprocessing.Process(target=crawl_cve_info, args=(cve_info_queue, sqllite_queue, ))
    crawl_cve4.start()
    crawl_cve5 = multiprocessing.Process(target=crawl_cve_info, args=(cve_info_queue, sqllite_queue, ))
    crawl_cve5.start()
    crawl_cve6 = multiprocessing.Process(target=crawl_cve_info, args=(cve_info_queue, sqllite_queue, ))
    crawl_cve6.start()
    crawl_cve7 = multiprocessing.Process(target=crawl_cve_info, args=(cve_info_queue, sqllite_queue, ))
    crawl_cve7.start()
    crawl_cve8 = multiprocessing.Process(target=crawl_cve_info, args=(cve_info_queue, sqllite_queue, ))
    crawl_cve8.start()
    crawl_cve9 = multiprocessing.Process(target=crawl_cve_info, args=(cve_info_queue, sqllite_queue, ))
    crawl_cve9.start()
    crawl_cve10 = multiprocessing.Process(target=crawl_cve_info, args=(cve_info_queue, sqllite_queue, ))
    crawl_cve10.start()


    #handle sqlite info
    sqlite_hd = multiprocessing.Process(target=data_into_sqlite, args=(sqllite_queue, ))
    sqlite_hd.start()
    
    #wait for catgory
    craw_cat.join()
    
    #wait for thread level
    craw_thread.join()
    craw_thread1.join()
    craw_thread2.join()
    
    #wait for vulid crawl
    craw_vulid.join()
    craw_vulid1.join()
    craw_vulid2.join()
    craw_vulid3.join()
    craw_vulid4.join()
    
    #wait for cve info crawl
    crawl_cve.join()
    crawl_cve1.join()
    crawl_cve2.join()
    crawl_cve3.join()
    crawl_cve4.join()
    crawl_cve5.join()
    crawl_cve6.join()
    crawl_cve7.join()
    crawl_cve8.join()
    crawl_cve9.join()
    crawl_cve10.join()
    
    #sqlite join
    sqlite_hd.join()
    
