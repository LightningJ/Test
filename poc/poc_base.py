#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
core.poc
"""
import logging
import types
import re
import ast
from requests.exceptions import ConnectTimeout
from requests.exceptions import ConnectionError
from requests.exceptions import HTTPError
from requests.exceptions import TooManyRedirects

logger = logging.getLogger(__name__)


class ERROR_TYPE_ID:
    NOTIMPLEMENTEDERROR = 2000
    CONNECTIONERROR = 3000
    HTTPERROR = 3001
    CONNECTTIMEOUT = 3002
    TOOMANYREDIRECTS = 3003
    OTHER = 4000


class POCBase(object):
    def __init__(self):
        self.target = None
        self.url = None
        self.mode = None
        self.params = None
        self.verbose = None

    def parse_target_url(self, url):
        """
        Parse target URL
        """
        ret_val = url

        if not re.search("^http[s]*://", ret_val, re.I) and not re.search(
                "^ws[s]*://", ret_val, re.I):
            if re.search(":443[/]*$", ret_val):
                retVal = "https://" + ret_val
            else:
                retVal = "http://" + ret_val

        return ret_val

    def execute(self, target=None, method=None, headers=None, params=None, mode='verify',
                verbose=True):
        """
        :param url: the target url
        :param headers: a :class dict include some fields for request header.
        :param params: a instance of Params, include extra params3

        :return: output
        """
        self.target = target
        self.url = self.parse_target_url(target)
        # self.header=headers
        self.method = method
        self.params = ast.literal_eval(params) if params else {}
        self.mode = mode
        self.verbose = verbose
        self.expt = (0, 'None')
        output = None
        # conf.retry
        retry = 5
        # TODO
        try:
            output = self._verify()
        except NotImplementedError as e:
            self.expt = (ERROR_TYPE_ID.NOTIMPLEMENTEDERROR, e)
            logger.error(
                'POC: %s not defined ' '%s mode' % (self.name, self.mode))
            output = Output(self)
        except ConnectTimeout as e:
            self.expt = (ERROR_TYPE_ID.CONNECTTIMEOUT, e)
            while retry > 0:
                logger.warning('POC: %s timeout, start it over.' % self.name)
                try:
                    if self.mode == 'attack':
                        output = self._attack()
                    else:
                        output = self._verify()
                    break
                except ConnectTimeout:
                    logger.error('POC: %s time-out retry failed!' % self.name)
                    output = Output(self)
                retry -= 1
            else:
                logger.error(str(e))
                output = Output(self)

        except HTTPError as e:
            self.expt = (ERROR_TYPE_ID.HTTPERROR, e)
            logger.warning(
                'POC: %s HTTPError occurs, start it over.' % self.name)
            output = Output(self)
        except ConnectionError as e:
            self.expt = (ERROR_TYPE_ID.CONNECTIONERROR, e)
            logger.error(str(e))
            output = Output(self)
        except TooManyRedirects as e:
            self.expt = (ERROR_TYPE_ID.TOOMANYREDIRECTS, e)
            logger.error(str(e))
            output = Output(self)
        except Exception as e:
            self.expt = (ERROR_TYPE_ID.OTHER, e)
            logger.error(str(e))
            output = Output(self)
        return output

    # 子类必须重写这个方法
    def _verify(self):
        """
        @function   以Poc的verify模式对urls进行检测(可能具有危险性)
                    需要在用户自定义的Poc中进行重写
                    返回一个Output类实例
        """
        raise NotImplementedError


class Output(object):
    ''' output of pocs
    Usage::
        >>> poc = POCBase()
        >>> output = Output(poc)
        >>> result = {'FileInfo': ''}
        >>> output.success(result)
        >>> output.fail('Some reason failed or errors')
    '''

    def __init__(self, poc=None):
        self.error = tuple()
        self.result = {}
        self.status = 1  # 失败
        if poc:
            self.url = poc.url
            self.mode = poc.mode
            self.CHvulID = poc.CHvulID
            self.name = poc.name
            self.componentsName = poc.componentsName
            self.componentsVersion = poc.componentsVersion
            self.error = poc.expt

    def is_success(self):
        return bool(True and self.status)

    def success(self, result):
        assert isinstance(result, types.DictType)
        self.status = 0  # 成功
        self.result = result

    def fail(self, error=""):
        self.status = 1  # 失败
        assert isinstance(error, types.StringType)
        self.error = (0, error)

    def error(self, error=""):
        self.expt = (ERROR_TYPE_ID.OTHER, error)
        self.error = (0, error)

    def show_result(self):
        if self.status == 0:
            infoMsg = "poc-%s '%s' has already been detected against '%s'." % (
                self.CHvulID, self.name, self.url)
            logger.info(infoMsg)
            return {'code': self.status, 'msg': self.result}
        else:
            errMsg = "poc-%s '%s' failed." % (self.CHvulID, self.name)
            logger.info(errMsg)
            return {'code': self.status, 'msg': self.error[1]}


if __name__ == '__main__':
    print "hello"
