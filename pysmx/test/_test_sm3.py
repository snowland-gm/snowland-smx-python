#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author: 深圳星河软通科技有限公司 A.Star
# @contact: astar@snowland.ltd
# @site: www.astar.ltd
# @file: _test_sm3 .py
# @time: 2020/11/7 23:04
# @Software: PyCharm


# from astartool.random import random_string
import unittest


class TestSM3(unittest.TestCase):

    def setUp(self):
        from pysmx.SM3 import hexdigest
        from pysmx.crypto import hashlib
        self.hashlib = hashlib
        self.hexdigest = hexdigest

    def test_digest_rand10000(self):
        """
        测试1000个随机数
        :return:
        """
        # s = random_string(1000)
        s = '2SXgayxQt2Wgac7yUFih4Bek0LZWsDEbQhozpl3Vlhm2wusUOtvtj7v6DshKfwakChA2uQbOM7gUZBWtZqRhhTwWlxDXfVbgxzglGaY6KTZmXjcxHqOwUcATPV0WAafhNbhz39jmQ9XYoEBNTt23NG8CXEIVKv8Y9artQn0RIkQ7USDZXXmv2vyanpDdSImk5tUePf7q276xi4qk4mo0xT67e4DUvGyNyWjFwWDMrLKGZiqY8NjXwrtU0zk9y4QX7rqe7voIrrnziQcVEouwpnqnJfhO76h6zVHI7iveNXhnZGbpKgm0AwgzyU1GPqXYBpGr6mOkBL4VpxgrXkQvgSWbPyssCJ4yL2ciyRDYGuXg0eKiyTRRCEBYRTOwMww2uNbtet975Aq9IpU218PLHfCJQFZPtExY6dXDRAThORSygSechsMrGelB65XP22gkRdseHazhgji9bUe7J3ubxPDvd7OIE2H6YjQh5cB89PGxHer7nU4mwtkz7B9F0rNpiJfDYXgZsbVm2Tkn7u9HnBBElc6WBHbuUhX8bHKqxL76MSaRErgJNrhGxKxRBbZfUB1GAzBiaDd6xRQ20PMG0QnNImyhtFirHe9ao3B6y2DbQbP3UUdvUbDqXRcp7GNJmgeFWpMMNGi8w47PqF9084cqeJk07tq5ag5e4sKbglet9IrYJPmVgJ8iuxD15kPO0d409tQmhVKS3Mf2gwMIYjaqeJJFke3BVtOqrY56Uwd2UTMTrlaPZTCCBAAjtUSNeQFUEfzGHb9g03Dut1U1LQ024yqZv9OwwtaOQAVLH6yU0jCjL2wX95FkJOGOzBJUYWz1E5Vsm2tOQPtJ4qtJ7wjKoL0lEiDh6yFCcmhV6jxFlr4kQVqQrcVRbGvx4VFq2XgY9NeFo2x7ehZjHV6eZdSj0282MpfXzSN83nkHjy86i7Wmnbr4EHSlsjTjmPAHuK7nLhiGy48bi3qxRcCYcB7YKtaPsmMA1AL34wdI'
        print(s)
        sm3 = self.hashlib.SM3Type()
        sm3.update(s)
        h = sm3.digest()
        from pysmx.SM3._SM3 import digest
        print(digest(s))
        print(h)
        self.assertEquals(digest(s), h)

    def test_update_rand10000(self):
        """
        测试1000个随机数
        :return:
        """
        # s = random_string(1000)
        s = '2SXgayxQt2Wgac7yUFih4Bek0LZWsDEbQhozpl3Vlhm2wusUOtvtj7v6DshKfwakChA2uQbOM7gUZBWtZqRhhTwWlxDXfVbgxzglGaY6KTZmXjcxHqOwUcATPV0WAafhNbhz39jmQ9XYoEBNTt23NG8CXEIVKv8Y9artQn0RIkQ7USDZXXmv2vyanpDdSImk5tUePf7q276xi4qk4mo0xT67e4DUvGyNyWjFwWDMrLKGZiqY8NjXwrtU0zk9y4QX7rqe7voIrrnziQcVEouwpnqnJfhO76h6zVHI7iveNXhnZGbpKgm0AwgzyU1GPqXYBpGr6mOkBL4VpxgrXkQvgSWbPyssCJ4yL2ciyRDYGuXg0eKiyTRRCEBYRTOwMww2uNbtet975Aq9IpU218PLHfCJQFZPtExY6dXDRAThORSygSechsMrGelB65XP22gkRdseHazhgji9bUe7J3ubxPDvd7OIE2H6YjQh5cB89PGxHer7nU4mwtkz7B9F0rNpiJfDYXgZsbVm2Tkn7u9HnBBElc6WBHbuUhX8bHKqxL76MSaRErgJNrhGxKxRBbZfUB1GAzBiaDd6xRQ20PMG0QnNImyhtFirHe9ao3B6y2DbQbP3UUdvUbDqXRcp7GNJmgeFWpMMNGi8w47PqF9084cqeJk07tq5ag5e4sKbglet9IrYJPmVgJ8iuxD15kPO0d409tQmhVKS3Mf2gwMIYjaqeJJFke3BVtOqrY56Uwd2UTMTrlaPZTCCBAAjtUSNeQFUEfzGHb9g03Dut1U1LQ024yqZv9OwwtaOQAVLH6yU0jCjL2wX95FkJOGOzBJUYWz1E5Vsm2tOQPtJ4qtJ7wjKoL0lEiDh6yFCcmhV6jxFlr4kQVqQrcVRbGvx4VFq2XgY9NeFo2x7ehZjHV6eZdSj0282MpfXzSN83nkHjy86i7Wmnbr4EHSlsjTjmPAHuK7nLhiGy48bi3qxRcCYcB7YKtaPsmMA1AL34wdI'
        print(s)
        len_s = len(s)
        sm3 = self.hashlib.SM3Type()
        for i in range(0, len_s, 10):
            sm3.update(s[i:i + 10])
        h = sm3.hexdigest()
        from pysmx.SM3._SM3 import digest, hexdigest
        hex = hexdigest(s)
        print("hexdigest:", hex)
        print("sm3 type:", h)
        assert hex == h

    def test_rand_abc(self):
        """
        测试"abc"
        :return:
        """
        s = "abc"
        sm3 = self.hashlib.SM3Type()
        sm3.update(s)
        h = sm3.hexdigest()
        print(h)
        h2 = self.hexdigest(s)
        self.assertEquals(h, h2)

    def test_update_abc(self):
        """
        测试"abc" update
        :return:
        """
        s = "a"
        sm3 = self.hashlib.SM3Type()
        sm3.update(s)
        sm3.update("bc")
        h = sm3.hexdigest()
        print(h)


if '__main__' == __name__:
    from pysmx.SM3 import hexdigest
    from pysmx.crypto import hashlib
    from pysmx.SM3._SM3 import digest

    s = '2SXgayxQt2Wgac7yUFih4Bek0LZWsDEbQhozpl3Vlhm2wusUOtvtj7v6DshKfwakChA2uQbOM7gUZBWtZqRhhTwWlxDXfVbgxzglGaY6KTZmXjcxHqOwUcATPV0WAafhNbhz39jmQ9XYoEBNTt23NG8CXEIVKv8Y9artQn0RIkQ7USDZXXmv2vyanpDdSImk5tUePf7q276xi4qk4mo0xT67e4DUvGyNyWjFwWDMrLKGZiqY8NjXwrtU0zk9y4QX7rqe7voIrrnziQcVEouwpnqnJfhO76h6zVHI7iveNXhnZGbpKgm0AwgzyU1GPqXYBpGr6mOkBL4VpxgrXkQvgSWbPyssCJ4yL2ciyRDYGuXg0eKiyTRRCEBYRTOwMww2uNbtet975Aq9IpU218PLHfCJQFZPtExY6dXDRAThORSygSechsMrGelB65XP22gkRdseHazhgji9bUe7J3ubxPDvd7OIE2H6YjQh5cB89PGxHer7nU4mwtkz7B9F0rNpiJfDYXgZsbVm2Tkn7u9HnBBElc6WBHbuUhX8bHKqxL76MSaRErgJNrhGxKxRBbZfUB1GAzBiaDd6xRQ20PMG0QnNImyhtFirHe9ao3B6y2DbQbP3UUdvUbDqXRcp7GNJmgeFWpMMNGi8w47PqF9084cqeJk07tq5ag5e4sKbglet9IrYJPmVgJ8iuxD15kPO0d409tQmhVKS3Mf2gwMIYjaqeJJFke3BVtOqrY56Uwd2UTMTrlaPZTCCBAAjtUSNeQFUEfzGHb9g03Dut1U1LQ024yqZv9OwwtaOQAVLH6yU0jCjL2wX95FkJOGOzBJUYWz1E5Vsm2tOQPtJ4qtJ7wjKoL0lEiDh6yFCcmhV6jxFlr4kQVqQrcVRbGvx4VFq2XgY9NeFo2x7ehZjHV6eZdSj0282MpfXzSN83nkHjy86i7Wmnbr4EHSlsjTjmPAHuK7nLhiGy48bi3qxRcCYcB7YKtaPsmMA1AL34wdI'
    print(s)
    len_s = len(s)
    sm3 = hashlib.SM3Type()
    for i in range(0, len_s, 10):
        sm3.update(s[i:i + 10])
    h = sm3.digest()
    print("digest:", digest(s))
    print("sm3 type:", h)
    assert digest(s) == h
