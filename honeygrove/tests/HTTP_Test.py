import unittest
import requests
import time
import threading
from honeygrove.services.HTTPService import HTTPService
from honeygrove import config
from twisted.internet import reactor
class HTTPTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        config.httpPort = 9914
        threading.Thread(target=reactor.run, args=(False,)).start()
        HTTPTest.httpInstance = HTTPService()
        HTTPTest.httpInstance.startService()

    @classmethod
    def tearDownClass(cls):
        reactor.callFromThread(reactor.stop)


    def testGET(self):
        """
        Test Get Method
        """
        response = requests.get("http://localhost:9914")
        self.assertEqual(response.status_code, 200)

    def testPost(self):
        """
        Test Post Method
        """
        response = requests.post("http://localhost:9914", data={"pwd":123})
        self.assertIn(response.status_code, [200, 403])
