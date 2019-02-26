from honeygrove.tests.testresources import testconfig as config
from honeygrove.tests.testresources.honeyadaptertest import incoming_messages as messages, outgoing_messages as answers
from honeygrove.tests.testresources.honeyadaptertest.DummyAdapter import BrokerEndpoint, DummyAdapter as HoneyAdapter

import mock
import os
from os.path import join, isfile
import unittest


class HoneyAdapter_Test(unittest.TestCase):
    def setUp(self):
        self.adapter = HoneyAdapter()
        self.patch = mock.patch.object(BrokerEndpoint, 'sendMessageToTopic')
        self.patched = self.patch.start()

    def test_ping(self):
        msg = messages.msg_ping
        self.adapter.handle_messages([[msg]])
        self.patched.assert_called_with('answer', answers.answ_ping)

    def test_getAllServices(self):
        msg = messages.msg_get_all_services_id
        self.adapter.handle_messages([[msg]])
        self.assertTrue(self.patched.call_count == 1)
        msg = messages.msg_get_all_services_all
        self.adapter.handle_messages([[msg]])
        self.assertTrue(self.patched.call_count == 2)

    def test_startServices(self):
        msg = messages.msg_start_services
        self.adapter.handle_messages([[msg]])
        self.patched.assert_called_with('answer', answers.answ_started_services)

    def test_stopServices(self):
        msg = messages.msg_stop_services
        self.adapter.handle_messages([[msg]])
        self.patched.assert_called_with('answer', answers.answ_stopped_services)

    def test_getSettings(self):
        msg = messages.msg_get_settings
        self.adapter.handle_messages([[msg]])
        self.patched.assert_called_with('answer', answers.answ_get_settings)

    def test_set_filesys(self):
        msg = messages.msg_set_filesys
        self.adapter.handle_messages([[msg]])
        self.patched.assert_called_with('answer', answers.answ_set_filesys)

        msg = messages.msg_set_invalid_1_filesys
        self.adapter.handle_messages([[msg]])
        self.patched.assert_called_with('answer', answers.answ_set_invalid_filesys)

        msg = messages.msg_set_invalid_2_filesys
        self.adapter.handle_messages([[msg]])
        self.patched.assert_called_with('answer', answers.answ_set_invalid_filesys)

    def test_get_filesys(self):
        msg = messages.msg_get_filesys
        self.adapter.handle_messages([[msg]])
        self.patched.assert_called_with('answer', answers.answ_get_filesys)

    def test_getTokenFiles(self):
        addTokenFile("suspicious_data.txt", "a:b:c:d")
        addTokenFile("mytoken", "sometoken")
        msg = messages.msg_get_token_files
        self.adapter.handle_messages([[msg]])
        self.assertTrue(self.patched.call_count == 1)
        removenTokenFile("suspicious_data.txt")
        removenTokenFile("mytoken")

    def test_AddTokenFile(self):
        filepath = config.tokendir_adapter + '/new_token.txt'

        # Case 1: Non Existent File
        msg = messages.msg_add_token_file
        self.adapter.handle_messages([[msg]])
        self.patched.assert_called_with('answer', answers.answ_add_token_file)
        with open(filepath) as f:
            s = f.read()
        self.assertEqual(s, "File as String")

        # Case 2: Existent File
        msg = messages.msg_add_token_file_existent
        self.adapter.handle_messages([[msg]])
        self.patched.assert_called_with('answer', answers.answ_add_token_file)
        with open(filepath) as f:
            s = f.read()
        self.assertEqual(s, "New File as String")
        removenTokenFile("new_token.txt")

    def test_RemoveTokenFile(self):
        # Case 1: Specific Files
        addTokenFile("tf1", "Content")
        addTokenFile("tf2", "Content")
        msg = messages.msg_rem_token_files
        self.adapter.handle_messages([[msg]])
        self.patched.assert_called_with('answer', answers.answ_remove_token_file)
        # Make sure they are deleted
        self.assertFalse(isfile(join(config.tokendir_adapter, "tf1")))
        self.assertFalse(isfile(join(config.tokendir_adapter, "tf2")))

        # Case 2: All Files
        addTokenFile("tf3", "Content")
        msg = messages.msg_rem_all_token_files
        self.adapter.handle_messages([[msg]])
        # Make sure everything is deleted
        self.assertFalse(os.listdir(config.tokendir_adapter))

        # directory stays trackable
        addTokenFile("afile", " ")

    def test_setSettings(self):
        # CASE 1: Service Not Running
        old_tokenprob = config.honeytokendbProbabilities['LISTEN']
        msg = messages.msg_set_settings
        self.adapter.handle_messages([[msg]])
        # Correct Answer Was Sent
        self.patched.assert_called_with('answer', answers.answ_set_settings)
        # New Token Probability Was Set
        self.assertTrue(config.honeytokendbProbabilities['LISTEN'] != old_tokenprob)
        # New Port Was Set
        service = self.adapter.controller.serviceDict['LISTEN']
        new_ports = service._port
        self.assertEqual(new_ports, [9, 8, 7])

        # CASE 2: Service Running
        old_tokenprob = config.honeytokendbProbabilities['TESTSERVICEB']
        msg = messages.msg_set_settings_run
        self.adapter.handle_messages([[msg]])
        # Correct Answer Was Sent (Included Port)
        self.patched.assert_called_with('answer', answers.answ_set_settings_run)
        # New Token Probability Was Set
        self.assertTrue(config.honeytokendbProbabilities['TESTSERVICEB'] != old_tokenprob)


def addTokenFile(name, content):
    path = join(config.tokendir_adapter, name)
    with open(path, 'w+') as file:
        file.write(content)


def removenTokenFile(name):
    os.remove(join(config.tokendir_adapter, name))
