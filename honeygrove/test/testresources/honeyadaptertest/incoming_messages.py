from honeygrove.tests.testresources import testconfig as cf
import json

msg_ping = '{"type": "ping", "to": ["ALL"], "from": "managementconsole"}'

msg_get_all_services_all = '{"type": "get_all_services", "from": "managementconsole", "to": ["ALL"]}'
msg_get_all_services_id = '{"type": "get_all_services", "from": "managementconsole", "to": ["' + str(cf.HPID) + '"]}'

msg_start_services = '{"type": "start_services", "from": "managemenconsole", "to": ["1", "2", "3", "' + str(
    cf.HPID) + '" ], "services": ["TESTSERVICEA"]}'

msg_stop_services = '{"type": "stop_services", "from": "managemenconsole", "to": ["1", "2", "3", "' + str(
    cf.HPID) + '" ], "services": ["TESTSERVICEB"]}'

msg_get_settings = '{"type": "get_settings", "from": "managementconsole", "to": ["1", "2", "3", "' + str(
    cf.HPID) + '\" ], "service": "TESTSERVICEA" }'

msg_get_listen_settings = '{"type": "get_settings", "from": "managementconsole", "to": ["1", "2", "3", "' + str(
    cf.HPID) + '\" ], "service": "LISTEN" }'

msg_set_settings = '{"type": "set_settings", "from": "managementconsole", "to": ["1", "2", "3", "' + str(
    cf.HPID) + '" ], "settings": {"service": "LISTEN", "ports": [9,8,7], "token_probability": 0.9}}'

msg_set_settings_run = '{"type": "set_settings", "from": "managementconsole", "to": ["1", "2", "3", "' + str(
    cf.HPID) + '" ], "settings": {"service": "TESTSERVICEB", "ports": [7], "token_probability": 1}}'

msg_get_html_pages = '{"type": "get_html_pages", "from": "managementconsole", "to": "' + str(cf.HPID) + '"}'

msg_add_html = '{"type": "add_html", "from": "managementconsole", "to": "' + str(
    cf.HPID) + '", "page": { "url": "/abc", "html": "<h1>Title</h1>", "dashboard": "<p>Hey</p>" } }'

msg_remove_html = '{"type": "remove_html", "from": "managementconsole", "to": "' + str(
    cf.HPID) + '", "urls": ["/abc1", "/abc2"] }'
msg_remove_all_html = '{"type": "remove_html", "from": "managementconsole", "to": "' + str(
    cf.HPID) + '", "urls": ["ALL"] }'

msg_get_cred = '{"type": "get_credentials", "from": "managementconsole", "to": "' + str(cf.HPID) + '"}'
msg_set_cred = '{"type": "set_credentials", "from": "managementconsole", "to": "' + str(
    cf.HPID) + '", "file": "SSH,HTTP,FTP:neu1:pw1\\nSSH,HTTP,FTP:alex:\\n" }'

msg_get_filesys = '{"type": "get_filesystem_xml", "from": "managementconsole", "to": "' + str(cf.HPID) + '"}'
msg_set_filesys = '{"type": "set_filesystem_xml", "from": "managementconsole", "to": "' + str(
    cf.HPID) + '", "file": "<!--4, 0-->\\n<dir name=\\"neuer\\">\\n\\t<dir name=\\"sub1\\"\\/>\\n\\t<dir name=\\"sub2\\">\\n\\t\\t<file name=\\"hi.txt\\"\\/>\\n\\t<\\/dir>\\n\\t<dir name=\\"sub3\\"\\/>\\n<\\/dir>" }'

msg_set_invalid_1_filesys = '{"type": "set_filesystem_xml", "from": "managementconsole", "to": "' + str(
    cf.HPID) + '", "file": "<!--4, 0-->\\n<dor name=\\"neuer\\">\\n\\t<dir name=\\"sub1\\"\\/>\\n\\t<dir name=\\"sub2\\">\\n\\t\\t<file name=\\"hi.txt\\"\\/>\\n\\t<\\/dir>\\n\\t<dir name=\\"sub3\\"\\/>\\n<\\/dir>" }'
msg_set_invalid_2_filesys = '{"type": "set_filesystem_xml", "from": "managementconsole", "to": "' + str(
    cf.HPID) + '", "file": "<!--4, 0-->\\ndir name=\\"neuer\\">\\n\\t<dir name=\\"sub1\\"\\/>\\n\\t<dir name=\\"sub2\\">\\n\\t\\t<file name=\\"hi.txt\\"\\/>\\n\\t<\\/dir>\\n\\t<dir name=\\"sub3\\"\\/>\\n<\\/dir>" }'

msg_get_token_files = '{"type": "get_token_files", "from": "managementconsole", "to": "' + str(cf.HPID) + '"}'
msg_add_token_file = '{"type": "add_token_file", "from": "managementconsole", "to": "' + str(
    cf.HPID) + '", "file": {"name": "new_token.txt", "file": "File as String"} }'

msg_add_token_file_existent = '{"type": "add_token_file", "from": "managementconsole", "to": "' + str(
    cf.HPID) + '", "file": {"name": "new_token.txt", "file": "New File as String"} }'

msg_rem_token_files = '{"type": "remove_token_files", "from": "managementconsole", "to": "' + str(
    cf.HPID) + '", "names": ["tf1", "tf2"] }'
msg_rem_all_token_files = '{"type": "remove_token_files", "from": "managementconsole", "to": "' + str(
    cf.HPID) + '", "names": ["ALL"] }'

all_incoming = [msg_ping, msg_get_all_services_all, msg_get_all_services_id, msg_get_settings, msg_set_settings,
                msg_start_services, msg_stop_services, msg_get_html_pages, msg_add_html, msg_remove_html, msg_get_cred,
                msg_set_cred, msg_get_filesys, msg_set_filesys, msg_add_token_file, msg_get_token_files,
                msg_rem_token_files, msg_remove_all_html, msg_rem_all_token_files, msg_get_listen_settings,
                msg_set_invalid_1_filesys, msg_set_invalid_2_filesys]
for inc in all_incoming:
    json.loads(inc)  # nur zum Testen, ob die obigen Antworten im korrekten JSON Format geschrieben sind
