from honeygrove.tests.testresources import testconfig as cf
import json

answ_ping = '{"from": "' + str(cf.HPID) + '", "to": "managementconsole", "type": "pong"}'
answ_ping = json.dumps(json.loads(answ_ping), sort_keys=True)

answ_get_all_services = '{"type": "send_all_services", "from": "' + str(
    cf.HPID) + '", "to": "managementconsole", "services": ["TESTSERVICEA", "TESTSERVICEB", "LISTEN"]}'
answ_get_all_services = json.dumps(json.loads(answ_get_all_services), sort_keys=True)

answ_started_services = '{"type": "started_services", "to": "managemenconsole", "from": "' + str(
    cf.HPID) + '", "services": ["TESTSERVICEA"]}'
answ_started_services = json.dumps(json.loads(answ_started_services), sort_keys=True)

answ_stopped_services = '{"type": "stopped_services", "to": "managemenconsole", "from": "' + str(
    cf.HPID) + '", "services": ["TESTSERVICEB"]}'
answ_stopped_services = json.dumps(json.loads(answ_stopped_services), sort_keys=True)

answ_get_settings = '{"type": "hp_settings", "from": "' + str(
    cf.HPID) + '", "to": "managementconsole", "settings": {"service": "TESTSERVICEA", "ports": [1], "running": false, "token_probabilty": 0.5}}'
answ_get_settings = json.dumps(json.loads(answ_get_settings), sort_keys=True)

answ_set_settings = '{"type": "hp_settings", "to": "managementconsole", "from": "' + str(
    cf.HPID) + '", "settings": {"service": "LISTEN", "ports": [9, 8, 7], "running": false, "token_probability": 0.9}}'
answ_set_settings = json.dumps(json.loads(answ_set_settings), sort_keys=True)

answ_set_settings_run = '{"type": "hp_settings", "to": "managementconsole", "from": "' + str(
    cf.HPID) + '", "settings": {"service": "TESTSERVICEB", "ports": [7], "running": true, "token_probability": 1}}'
answ_set_settings_run = json.dumps(json.loads(answ_set_settings_run), sort_keys=True)

answ_get_filesys = '{"type": "respond_filesystem_xml", "to": "managementconsole", "from": "' + str(
    cf.HPID) + '", "file": "<!--0, 0-->\\n<dir name=\\"/\\">\\n    <dir name=\\"bin\\"/>\\n</dir>" } '
answ_get_filesys = json.dumps(json.loads(answ_get_filesys), sort_keys=True)

answ_set_filesys = '{ "type": "update", "to": "managementconsole", "from": "' + str(
    cf.HPID) + '", "successful": true, "response": "set_filesystem_xml"}'
answ_set_filesys = json.dumps(json.loads(answ_set_filesys), sort_keys=True)

answ_set_invalid_filesys = '{ "type": "update", "to": "managementconsole", "from": "' + str(
    cf.HPID) + '", "successful": false, "response": "set_filesystem_xml"}'
answ_set_invalid_filesys = json.dumps(json.loads(answ_set_invalid_filesys), sort_keys=True)

answ_get_token_files = '{"from": "' + str(
    cf.HPID) + '", "to": "managementconsole", "tokenfiles": [{"file": "sometoken", "name": "mytoken"}, {"file": "a:b:c:d", "name": "suspicious_data.txt"}], "type": "send_token_files"}'

answ_add_token_file = '{"from": "' + str(
    cf.HPID) + '", "response": "add_token_file", "successful": "true", "to": "managementconsole", "type": "update"}'

answ_remove_token_file = '{"from": "' + str(
    cf.HPID) + '", "response": "remove_token_files", "successful": "true", "to": "managementconsole", "type": "update"}'

all_answers = [answ_ping, answ_get_all_services, answ_started_services, answ_stopped_services, answ_get_settings,
               answ_set_settings, answ_get_filesys, answ_set_filesys, answ_set_invalid_filesys]

for ans in all_answers:
    json.loads(ans)  # nur zum Testen, ob die obigen Antworten im korrekten JSON Format geschrieben sind