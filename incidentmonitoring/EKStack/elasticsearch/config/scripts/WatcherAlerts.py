from incidentmonitoring.CIMBroker.CIMBrokerConfig import es
from elasticsearch_watcher import WatcherClient


class WatcherAlerts():

    # add the .watcher namespace to it
    WatcherClient.infect_client(es)

    # Watcher alerts
    @staticmethod
    def putWatch():

        # Mattermost webhook url
        url = ''

        #HTTP brute force alert
        es.watcher.put_watch(
            id='brute_force_http',
            body={
                # Run the watch every 10 seconds
                'trigger': {'schedule': {'interval': '10s'}},

                # The search request to execute
                'input': {
                    'search': {
                        'request': {
                            'indices': ['honeygrove'],
                            'body': {
                                'query': {
                                    'bool': {
                                        'must': [
                                            {'match': {'service': "HTTP"}},
                                            {'match': {'successful': "false"}}],
                                        'filter': {
                                            'range': {
                                                '@timestamp': {
                                                    'from': 'now-10s',
                                                    'to': 'now'}}}}}}}}},

                # Search for at least 100 logs matching the condition
                'condition': {
                          'compare': {
                            'ctx.payload.hits.total': {
                              'gt': 100}}},

                # The actions to perform
                'actions': {
                    'mattermost_webhook': {
                        'webhook': {
                            'method': 'POST',
                            'url': url,
                            'headers': {
                                'Content-Type': 'application/json'},
                            'body': {
                                'inline': {
                                    'text': ':heavy_exclamation_mark: **HTTP Brute Force Alert:** \n '
                                            '**{{ctx.payload.hits.total}}** **failed login attempts** was/were registered in the last 10 seconds. \n'
                                            'For an overview you can use the visualisations in **Kibana**.'}}}}}})

        # FTP brute force alert
        es.watcher.put_watch(
            id='brute_force_ftp',
            body={
                # Run the watch every 10 seconds
                'trigger': {'schedule': {'interval': '10s'}},

                # The search request to execute
                'input': {
                    'search': {
                        'request': {
                            'indices': ['honeygrove'],
                            'body': {
                                'query': {
                                    'bool': {
                                        'must': [
                                            {'match': {'service': "FTP"}},
                                            {'match': {'successful': "false"}}],
                                        'filter': {
                                            'range': {
                                                '@timestamp': {
                                                    'from': 'now-10s',
                                                    'to': 'now'}}}}}}}}},

                # Search for at least 100 logs matching the condition
                'condition': {
                          'compare': {
                            'ctx.payload.hits.total': {
                              'gt': 100}}},

                # The actions to perform
                'actions': {
                    'mattermost_webhook': {
                        'webhook': {
                            'method': 'POST',
                            'url': url,
                            'headers': {
                                'Content-Type': 'application/json'},
                            'body': {
                                'inline': {
                                    'text': ':heavy_exclamation_mark: **FTP Brute Force Alert:** \n '
                                            '**{{ctx.payload.hits.total}}** **failed login attempts** was/were registered in the last 10 seconds. \n'
                                            'For an overview you can use the visualisations in **Kibana**.'}}}}}})

        # SSH brute force alert
        es.watcher.put_watch(
            id='brute_force_ssh',
            body={
                # Run the watch every 10 seconds
                'trigger': {'schedule': {'interval': '10s'}},

                # The search request to execute
                'input': {
                    'search': {
                        'request': {
                            'indices': ['honeygrove'],
                            'body': {
                                'query': {
                                    'bool': {
                                        'must': [
                                            {'match': {'service': "SSH"}},
                                            {'match': {'successful': "false"}}],
                                        'filter': {
                                            'range': {
                                                '@timestamp': {
                                                    'from': 'now-10s',
                                                    'to': 'now'}}}}}}}}},

                # Search for at least 100 logs matching the condition
                'condition': {
                          'compare': {
                            'ctx.payload.hits.total': {
                              'gt': 100}}},

                # The actions to perform
                'actions': {
                    'mattermost_webhook': {
                        'webhook': {
                            'method': 'POST',
                            'url': url,
                            'headers': {
                                'Content-Type': 'application/json'},
                            'body': {
                                'inline': {
                                    'text': ':heavy_exclamation_mark: **SSH Brute Force Alert:** \n '
                                            '**{{ctx.payload.hits.total}}** **failed login attempts** was/were registered in the last 10 seconds. \n'
                                            'For an overview you can use the visualisations in **Kibana**.'}}}}}})

        # Malware alert
        es.watcher.put_watch(
            id='malware_alerts',
            body={
                # Run the watch every 10 seconds
                'trigger': {'schedule': {'interval': '10s'}},

                # The search request to execute
                'input': {
                    'search': {
                        'request': {
                            'indices': ['honeygrove'],
                            'body': {
                                'query': {
                                    'bool': {
                                        'filter': {
                                            'range': {
                                                '@timestamp': {
                                                    'from': 'now-10s',
                                                    'to': 'now'}}},
                                        'must': [{
                                            'range': {
                                                'percent': {
                                                    'gte': 30,
                                                    'lte': 100}}}]}}}}}},


                # Search for every log matching the condition
                'condition': {
                          'compare': {
                            'ctx.payload.hits.total': {
                              'gt': 0}}},

                # The actions to perform
                'actions': {
                    'mattermost_webhook': {
                        'webhook': {
                            'method': 'POST',
                            'url': url,
                            'headers': {
                                'Content-Type': 'application/json'},
                            'body': {
                                'inline': {
                                    'text': ':heavy_exclamation_mark: **Malware Alert:** \n'
                                            '**{{ctx.payload.hits.total}}** new **malware file(s)** was/were discovered in the last 10 seconds. \n'
                                            'For an overview you can use the visualisations in **Kibana**.'}}}}}})

        # honeytoken alert
        es.watcher.put_watch(
            id='honeytoken_alerts',
            body={
                # Run the watch every 10 seconds
                'trigger': {'schedule': {'interval': '10s'}},

                # The search request to execute
                'input': {
                    'search': {
                        'request': {
                            'indices': ['honeygrove'],
                            'body': {
                                'query': {
                                    'bool': {
                                        'must': [
                                            {'match': {'successful': "true"}}],
                                        'filter': {
                                            'range': {
                                                '@timestamp': {
                                                    'from': 'now-10s',
                                                    'to': 'now'}}}}}}}}},

                # Search for every log matching the condition
                'condition': {
                          'compare': {
                            'ctx.payload.hits.total': {
                              'gt': 0}}},

                # The actions to perform
                'actions': {
                    'mattermost_webhook': {
                        'webhook': {
                            'method': 'POST',
                            'url': url,
                            'headers': {
                                'Content-Type': 'application/json'},
                            'body': {
                                'inline': {
                                    'text': ':heavy_exclamation_mark: **Honeytoken Alert:** \n'
                                            '**{{ctx.payload.hits.total}}** **honeytokens** was/were used in the last 10 seconds. \n'
                                            'For an overview you can use the visualisations in **Kibana**.'}}}}}})

        print('\033[94m'+'Watcher Alerts Complete.'+'\033[0m')

if __name__ == '__main__':

    WatcherAlerts.putWatch()
