from honeygrove.core.Credential import Credential


class SessionDatabase:

    def on_login(self, cred):
        if not isinstance(cred, Credential):
            return None

        print("SessionDatabase.on_login({})".format(cred))
        return "foo"
