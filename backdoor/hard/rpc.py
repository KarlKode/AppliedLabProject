import Pyro4

class Test():
    def credential_login(self, user_id, password):
        print user_id
        print password
        return {"_rpc_status": "success", "data": "asdf1234"}

def main():
    t = Test()
    Pyro4.Daemon.serveSimple({t: "core"}, ns=False)

if __name__ == "__main__":
    main()

