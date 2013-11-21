import os
import Pyro4
import multiprocessing

class StatusRPC(object):
    def load(self):
        result = os.getloadavg()
        return str(result)

    def cpu_count(self):
        return multiprocessing.cpu_count()

    def status(self):
        return "running"


def main():
    status = StatusRPC()
    Pyro4.config.SERIALIZERS_ACCEPTED = ["json", "marshal", "serpent", "pickle"]
    Pyro4.Daemon.serveSimple(
        {
            status: "status",
        },
        host="0.0.0.0",
        port=4446,
        ns=False
    )

if __name__ == "__main__":
    main()
