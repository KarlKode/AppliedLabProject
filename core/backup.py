import sys
import base64
import serpent
from utils import decrypt

BACKUP_PRIVATE_KEY = "backup.key"


def main():
    if len(sys.argv) != 3:
        print "Usage: python backup.py <pkcs12 file to decrypt> <output file>"
        return
    try:
        data = serpent.loads(file(sys.argv[1]).read())
    except:
        print "Could not load encrypted data"
        return
    try:
        of = file(sys.argv[2], "wb")
        of.write(decrypt(BACKUP_PRIVATE_KEY, base64.b64decode(data["key_ct"]), base64.b64decode(data["ct"]),
                         base64.b64decode(data["mac"])))
        of.close()
    except:
        print "Could not decrypt data"
        raise


if __name__ == "__main__":
    main()