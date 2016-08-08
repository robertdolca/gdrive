import sys
import gdrive

from oauth2client.clientsecrets import InvalidClientSecretsError
from googleapiclient.errors import HttpError

if __name__ == '__main__':
    try:
        service = gdrive.get_service()
        # your code goes here
    except (HttpError, InvalidClientSecretsError) as error:
        print(str(error))
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(0)
