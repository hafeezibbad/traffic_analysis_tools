import logging
from typing import Optional
from urllib.error import HTTPError, URLError
from urllib.request import urlopen

from core.static.CONSTANTS import WIRESHARK_MANUF_FILE


def get_oui_info(manufs: dict, mac: str) -> Optional[str]:
    """
    This function takes a dictionary object containing OUI manufacturer's
    information and checks the oui_prefix obtained from mac addresses to
    find out the respective manufacturer's information.
    :param manufs: dictionary containing OUI to manufacturer mapping
    :param mac: mac address of the device
    """
    _oui = mac.replace('-', ':').upper()[:8]
    if _oui in manufs.keys():
        return manufs.get(_oui.upper())[0]

    return None


def load_manuf_file(manuf_file_path: str) -> Optional[dict]:
    """
    This function parses the file containing manufacturer's info and returns it as a dictionary where keys are the
    mac_id (prefixes) and values contain tuple (manufacturer-shortname, manufacturer-longname).
    Lines beginning with # and empty lines are ignored.
    :param manuf_file_path: path of manuf file
    :return: dictionary object manuf for given oui prefix.
    """
    manufs = dict()
    try:
        logging.debug('Looking for wireshark manuf file at {0}'.format(manuf_file_path))
        with open(manuf_file_path, 'r') as f:
            logging.info('Reading manuf file from {0}'.format(manuf_file_path))
            content = f.readlines()
            for line in content:
                if line and not line.startswith('#'):
                    entry = line.rstrip().split('\t')
                    manufs[entry[0]] = entry[1:]
        logging.info('{0} entries retrieved.'.format(len(manufs.keys())))
        return manufs
    except FileNotFoundError:
        logging.error('File not found at {0}'.format(manuf_file_path))

    except Exception as e:
        logging.error('Unable to process file: {0}.\nError: {1}'.format(manuf_file_path, e))

    return None


def fetch_manuf_file(manuf_file_uri: str = WIRESHARK_MANUF_FILE,  manuf_file_path: str = '') -> bool:
    """
    This function retrieves the latest version of file from web and storesit in local storage.
    :param manuf_file_uri: Link to the latest version of wireshark manuf file.
    :param manuf_file_path: path to store the downloaded file.
    :return: True if manu file successfully downloaded and saved
    """
    try:
        response = urlopen(manuf_file_uri)
        data = response.read()
        with open(manuf_file_path, 'wb+') as f:
            f.write(data)

        logging.info('MANUFs file successfully retrieved from {} and stored at {}'.format(
            manuf_file_uri,  manuf_file_path))

        return True
    except HTTPError as e:
        logging.error('Server failure in fetching resource from {0}. Error code: {1}'.format(manuf_file_uri, e.code))

    except URLError as e:
        logging.error('Unable to retrieve the resource from {0}. Reason {1}'.format(manuf_file_uri, e.reason))

    except IOError as e:
        logging.error('Unable to store manuf file at {0}. Error {1}'.format( manuf_file_uri, e))

    except Exception as e:
        logging.error('Unable to retrieve and store manuf file. Error {0}'.format(e))

    return False
