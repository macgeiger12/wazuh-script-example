import json
from datetime import datetime, timezone, timedelta
from typing import Optional
import requests
from requests.auth import HTTPBasicAuth
from requests.exceptions import HTTPError

DATE_FMT = "%Y-%m-%d"

class Client:
    """A simple client"""
    def __init__(self, url: str=None,
                 username: str=None,
                 password: str=None,
                 verify: bool=True):

        if not verify:
            requests.packages.urllib3.disable_warnings()

        self.verify = verify
        self.url = url
        self._credentials = HTTPBasicAuth(username, password)
        self.session = requests.Session()
        self.authenticate()

    @property
    def credentials(self):
        return self._credentials

    @credentials.setter
    def credentials(self, value):
        if self._credentials is None:
            self._credentials = value
        else:
            raise AttributeError('Cannot modify read-only property')

    def authenticate(self):
        """Authenticates using the provided credentials and updates
        the session headers."""
        endpoint = f'{self.url}/security/user/authenticate'
        try:
            response = self.session.get(
                url=endpoint,
                auth=self._credentials,
                verify=self.verify
            )
        except HTTPError as e:
            raise e
        json_response = json.loads(response.text)
        if 'token' in json_response['data']:
            headers = {
                'Authorization': f"Bearer {json_response['data']['token']}",
                'Content-Type': 'application/json'
            }
            self.session.headers.update(headers)

    def _do(self, http_method: str, endpoint: str, params: dict=None,
           data=None, files: dict=None, **kwargs):
        """handles requests"""
        try:
            response = self.session.request(
                method=http_method, url=endpoint, params=params,
                data=data, files=files, verify=self.verify, **kwargs
            )
        except requests.exceptions.RequestException as e:
            raise e

        return response

    def get(self, endpoint: str, params: Optional[dict] = None):
        """handles get requests"""
        return self._do(http_method='GET', endpoint=endpoint, params=params)

    def post(self, endpoint: str, params: Optional[dict] = None, data: dict=None):
        """handles post requests"""
        return self._do(http_method='POST', endpoint=endpoint, params=params, data=data)

    def get_stats(self, pretty: Optional[bool] = False,
                  wait_for_complete: Optional[bool] = False,
                  date: Optional[str] = None):
        """Return Wazuh statistical information for the current or specified date"""

        endpoint = f'{self.url}/manager/stats'
        params = {
            'pretty': pretty,
            'wait_for_complete': wait_for_complete,
            'date': date
        }

        # if no date is passed to get_stats, use today's date.
        if not date:
            params.update({'date': datetime.strftime(datetime.now(tz=timezone.utc), format=DATE_FMT)})

        return self.get(endpoint=endpoint, params=params)

    def list_agents(self,
                    status: str,
                    agents_list: Optional[str] = None,
                    pretty: Optional[bool] = False,
                    wait_for_complete: Optional[bool] = False):
        """Return information about all available agents or a list of them."""

        endpoint = f'{self.url}/agents'
        params = {'status': status,
                  'agents_list': agents_list,
                  'pretty': pretty,
                  'wait_for_complete': wait_for_complete}

        if status:
            if isinstance(list, status):
                status = ','.join(item for item in status)
                params.update({'status': status})

        return self.get(endpoint=endpoint, params=params)


if __name__ == '__main__':
    url = '<wazuh_url>:55000'
    username = '<username>'
    password = '<password>'

    client = Client(url=url, username=username, password=password, verify=False)
    yesterday = datetime.strftime(datetime.now(tz=timezone.utc) - timedelta(days=1), format=DATE_FMT)
    response = client.get_stats(date=yesterday)

