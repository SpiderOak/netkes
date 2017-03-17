from urlparse import urljoin
import requests


class ApiClient(object):
    def __init__(self, base, username, password):
        self.base = base
        self.username = username
        self.password = password

    def _path(self, path):
        return urljoin(self.base, path)

    def get(self, path):
        r = requests.get(self._path(path), auth=(self.username, self.password))
        r.raise_for_status()
        return r

    def get_json(self, path):
        return self.get(path).json()

    def post(self, path, data, headers=None):
        r = requests.post(
            self._path(path), auth=(self.username, self.password), headers=headers, data=data)
        r.raise_for_status()
        return r

    def post_json_raw_response(self, path, data, headers=None):
        r = requests.post(
            self._path(path), auth=(self.username, self.password), headers=headers, json=data)
        r.raise_for_status()
        return r

    def post_json(self, path, data, headers=None):
        r = self.post_json_raw_response(self._path(path), data, headers)
        if r.text:
            return r.json()

    def delete(self, path, headers=None):
        r = requests.delete(
            self._path(path), headers=headers, auth=(self.username, self.password))
        r.raise_for_status()
        return r
