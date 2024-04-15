import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

''' IMPORTS '''
from typing import Any, List, Dict
import json
import requests
from time import monotonic, sleep
from datetime import datetime, timezone, timedelta

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()
from threading import RLock
import base64

from abc import ABC, abstractmethod
from contextlib import contextmanager
from dataclasses import dataclass

''' CONSTANTS '''
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
utc_tzinfo = timezone(timedelta(), name='UTC')
THREAT_INTELLIGENCE = "Threat Intelligence"

# STATUS Constants
AUTO_CLOSED = 'auto-closed'

RISK_TYPE_ALL = "all"

TRIAGE_ITEM_STATE_REJECTED = 'rejected'

# FIELDS Constants
UPDATED = 'updated'

STATE = 'state'

EVENT_ACTION_CREATE = 'create'

EVENT_ACTION = 'event-action'

ALERT = 'alert'

INCIDENT_ID = 'incident-id'

COMMENTS = 'comments'

ID = 'id'

EXPOSED_ACCESS_KEY = 'exposed-access-key'

UNAUTHORIZED_CODE_COMMIT = 'unauthorized-code-commit'

IMPERSONATING_SUBDOMAIN = 'impersonating-subdomain'

IMPERSONATING_DOMAIN = 'impersonating-domain'

EXPOSED_CREDENTIAL = 'exposed-credential'

ALERT_ID = 'alert-id'

SOURCE = 'source'

TRIAGE_ITEM_ID = 'triage-item-id'

RISK_ASSESSMENT = 'risk-assessment'

CLASSIFICATION = 'classification'

EVENT = 'event'

RISK_TYPE = 'risk-type'

RISK_LEVEL = 'risk-level'

ASSETS = 'assets'

INCIDENT = 'incident'

TRIAGE_ITEM = 'triage_item'

ALERT_FIELD = 'alert'


class Logger(ABC):
    """
    Abstract Base Class which provides an interface for Logging
    """

    def __init__(self, **kwargs):
        pass

    @abstractmethod
    def info(self, msg, *args, **kwargs):
        pass

    @abstractmethod
    def debug(self, msg, *args, **kwargs):
        pass

    @abstractmethod
    def warning(self, msg, *args, **kwargs):
        pass

    @abstractmethod
    def error(self, msg, *args, **kwargs):
        pass

    @abstractmethod
    def critical(self, msg, *args, **kwargs):
        pass


@dataclass
class HttpResponse:
    """Response from a HTTP Request"""

    status_code: int
    headers: Dict
    body: Any

    def raise_for_status(self):
        if self.status_code > 299 or self.status_code < 200:
            raise ValueError(f"Unsuccessful HTTP request - Http Status code: {self.status_code}")

    def json(self):
        return json.loads(self.body)


class HttpResponseHeaderRateLimiter:
    """Rate limiter for HTTP responses based on standard rate-limit response headers.

    This class implements just-enough to work with the SearchLight API and
    isn't intended to cope with the entirety of
    https://tools.ietf.org/id/draft-polli-ratelimit-headers-00.html

    Params specifit to this class:
    :param ratelimit: the number of requests per time-window
    :param window: time-window in seconds
    :param clock: function which returns the current time. Exposed for testing.
    """

    def __init__(self, ratelimit: int = 100, window: int = 60, clock=monotonic):
        self.ratelimit = ratelimit  # preserve as we might recalculate later
        self.window = window  # preserve as we might recalculate later
        self.rate_factor = 0.75  # factor that allows us to run ahead of any advertised rate limit
        self.period_s: float = self.rate_factor * (float(window) / float(ratelimit))
        self.clock = clock
        # initialise last_call such that the first call will happen immediately
        self.last_call = self.clock() - self.period_s
        self.lock = RLock()

    def handle_response(self, resp: HttpResponse) -> HttpResponse:
        # re-initialise rate limit config if we find the header has changed
        if 'ratelimit-limit' in resp.headers:
            self.__set_ratelimit_from_header(resp.headers['ratelimit-limit'])
        # check the remaining count and if it is getting too low, ensure we delay
        # our next request
        if 'ratelimit-remaining' in resp.headers:
            remaining = int(resp.headers.get('ratelimit-remaining'))
            if remaining <= 4:
                # find the remaining seconds and backoff for that long so we don't hit the limit
                reset_s = int(resp.headers.get('ratelimit-reset'))
                # push the last_call for this url out a bit further to avoid the next call breaking
                # the limit
                self.last_call = self.clock() + reset_s
        # now rate-limit ourselves before we return
        with self.__acquire():
            return resp

    def __set_ratelimit_from_header(self, headerval: str):
        """
        Set a new value for the rate-limit.

        Useful if initialised with a default value to start and replaced with a header-value
        later on.

        :param ratelimit: rate limit
        """
        # we know that SearchLight just returns an int and not the quota-policy stuff
        val = int(headerval)
        if val != self.ratelimit:
            self.ratelimit = val
            self.period_s = self.rate_factor * (float(val) / self.window)

    def __ready_time(self):
        time_elapsed_s = self.clock() - self.last_call
        return self.period_s - time_elapsed_s

    @contextmanager
    def __acquire(self):
        with self.lock:
            ready_time = self.__ready_time()
            while ready_time > 0:
                sleep(ready_time + 0.5)
                ready_time = self.__ready_time()
            try:
                yield
            finally:
                self.last_call = self.clock()


class HttpRequestHandler(ABC):
    """
    Abstract Base Class which provides an interface for HTTP request handlers.
    """

    def __init__(self, base_url, account_id, access_key, secret_key, **kwargs):
        self.base_url = base_url.rstrip("/")
        self.account_id = account_id
        self.access_key = access_key
        self.secret_key = secret_key
        self.headers = self.build_auth_headers()
        self.ratelimiter = HttpResponseHeaderRateLimiter(**kwargs)

    def build_auth_headers(self):
        """
        Create the default basic auth and 'searchlight-account-id' headers required for each request
        """
        headers = {}
        if self.account_id:
            headers['searchlight-account-id'] = self.account_id
        auth = str(self.access_key) + ':' \
               + str(self.secret_key)
        headers['Authorization'] = 'Basic {}'.format(base64.b64encode(auth.encode()).decode())
        return headers

    @abstractmethod
    def get(self, url, headers={}, params={}, data=None, **kwargs) -> HttpResponse:
        pass

    @abstractmethod
    def post(self, url, headers={}, params={}, data=None, **kwargs) -> HttpResponse:
        pass

    def rate_limit_response(self, response: HttpResponse):
        return self.ratelimiter.handle_response(response)


########################SearchLightRequestHandler##########################
class SearchLightRequestHandler(HttpRequestHandler):

    def __init__(self, base_url, account_id, access_key, secret_key, proxies=None, **kwargs):
        super().__init__(base_url, account_id, access_key, secret_key, **kwargs)
        self.headers['Accept'] = 'application/json'
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        self.session.auth = (access_key, secret_key)
        if proxies:
            self.session.proxies = proxies

    def get(self, url, headers={}, params={}, **kwargs):
        r = self.session.get(self.base_url + url, params=params, headers=headers, verify=False, **kwargs)
        return self.rate_limit_response(r)

    def post(self, url, headers={}, data=None, **kwargs):
        r = self.session.post(self.base_url + url, json=data, headers=headers, verify=False, **kwargs)
        return self.rate_limit_response(r)

    def put(self, url, headers={}, data=None, **kwargs):
        r = self.session.put(self.base_url + url, data=data, headers=headers, verify=False, **kwargs)
        return self.rate_limit_response(r)


################################### Incidents ###################################

def get_incidents(request_handler: HttpRequestHandler, incident_ids=[], **kwargs) -> List:
    LOG("Fetching incidents for ids: {}".format(incident_ids))
    if not incident_ids:
        return []
    params = dict(id=incident_ids)
    r = request_handler.get('/v1/incidents', params=params, **kwargs)
    r.raise_for_status()
    return r.json()


################################### Assets ###################################
def get_assets(request_handler: HttpRequestHandler, asset_ids=[], **kwargs) -> List:
    LOG("Fetching assets for ids: {}".format(asset_ids))
    if not asset_ids:
        return []
    results = []
    for chunk in chunks(asset_ids, 100):
        params = dict(id=chunk)
        r = request_handler.get('/v1/assets', params=params, **kwargs)
        r.raise_for_status()
        results.extend(r.json())
    return results


################################### Triage ###################################

utc_tzinfo = timezone(timedelta(), name='UTC')


def chunks(lst, n):
    """
    Yield successive n-sized chunks from lst.

    From: https://stackoverflow.com/a/312464
    """
    to_chunk = lst
    if not hasattr(lst, '__getitem__'):
        # not subscriptable so push into a list
        to_chunk = list(lst)
    for i in range(0, len(to_chunk), n):
        yield to_chunk[i:i + n]


def get_triage_item_events(request_handler: HttpRequestHandler, event_num_after=0,
                           event_created_after: datetime = None, risk_types=[], limit=100, **kwargs) -> List:
    """Retrieve a batch of triage item events

    Args:
        request_handler (HttpRequestHandler): the request_handler to use for HTTP requests
        logger (Logger): logger used for logging
        event_num_after (int): only return events with a higher event-num than this value, default 0
        event_created_after (datetime): only return events created after this value
        limit (int): return up to this number of events, default 100
    """
    params = {'event-num-after': event_num_after, 'limit': limit}
    if event_created_after is not None:
        utc_datetime = event_created_after.astimezone(utc_tzinfo)
        params['event-created-after'] = utc_datetime.strftime("%Y-%m-%dT%H:%M:%SZ")
    if len(risk_types) > 0:
        params['risk-type'] = risk_types
    LOG("Fetching triage item events. Parameters: {}".format(params))
    LOG("request_handler type: {}".format(type(request_handler)))
    LOG("requests type: {}".format(type(requests)))
    r = request_handler.get('/v1/triage-item-events', params=params, **kwargs)
    LOG("response------> {}".format(r))
    r.raise_for_status()
    return r.json()


def get_triage_items(request_handler: HttpRequestHandler, triage_item_ids=[], **kwargs) -> List:
    LOG("Fetching triage items for ids: {}".format(triage_item_ids))
    if not triage_item_ids:
        return []
    params = dict(id=triage_item_ids)
    r = request_handler.get('/v1/triage-items', params=params, **kwargs)
    r.raise_for_status()
    return r.json()


def get_triage_item_comments(request_handler: HttpRequestHandler, triage_item_ids=[], **kwargs) -> List:
    LOG("Fetching triage item comments for ids: {}".format(triage_item_ids))
    if not triage_item_ids:
        return []
    data = []
    for chunk in chunks(triage_item_ids, 10):
        params = dict(id=chunk)
        r = request_handler.get('/v1/triage-item-comments', params=params, **kwargs)
        r.raise_for_status()
        data.extend(r.json())
    return data


def update_triage_item_state(request_handler: HttpRequestHandler, triage_item_id, state, comment=None, **kwargs):
    payload = {
        "state": state,
    }
    if comment:
        payload["comment"] = {"content": comment}
    r = request_handler.put('/v1/triage-items/{}/state'.format(triage_item_id), json=payload, **kwargs)
    r.raise_for_status()
    return r


################################### Alerts ###################################
def get_alerts(request_handler: HttpRequestHandler, alert_ids=[], **kwargs) -> List:
    LOG("Fetching alert ids: {}".format(alert_ids))
    if not alert_ids:
        return []
    params = dict(id=alert_ids)
    r = request_handler.get("/v1/alerts", params=params, **kwargs)
    r.raise_for_status()
    return r.json()


def get_credential_exposure_alerts(request_handler: HttpRequestHandler, alert_ids=[], **kwargs) -> List:
    LOG("Fetching credential exposure alerts for alert ids: {}".format(alert_ids))
    if not alert_ids:
        return []
    params = dict(id=alert_ids)
    r = request_handler.get("/v1/exposed-credential-alerts", params=params, **kwargs)
    r.raise_for_status()
    return r.json()


def get_impersonating_domain_alerts(request_handler: HttpRequestHandler, alert_ids=[],
                                    **kwargs) -> List:
    LOG("Fetching impersonating domain alerts for alert ids: {}".format(alert_ids))
    if not alert_ids:
        return []
    params = dict(id=alert_ids)
    r = request_handler.get("/v1/impersonating-domain-alerts", params=params, **kwargs)
    r.raise_for_status()
    return r.json()


def get_impersonating_subdomain_alerts(request_handler: HttpRequestHandler, alert_ids=[],
                                       **kwargs) -> List:
    LOG("Fetching impersonating subdomain alerts for alert ids: {}".format(alert_ids))
    if not alert_ids:
        return []
    params = dict(id=alert_ids)
    r = request_handler.get("/v1/impersonating-subdomain-alerts", params=params, **kwargs)
    r.raise_for_status()
    return r.json()


def get_unauthorized_code_commit(request_handler: HttpRequestHandler, alert_ids=[], **kwargs) -> List:
    LOG("Fetching unauthorized code commit for alert ids: {}".format(alert_ids))
    if not alert_ids:
        return []
    params = dict(id=alert_ids)
    r = request_handler.get("/v1/unauthorized-code-commit-alerts", params=params, **kwargs)
    r.raise_for_status()
    return r.json()


def get_exposed_access_key_alerts(request_handler: HttpRequestHandler, alert_ids=[], **kwargs) -> List:
    LOG("Fetching exposed access key alerts for alert ids: {}".format(alert_ids))
    if not alert_ids:
        return []
    params = dict(id=alert_ids)
    r = request_handler.get("/v1/exposed-access-key-alerts", params=params, **kwargs)
    r.raise_for_status()
    return r.json()


################################### Indicators ###################################

utc_tzinfo = timezone(timedelta(), name="UTC")


def get_indicator_events(
    request_handler: HttpRequestHandler,
    event_num_after=0,
    event_created_after: datetime = None,
    limit=100,
    **kwargs
) -> List:
    """Retrieve a batch of triage item events

    Args:
        request_handler (HttpRequestHandler): the request_handler to use for HTTP requests
        logger (Logger): logger used for logging
        event_num_after (int): only return events with a higher event-num than this value, default 0
        event_created_after (datetime): only return events created after this value
        limit (int): return up to this number of events, default 100
    """

    params = {"event-num-after": event_num_after, "limit": limit}
    if event_created_after is not None:
        utc_datetime = event_created_after.astimezone(utc_tzinfo)
        params["event-created-after"] = utc_datetime.strftime("%Y-%m-%dT%H:%M:%SZ")
    LOG("Fetching indicator events. Parameters: {}".format(params))
    r = request_handler.get("/v1/indicator-events", params=params, **kwargs)
    r.raise_for_status()
    return r.json()


def get_indicators(
    request_handler: HttpRequestHandler, indicator_ids=[], **kwargs
) -> List:
    """Retrieve one or more indicators by ID."""

    LOG("Fetching indicators for ids: {}".format(indicator_ids))
    if not indicator_ids:
        return []
    params = dict(id=indicator_ids, limit=100)
    r = request_handler.get("/v1/indicators", params=params, **kwargs)
    r.raise_for_status()
    return r.json()


################################### Indicator grouping ###################################

def get_indicator_grouping_events(
    request_handler: HttpRequestHandler,
    logger: Logger,
    event_num_after=0,
    event_created_after: datetime = None,
    limit=100,
    **kwargs
) -> List:
    """Retrieve a batch of triage item events

    Args:
        request_handler (HttpRequestHandler): the request_handler to use for HTTP requests
        logger (Logger): logger used for logging
        event_num_after (int): only return events with a higher event-num than this value, default 0
        event_created_after (datetime): only return events created after this value
        limit (int): return up to this number of events, default 100
    """

    params = {"event-num-after": event_num_after, "limit": limit}
    if event_created_after is not None:
        utc_datetime = event_created_after.astimezone(utc_tzinfo)
        params["event-created-after"] = utc_datetime.strftime("%Y-%m-%dT%H:%M:%SZ")
    logger.debug("Fetching indicator events. Parameters: {}".format(params))
    r = request_handler.get("/v1/indicator-grouping-events", params=params, **kwargs)
    r.raise_for_status()
    return r.json()


def get_indicator_groupings(
    request_handler: HttpRequestHandler, ids=[], **kwargs
) -> List:
    """Retrieve one or more indicator groupings by ID."""

    LOG("Fetching indicator groupings for ids: {}".format(ids))
    if not ids:
        return []
    params = dict(id=ids, limit=100)
    r = request_handler.get("/v1/indicator-groupings", params=params, **kwargs)
    r.raise_for_status()
    return r.json()


class HttpRequestHandler(ABC):
    """
    Abstract Base Class which provides an interface for HTTP request handlers.
    """

    def __init__(self, base_url, account_id, access_key, secret_key, **kwargs):
        self.base_url = base_url.rstrip("/")
        self.account_id = account_id
        self.access_key = access_key
        self.secret_key = secret_key
        self.headers = self.build_auth_headers()
        self.ratelimiter = HttpResponseHeaderRateLimiter(**kwargs)

    def build_auth_headers(self):
        """
        Create the default basic auth and 'searchlight-account-id' headers required for each request
        """
        headers = {}
        if self.account_id:
            headers['searchlight-account-id'] = self.account_id
        auth = str(self.access_key) + ':' \
               + str(self.secret_key)
        headers['Authorization'] = 'Basic {}'.format(base64.b64encode(auth.encode()).decode())
        return headers

    @abstractmethod
    def get(self, url, headers={}, params={}, data=None, **kwargs) -> HttpResponse:
        pass

    @abstractmethod
    def post(self, url, headers={}, params={}, data=None, **kwargs) -> HttpResponse:
        pass

    def rate_limit_response(self, response: HttpResponse):
        return self.ratelimiter.handle_response(response)


@dataclass(frozen=True)
class IndicatorsResult:
    max_event_number: int
    data: Any


@dataclass(frozen=True)
class PollResult:
    max_event_number: int
    triage_data: Any


def removing_unwanted_data(data_item):
    # Removing source from triage as source already merged into triage
    data_item[TRIAGE_ITEM].pop('source')

    # Removing risk-level, classification and risk-type from triage-item and event
    if data_item.get(ALERT_FIELD) and data_item[ALERT_FIELD].get(ASSETS):
        data_item[ALERT_FIELD].pop(ASSETS)
        data_item[ALERT_FIELD].pop(RISK_ASSESSMENT)
        data_item[ALERT_FIELD].pop(RISK_TYPE)
        if data_item[ALERT_FIELD].get(CLASSIFICATION): data_item[ALERT_FIELD].pop(CLASSIFICATION)
    elif data_item.get(INCIDENT) and data_item[INCIDENT].get(ASSETS):
        data_item[INCIDENT].pop(ASSETS)
        data_item[INCIDENT].pop(RISK_LEVEL)
        data_item[INCIDENT].pop(RISK_TYPE)
        data_item[INCIDENT].pop(CLASSIFICATION)

    if data_item.get(EVENT):
        data_item[EVENT].pop(RISK_LEVEL)
        data_item[EVENT].pop(RISK_TYPE)
        data_item[EVENT].pop(CLASSIFICATION)
    return data_item


def get_comments_map(triage_item_comments):
    comment_map = {}
    for comment in triage_item_comments:
        if comment[TRIAGE_ITEM_ID] in comment_map:
            comment_map[comment[TRIAGE_ITEM_ID]].append(comment)
        else:
            comment_map[comment[TRIAGE_ITEM_ID]] = [comment]
    sorted_comment_map = {key: sorted(comments, key=lambda x: x[UPDATED], reverse=True) for key, comments in
                          comment_map.items()}
    # Keeping only latest 10 comments
    latest_10_comments_map = {key: comments[:10] for key, comments in
                              sorted_comment_map.items()}

    return latest_10_comments_map


class SearchLightTriagePoller(object):

    def __init__(self, request_handler: HttpRequestHandler):
        self.request_handler = request_handler

    def get_alerts(self, alert_triage_items=[]):
        """
        Retrieve Alert details from SearchLight API

        Uses API endpoints that provide additional details where provided for
        a given triage item classification.

        :param alert_triage_items: triage item from which we extract alert ids
        :param alert_risk_types: alert risk types to be fetched
        """
        if not alert_triage_items:
            return []
        cred_alert_ids = set()
        domain_alert_ids = set()
        subdomain_alert_ids = set()
        code_commit_alert_ids = set()
        access_key_alert_ids = set()
        other_alert_ids = set()
        for ti in alert_triage_items:
            if EXPOSED_CREDENTIAL == ti[RISK_TYPE]:
                cred_alert_ids.add(ti[SOURCE][ALERT_ID])
            elif IMPERSONATING_DOMAIN == ti[RISK_TYPE]:
                domain_alert_ids.add(ti[SOURCE][ALERT_ID])
            elif IMPERSONATING_SUBDOMAIN == ti[RISK_TYPE]:
                subdomain_alert_ids.add(ti[SOURCE][ALERT_ID])
            elif UNAUTHORIZED_CODE_COMMIT == ti[RISK_TYPE]:
                code_commit_alert_ids.add(ti[SOURCE][ALERT_ID])
            elif EXPOSED_ACCESS_KEY == ti[RISK_TYPE]:
                access_key_alert_ids.add(ti[SOURCE][ALERT_ID])
            else:
                other_alert_ids.add(ti[SOURCE][ALERT_ID])

        other_alert_ids.difference(cred_alert_ids) \
            .difference(domain_alert_ids) \
            .difference(subdomain_alert_ids) \
            .difference(code_commit_alert_ids) \
            .difference(access_key_alert_ids)

        cred_alerts = get_credential_exposure_alerts(self.request_handler, cred_alert_ids)
        domain_alerts = get_impersonating_domain_alerts(self.request_handler, domain_alert_ids)
        subdomain_alerts = get_impersonating_subdomain_alerts(self.request_handler, subdomain_alert_ids)
        code_commit_alerts = get_unauthorized_code_commit(self.request_handler, code_commit_alert_ids)
        access_key_alerts = get_exposed_access_key_alerts(self.request_handler, access_key_alert_ids)
        other_alerts = get_alerts(self.request_handler, other_alert_ids)
        return [*cred_alerts, *domain_alerts, *subdomain_alerts, *code_commit_alerts, *access_key_alerts, *other_alerts]

    def merge_data(self, events, triage_items, triage_item_comments, alerts, incidents, assets) -> List[PollResult]:
        """
        Merge the triage item data together with the found alert, incident and asset information.
        """
        data = []

        event_map = {event[TRIAGE_ITEM_ID]: event for event in events}
        alert_map = {alert[ID]: alert for alert in alerts}
        incident_map = {incident[ID]: incident for incident in incidents}
        asset_map = {asset[ID]: asset for asset in assets}
        comment_map = get_comments_map(triage_item_comments)
        LOG('inside merge ------->>>>')
        for triage_item in triage_items:
            data_item = {TRIAGE_ITEM: triage_item, ASSETS: [], EVENT: event_map[triage_item[ID]]}
            if triage_item[ID] in comment_map:
                data_item[COMMENTS] = json.dumps(comment_map[triage_item[ID]])

            alert_or_incident = None
            if ALERT_ID in triage_item[SOURCE] and triage_item[SOURCE][ALERT_ID]:
                # will KeyError if missing - intentional, shouldn't be
                if triage_item[SOURCE][ALERT_ID] not in alert_map:
                    continue
                alert = alert_map[triage_item[SOURCE][ALERT_ID]]
                alert = self.stringyfyAlert(alert)
                data_item[ALERT] = alert
                alert_or_incident = alert
            elif INCIDENT_ID in triage_item[SOURCE] and triage_item[SOURCE][INCIDENT_ID]:
                # will KeyError if missing - intentional, shouldn't be
                if triage_item[SOURCE][INCIDENT_ID] not in incident_map:
                    continue
                incident = incident_map[triage_item[SOURCE][INCIDENT_ID]]
                data_item[INCIDENT] = incident
                alert_or_incident = incident
            # merge assets on (where available)
            for asset_id_holder in alert_or_incident[ASSETS]:
                # assets can be missing if deleted
                asset = asset_map.get(asset_id_holder[ID], None)
                if asset:
                    data_item[ASSETS].append(json.dumps(asset))

            # a new boolean field “auto-closed”, is added → where the triage-event indicates that the triage item is\
            # auto-rejected, this is set to true. Otherwise, it is false
            # based on event-action="create" and status="rejected" on the triage item event
            auto_closed = data_item[EVENT][EVENT_ACTION] == EVENT_ACTION_CREATE and data_item[TRIAGE_ITEM][
                STATE] == TRIAGE_ITEM_STATE_REJECTED
            data_item[AUTO_CLOSED] = auto_closed

            data_item = removing_unwanted_data(data_item)

            data.append(data_item)

        return data

    def stringyfyAlert(self, alert):
        LOG(f'------stringyfyAlert')
        if alert.get('risk-factors'):
            alert.update({'risk-factors': json.dumps(alert.get('risk-factors'))})
        if alert.get('mitre-attack-mapping'):
            alert.update({'mitre-attack-mapping': json.dumps(alert.get('mitre-attack-mapping'))})
        if alert.get('validation'):
            alert.update({'validation': json.dumps(alert.get('validation'))})

        alert_details = {}
        if alert.get('title'):
            alert_details['title'] = alert.pop('title')
        if alert.get('portal-id'):
            alert_details['portal-id'] = alert.pop('portal-id')
        if alert.get('id'):
            alert_details['id'] = alert.pop('id')
        if alert.get('description'):
            alert_details['description'] = alert.pop('description')
        if alert.get('raised'):
            alert_details['raised'] = alert.pop('raised')
        if alert.get('updated'):
            alert_details['updated'] = alert.pop('updated')
        if alert.get('email'):
            alert_details['email'] = alert.pop('email')
        if alert.get('password'):
            alert_details['password'] = alert.pop('password')
        if alert.get('inferred-password-type'):
            alert_details['inferred-password-type'] = alert.pop('inferred-password-type')
        if alert.get('first-seen'):
            alert_details['first-seen'] = alert.pop('first-seen')
        alert['details'] = json.dumps(alert_details)
        LOG(f'------alert: {alert}')
        return alert

    def poll_triage(self, event_num_start=0, limit=100, event_created_after=None, alert_risk_types=[RISK_TYPE_ALL]):
        """
        A single poll of the triage API for new events, fully populating any new events found.

        Calls a provided callback method with the fully-populated data.

        Returns the largest event-num from the triage item events that were processed.
        """
        LOG(
            "Polling triage items. Event num start: {}, Event created after: {}, Limit: {}".format(event_num_start,
                                                                                                   event_created_after,
                                                                                                   limit))
        risk_types_filter = []
        if not RISK_TYPE_ALL in alert_risk_types and len(alert_risk_types) > 0:
            risk_types_filter = alert_risk_types
        events = get_triage_item_events(self.request_handler, event_num_after=event_num_start, limit=limit,
                                        event_created_after=event_created_after, risk_types=risk_types_filter)
        if not events:
            LOG("No events were fetched. Event num start: {}, Event created after: {}, Limit: {}".format(
                event_num_start, event_created_after, limit))
            return PollResult(event_num_start, [])

        max_event_num = max([e['event-num'] for e in events])

        triage_item_ids = [e[TRIAGE_ITEM_ID] for e in events]
        triage_items = get_triage_items(self.request_handler, triage_item_ids)

        if not triage_items:
            # if a triage item is deleted it is not returned to the list - outside chance that all could be deleted
            # so validate before proceeding
            LOG("No triage items were fetched. Event num start: {}, Event created after: {}, Limit: {}"
                .format(event_num_start, event_created_after, limit))
            return PollResult(event_num_start, [])

        triage_item_comments = get_triage_item_comments(self.request_handler, triage_item_ids=triage_item_ids)

        alert_triage_items = [ti for ti in triage_items if ALERT_ID in ti[SOURCE] and ti[SOURCE][ALERT_ID]]

        # get summary details of alerts and incidents.
        # note that this is a simplified example. For certain classifications we have more-detailed endpoints that give
        # a greater granularity of information, such as the credential-exposure endpoint which contains the actual
        # credential we have found exposed in a specific field on the model
        alerts = self.get_alerts(alert_triage_items=alert_triage_items)

        incident_ids = set([ti[SOURCE][INCIDENT_ID] for ti in triage_items if
                            INCIDENT_ID in ti[SOURCE] and ti[SOURCE][INCIDENT_ID]])
        incidents = get_incidents(self.request_handler, incident_ids=incident_ids)

        asset_ids = set(
            [asset[ID] for alert_or_incident in [*alerts, *incidents] for asset in alert_or_incident[ASSETS]])
        assets = get_assets(self.request_handler, asset_ids=asset_ids)

        triage_data = self.merge_data(events, triage_items, triage_item_comments, alerts, incidents, assets)
        return PollResult(max_event_num, triage_data)


class SearchLightIndicatorsPoller(object):
    def __init__(self, request_handler: HttpRequestHandler):
        self.request_handler = request_handler

    def get_group_map(self, groups):
        """
        prepare group id to group info map
        @param groups: groups objects
        @return: map group id to group info
        """
        return {grp["id"]: {"group_name": grp["indicator-grouping"]["name"],
                            "group_description": grp["indicator-grouping"]["description"],
                            "group_url": grp["indicator-grouping"]["url"],
                            "group_labels": grp["indicator-grouping"]["labels"]} for grp in groups}

    def merge_data(self, indicators, groups):
        """
        Its just merges the indicator data along with the grouping details
        @param indicators: indicators
        @param groups: groups info
        @return: data as list
        """
        group_map = self.get_group_map(groups)
        data = []
        for indicator in indicators:
            indicator_data = {
                "id": indicator.get("id"),
                "indicator_grouping_id": indicator.get("indicator-grouping-id"),
                "created": indicator.get("created"),
                "revoked": indicator.get("revoked"),
                # flattened indicator fields
                "value": self.transform_value(indicator['indicator'].get("type"), indicator['indicator'].get("value")),
                "title": indicator['indicator'].get("title"),
                "description": indicator['indicator'].get("description"),
                "source_created": indicator['indicator'].get("source-created"),
                "source": indicator['indicator'].get("source"),
                "type": indicator['indicator'].get("type")
            }
            indicator_data.update(group_map.get(indicator["indicator-grouping-id"], None))
            data.append(indicator_data)
        return data

    def transform_value(self, value_type: str, value: str):
        """Apply a type-specific transformation to the value.

        Typically used to canonicalize values for loading into the kvstore
        as kv lookups are case-sensitive

        Args:
            value_type (str): the type of value
            value (str): the value itself

        Returns:
            a transformed value, or the original value if no transform is needed
        """
        if value_type == 'email' \
            or value_type == 'host' \
            or value_type == 'ipv4' \
            or value_type == 'ipv6' \
            or value_type == 'md5' \
            or value_type == 'sha1' \
            or value_type == 'sha256':

            # lowercase as these types are inherantly case-insensitive
            return value.lower()
        else:
            # type is not known to be case-insensitive, so don't transform.
            return value

    def poll_indicators(self, event_num_start=0, limit=100, event_created_after=None):
        """
        polls indicators for given filters
        @param event_num_start: event number
        @param limit: limit
        @param event_created_after: date from where we want to poll the indicators
        @return: returns IndicatorsResult object
        """
        LOG(
            "Polling indicators items. Event num start: {}, Event created after: {}, Limit: {}".format(event_num_start,
                                                                                                       event_created_after,
                                                                                                       limit))
        events = get_indicator_events(self.request_handler, event_num_start, event_created_after, limit)
        if not events:
            LOG("{}: No events were fetched. Event num start: {}, Event created after: {}, Limit: {}".format(
                THREAT_INTELLIGENCE, event_num_start, event_created_after, limit))
            return IndicatorsResult(event_num_start, [])
        max_event_num = max([e['event-num'] for e in events])

        indicator_event_ids = [e["indicator-id"] for e in events]
        indicators = get_indicators(self.request_handler, indicator_event_ids)
        if not indicators:
            # if indicators are deleted it is not returned to the list - outside chance that all could be deleted
            # so validate before proceeding
            LOG("{}: No indicators were fetched. Event num start: {}, Event created after: {}, Limit: {}"
                .format(THREAT_INTELLIGENCE, event_num_start, event_created_after, limit))
            return IndicatorsResult(event_num_start, [])
        indicator_grouping_ids = [e["indicator-grouping-id"] for e in events]
        indicator_groups = get_indicator_groupings(self.request_handler, indicator_grouping_ids)

        indicators_data = self.merge_data(indicators, indicator_groups)
        return IndicatorsResult(max_event_num, indicators_data)


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    def __init__(self, *args, **kwargs):
        LOG("----> inside client constructoire")
        self.base_url = kwargs["base_url"]
        self.account_id = kwargs['account_id']
        self.verify = kwargs["verify"]
        self.access_key = kwargs["access_key"]
        self.secret_key = kwargs["secret_key"]
        self.auth = kwargs["auth"]
        self.headers = self.build_auth_headers()
        self.limit = kwargs["limit"]

    def test_client(self):
        r = requests.request("GET", self.base_url + '/v1/test', headers=self.headers)
        r_data = r.json()
        LOG(f"response------->{json.dumps(r_data)}")
        if not r_data.get("api-key-valid"):
            return 400, "Invalid API Key"
        if not r_data.get("access-account-enabled"):
            return 400, "Account access disabled"
        if not r_data.get("account-api-enabled"):
            return 400, "Account API disabled"
        if not r_data.get("account-id-valid"):
            return 400, "Account Id invalid"
        return r.status_code, r_data

    def build_auth_headers(self):
        """
        Create the default basic auth and 'searchlight-account-id' headers required for each request
        """
        headers = {}
        if self.account_id:
            headers['searchlight-account-id'] = self.account_id
        auth = str(self.access_key) + ':' \
               + str(self.secret_key)
        LOG(f"auth--------> {auth}")
        headers['Authorization'] = 'Basic {}'.format(base64.b64encode(auth.encode()).decode())
        return headers

    def say_hello(self, name):
        return f'Hello aaaa {name} '

    def get_incident(self, count="1"):
        response = requests.request("GET", self.base_url + "?offset=1&limit=50", headers=self.headers,
                                    verify=self.verify, auth=self.auth)
        return response.json()

    def say_hello_http_request(self, name):
        data = self._http_request(
            method='GET',
            url_suffix='/hello/' + name
        )
        return data.get('result')


def test_module(client):
    status, message = client.test_client()
    if status == 200:
        return 'ok'
    else:
        return 'Test failed because ......' + message


def parse_date(since):
    try:
        return datetime.strptime(since, constants.SINCE_DATE_FORMAT)
    except Exception as e:
        return datetime.strptime(since, constants.SINCE_DATE_FORMAT_WITH_MILLISECONDS)
    except Exception as ee:
        raise Exception(f"Unable to parse date from input: {since}") from ee


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    LOG(f'input config------: {demisto.params()}')
    secretKey = demisto.params().get("apiSecret").get('identifier')
    accessKey = demisto.params().get('apiKey').get('identifier')
    account = demisto.params().get('accountId')
    riskTypes = demisto.params().get('riskTypes')

    if RISK_TYPE_ALL in riskTypes:
        riskTypes = [RISK_TYPE_ALL]

    # get the service API url
    base_url = demisto.params()['searchLightUrl']
    verify_certificate = not demisto.params().get('insecure', False)

    # How much time before the first fetch to retrieve incidents
    first_fetch_time = demisto.params().get('fetch_time', '3 days').strip()

    proxy = demisto.params().get('proxy', False)
    limit = demisto.params().get('limit', 1)
    LOG('before last run-----')
    last_run = demisto.getLastRun()
    LOG(f'after last run----- {last_run}')

    LOG(f'Command being called is {demisto.command()}')
    try:
        searchLightClient = Client(
            base_url=base_url,
            account_id=account,
            access_key=accessKey,
            secret_key=secretKey,
            verify=verify_certificate,
            auth=(secretKey, accessKey),
            limit=limit
        )
        LOG("client initialized ----- test client")
        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            LOG('calling test module')
            result = test_module(searchLightClient)
            demisto.results(result)
        if demisto.command() == 'fetch-indicators':
            LOG(f"inside indicatores-----> ")
            last_event_num = last_run.get('indicators', {}).get('last_fetch', 0)
            LOG(f"last_event_num indicatores-----> ")

            search_light_request_handler_for_indicators = SearchLightRequestHandler(base_url,
                                                                                    account,
                                                                                    accessKey,
                                                                                    secretKey)
            LOG(f"search_light_request_handler_for_indicators indicatores-----> ")

            search_light_indicators_poller = SearchLightIndicatorsPoller(search_light_request_handler_for_indicators)
            LOG(f"search_light_indicators_poller indicatores-----> ")

            poll_result = search_light_indicators_poller.poll_indicators(event_num_start=last_event_num, limit=10)
            LOG(f"poll_result indicatores-----> ")

            data = poll_result.data
            last_polled_number = poll_result.max_event_number
            LOG(f"indicatores-----> {data}")
            if data:
                indicators = []
                for item in data:
                    indicator = {
                        'type': item['type'],
                        'fields': {"some": "thing"},
                        'occurred': item["created"],
                        'rawJSON': item
                    }
                    indicators.append(indicator)
                # check if the version is higher than 6.5.0 so we can use noUpdate parameter
                if is_demisto_version_ge('6.5.0'):
                    for b in batch(indicators, batch_size=10):
                        LOG(f"batch----->{b}")
                        demisto.createIndicators(b)

            demisto.setLastRun({'indicators': {'last_fetch': last_polled_number}})

        elif demisto.command() == 'fetch-incidents':
            LOG(f"inside command ------>{demisto.command()}")
            last_event_num = last_run.get('incidents', {}).get('last_fetch', 0)
            LOG(f"last run  ------> {last_event_num}")
            search_light_request_handler = SearchLightRequestHandler(base_url,
                                                                     account,
                                                                     accessKey,
                                                                     secretKey)
            LOG(f"before search_light_request_handler ------>")
            search_list_triage_poller = SearchLightTriagePoller(search_light_request_handler)
            LOG(f"after search_list_triage_poller ------>")

            poll_result = search_list_triage_poller.poll_triage(event_num_start=last_event_num, limit=2,
                                                                alert_risk_types=riskTypes)
            LOG(f"after poll_result ------>")
            data = poll_result.triage_data
            last_polled_number = poll_result.max_event_number
            # LOG(f"after poll_result {data}")
            LOG(f"after poll_result {last_polled_number}")
            # if poll_result.max_event_number == last_event_num:
            #     LOG(f"Polling done. last_event_num: {last_event_num}")
            #     demisto.results("")
            LOG(f"before data------>")
            if data:
                LOG(f"inside if data")
                incidents = []
                for item in data:
                    incident = {
                        'name': "incident",
                        'occurred': item["triage_item"]['raised'],
                        'rawJSON': json.dumps(item)
                    }
                    incidents.append(incident)
                LOG(f"data------>{incidents}")
                demisto.incidents(incidents)
            demisto.setLastRun({'incidents': {'last_fetch': last_polled_number}})

        elif demisto.command() == 'helloworld-say-hello':
            return_outputs(*say_hello_command(searchLightClient, demisto.args()))

    # Log exceptions
    except Exception as e:
        LOG(f"error: {str(e)} Error message: {e.message}")
        return_error(f'Failed to execute {demisto.command()} command. error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

