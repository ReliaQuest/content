import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

"""Digital Shadows for Cortex XSOAR."""

''' IMPORTS '''
import traceback
from datetime import datetime, timezone, timedelta
from time import monotonic, sleep

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()
from threading import RLock
import base64
import json
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
RISK_LEVEL_ALL = "all"

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

DS_BASE_URL = 'https://portal-digitalshadows.com'


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


'''HttpRequestHandler'''


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


'''SearchLightRequestHandler'''


class SearchLightRequestHandler(HttpRequestHandler):

    def __init__(self, base_url, account_id, access_key, secret_key, proxies=None, **kwargs):
        super().__init__(base_url, account_id, access_key, secret_key, **kwargs)
        LOG("inside SearchLightRequestHandler------")
        self.headers['Accept'] = 'application/json'
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        self.session.auth = (access_key, secret_key)
        if proxies:
            self.session.proxies = proxies

    def get(self, url, headers={}, params={}, **kwargs):
        LOG(f"SearchLightRequestHandler get headers --> {headers}")
        LOG(f"SearchLightRequestHandler get params --> {params}")
        LOG(f"SearchLightRequestHandler get params --> {kwargs}")
        r = self.session.get(self.base_url + url, params=params, headers=headers, verify=False, **kwargs)
        LOG(f"respnse incidents->> {r.json()}")
        return self.rate_limit_response(r)

    def post(self, url, headers={}, data=None, **kwargs):
        r = self.session.post(self.base_url + url, json=data, headers=headers, verify=False, **kwargs)
        return self.rate_limit_response(r)

    def put(self, url, headers={}, data=None, **kwargs):
        r = self.session.put(self.base_url + url, data=data, headers=headers, verify=False, **kwargs)
        return self.rate_limit_response(r)


'''Indicators'''


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


'''Indicator grouping'''


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


'''HttpRequestHandler'''


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


'''SearchLightIndicatorsPoller'''


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
        self.base_url = kwargs["base_url"]
        self.account_id = kwargs['account_id']
        self.verify = kwargs["verify"]
        self.access_key = kwargs["access_key"]
        self.secret_key = kwargs["secret_key"]
        self.auth = kwargs["auth"]
        self.headers = self.build_auth_headers()

    def test_client(self):
        r = requests.request("GET", self.base_url + '/v1/test', headers=self.headers)
        r_data = r.json()
        LOG(f"response------->{json.dumps(r_data)}")
        if r_data.get('message') and "'accountId' is invalid" in r_data.get('message'):
            return 400, "Account Id invalid"
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
        headers['Authorization'] = 'Basic {}'.format(base64.b64encode(auth.encode()).decode())
        return headers


def test_module(client):
    status, message = client.test_client()
    if status == 200:
        return 'ok'
    else:
        return 'Test failed because ......' + message


def get_remote_incident_data(client, incident_ids):
    """
    Gets the remote incident data.
    Args:
        client: The client object.
        incident_id: The incident ID to retrieve.

    Returns:
        mirrored_data: The raw mirrored data.
        updated_object: The updated object to set in the XSOAR incident.
    """
    LOG(f"inside---get_remote_incident_data{incident_ids}")
    return client.get_triage_details(incident_ids)

    # mirrored_data = client.http_request('GET', f'incidents/{incident_id}')
    # incident_mirrored_data = incident_data_to_xsoar_format(mirrored_data, is_fetch_incidents=True)
    # fetch_incidents_additional_info(client, incident_mirrored_data)
    # updated_object: Dict[str, Any] = {}
    #
    # for field in INCOMING_MIRRORED_FIELDS:
    #     if value := incident_mirrored_data.get(field):
    #         updated_object[field] = value
    #
    # return mirrored_data, updated_object


def get_remote_data_command(client, args):
    LOG(f"inside---get_remote_data_command")
    LOG(f"inside---{args}")
    parsed_args = GetRemoteDataArgs(args)

    LOG(f"remote args {parsed_args}")
    new_incident_data = get_remote_incident_data(client, [parsed_args.remote_incident_id])
    LOG(f"new incident data : {new_incident_data}")


def parse_date(since):
    SINCE_DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
    SINCE_DATE_FORMAT_WITH_MILLISECONDS = "%Y-%m-%dT%H:%M:%S.%fZ"
    try:
        return datetime.strptime(since, SINCE_DATE_FORMAT)
    except Exception as e:
        return datetime.strptime(since, SINCE_DATE_FORMAT_WITH_MILLISECONDS)
    except Exception as ee:
        LOG(f"Unable to parse date from input: {since}")
        raise ee


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    LOG(f'input config------: {demisto.params()}')
    secretKey = demisto.params().get("apiSecret").get('identifier')
    accessKey = demisto.params().get('apiKey').get('identifier')
    account = demisto.params().get('accountId')
    # get the service API url
    base_url = demisto.params()['searchLightUrl']
    verify_certificate = not demisto.params().get('insecure', False)

    # How much time before the first fetch to retrieve incidents
    first_fetch_time = demisto.params().get('fetch_time', '3 days').strip()
    fetchLimit = demisto.params().get('fetchLimit')
    sinceDate = demisto.params().get('sinceDate')
    try:
        sinceDate = parse_date(sinceDate)
    except Exception as ee:
        demisto.results('Unable to parse date from input')
    if sinceDate > datetime.now():
        demisto.results('Date should be less than current date')
    proxy = demisto.params().get('proxy', False)
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
        )
        LOG("client initialized ----- test client")
        search_light_request_handler = SearchLightRequestHandler(base_url,
                                                                 account,
                                                                 accessKey,
                                                                 secretKey)
        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            if fetchLimit.isdigit() and int(fetchLimit) > 100:
                demisto.results('fetch limit must be less than 100')
            elif not fetchLimit.isdigit():
                demisto.results('fetch limit must be number')
            result = test_module(searchLightClient)
            demisto.results(result)
        if demisto.command() == 'fetch-indicators':
            LOG(f"inside indicatores-----> ")
            last_event_num = last_run.get('last_fetch', 0)
            LOG(f"last_event_num indicatores-----> ")

            LOG(f"search_light_request_handler_for_indicators indicatores-----> ")

            search_light_indicators_poller = SearchLightIndicatorsPoller(search_light_request_handler)
            LOG(f"search_light_indicators_poller indicatores-----> ")

            poll_result = search_light_indicators_poller.poll_indicators(event_num_start=last_event_num, limit=fetchLimit,
                                                                         event_created_after=sinceDate)
            LOG(f"poll_result indicatores-----> ")

            data = poll_result.data
            last_polled_number = poll_result.max_event_number
            LOG(f"indicatores-----> {data}")
            if data:
                indicators = []
                for item in data:
                    indicator = {
                        'type': item['type'],
                        'fields': {},
                        'occurred': item["created"],
                        'value': item["value"],
                        'service': 'Digital Shadows Feed',
                        'rawJSON': item
                    }
                    indicators.append(indicator)
                for b in batch(indicators, batch_size=10):
                    LOG(f"batch----->{b}")
                    demisto.createIndicators(b)
            demisto.setLastRun({'last_fetch': last_polled_number})
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(
            f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''
if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
