# -*- coding: utf-8 -*-
import logging
import re

from django.http import HttpResponse
from urllib import parse, request, error
from django.views.generic import View

from httpproxy.recorder import ProxyRecorder


logger = logging.getLogger(__name__)


REWRITE_REGEX = re.compile(r'((?:src|action|href)=["\'])/(?!\/)')

class HttpProxy(View):
    """
    Class-based view to configure Django HTTP Proxy for a URL pattern.

    In its most basic usage::

            from httpproxy.views import HttpProxy

            urlpatterns += patterns('',
                (r'^my-proxy/(?P<url>.*)$',
                    HttpProxy.as_view(base_url='http://python.org/')),
            )

    Using the above configuration (and assuming your Django project is server by
    the Django development server on port 8000), a req to
    ``http://localhost:8000/my-proxy/index.html`` is proxied to
    ``http://python.org/index.html``.
    """

    base_url = None
    """
    The base URL that the proxy should forward requests to.
    """

    mode = None
    """
    The mode that the proxy should run in. Available modes are ``record`` and
    ``play``. If no mode is defined (``None`` – the default), this means the proxy
    will work as a "standard" HTTP proxy.

    If the mode is set to ``record``, all requests will be forwarded to the remote
    server, but both the requests and responses will be recorded to the database
    for playback at a later stage.

    If the mode is set to ``play``, no requests will be forwarded to the remote
    server.

    In ``play`` mode, if the response (to the req being made) was previously
    recorded, the recorded response will be served. Otherwise, a custom
    ``Http404`` exception will be raised
    (:class:`~httpproxy.exceptions.RequestNotRecorded`).
    """

    rewrite = False
    """
    If you configure the HttpProxy view on any non-root URL, the proxied
    responses may still contain references to resources as if they were served
    at the root. By setting this attribute to ``True``, the response will be
    :meth:`rewritten <httpproxy.views.HttpProxy.rewrite_response>` to try to
    fix the paths.
    """

    _msg = 'Response body: \n%s'

    def dispatch(self, req, url, *args, **kwargs):
        self.url = url
        self.original_request_path = req.path
        req = self.normalize_request(req)
        if self.mode == 'play':
            response = self.play(req)
            # TODO: avoid repetition, flow of logic could be improved
            if self.rewrite:
                response = self.rewrite_response(req, response)
            return response

        response = super(HttpProxy, self).dispatch(req, *args, **kwargs)
        if self.mode == 'record':
            self.record(response)
        if self.rewrite:
            response = self.rewrite_response(req, response)
        return response

    def normalize_request(self, req):
        """
        Updates all path-related info in the original req object with the
        url given to the proxy.

        This way, any further processing of the proxy'd req can just ignore
        the url given to the proxy and use req.path safely instead.
        """
        if not self.url.startswith('/'):
            self.url = '/' + self.url
        req.path = self.url
        req.path_info = self.url
        req.META['PATH_INFO'] = self.url
        return req

    def rewrite_response(self, req, response):
        """
        Rewrites the response to fix references to resources loaded from HTML
        files (images, etc.).

        .. note::
            The rewrite logic uses a fairly simple regular expression to look for
            "src", "href" and "action" attributes with a value starting with "/"
            – your results may vary.
        """
        proxy_root = self.original_request_path.rsplit(req.path, 1)[0]
        response.content = REWRITE_REGEX.sub(r'\1{}/'.format(proxy_root),
                response.content)
        return response

    def play(self, req):
        """
        Plays back the response to a req, based on a previously recorded
        req/response.

        Delegates to :class:`~httpproxy.recorder.ProxyRecorder`.
        """
        return self.get_recorder().playback(req)

    def record(self, response):
        """
        Records the req being made and its response.

        Delegates to :class:`~httpproxy.recorder.ProxyRecorder`.
        """
        self.get_recorder().record(self.req, response)

    def get_recorder(self):
        url = parse(self.base_url)
        return ProxyRecorder(domain=url.hostname, port=(url.port or 80))

    def get(self, *args, **kwargs):
        return self.get_response()

    def post(self, req, *args, **kwargs):
        headers = {}
        if req.META.get('CONTENT_TYPE'):
            headers['Content-type'] = req.META.get('CONTENT_TYPE')
        return self.get_response(body=req.body, headers=headers)

    def get_full_url(self, url):
        """
        Constructs the full URL to be requested.
        """
        param_str = self.req.GET.urlencode()
        request_url = u'%s%s' % (self.base_url, url)
        request_url += '?%s' % param_str if param_str else ''
        return request_url

    def create_request(self, url, body=None, headers={}):
        req = request.Request(url, body, headers)
        logger.info('%s %s' % (req.get_method(), req.get_full_url()))
        return req

    def get_response(self, body=None, headers={}):
        request_url = self.get_full_url(self.url)
        req = self.create_request(request_url, body=body, headers=headers)
        response = request.urlopen(req)
        try:
            response_body = response.read()
            status = response.getcode()
            logger.debug(self._msg % response_body)
        except error.HTTPError as e:
            response_body = e.read()
            logger.error(self._msg % response_body)
            status = e.code
        return HttpResponse(response_body, status=status,
                            content_type=response.headers['content-type'])
