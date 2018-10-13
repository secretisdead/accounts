from functools import wraps
import time
import hashlib

from flask import g
from flask import request, after_this_request, url_for, abort, redirect
from werkzeug import UserAgent
import urllib

from .. import Accounts

def initialize(config, access_log, engine, install):
	g.accounts = Accounts(config, access_log, engine, install=install)

	# use default avatar file uri if custom uri isn't specified
	if not g.accounts.config['avatar_file_uri']:
		g.accounts.config['avatar_file_uri'] = url_for(
			'accounts_signed_out.avatar_file',
			avatar_filename='AVATAR_FILENAME'
		).replace('AVATAR_FILENAME', '{}')

	# cookie session
	if g.accounts.config['session']['name'] in request.cookies:
		session_id = request.cookies[g.accounts.config['session']['name']]
		if not g.accounts.populate_current_user(
				request.remote_addr,
				request.user_agent,
				session_id,
			):
			clear_session_cookie()
		return

	return
	#TODO cert authentication

# session cookie handling
def set_session_cookie(session):
	@after_this_request
	def set_session_cookie(response):
		opts = {
			'value': session.id,
			'expires': (time.time() + g.accounts.config['session']['lifetime']),
			'secure': g.accounts.config['session']['secure'],
		}
		if g.accounts.config['session']['domain']:
			opts['domain'] = g.accounts.config['session']['domain']
		if g.accounts.config['session']['path']:
			opts['path'] = g.accounts.config['session']['path']

		response.set_cookie(g.accounts.config['session']['name'], **opts)
		return response

def clear_session_cookie():
	@after_this_request
	def clear_session_cookie(response):
		opts = {
			'value': '',
			'expires': time.time() - 1,
			'secure': g.accounts.config['session']['secure'],
		}
		if g.accounts.config['session']['domain']:
			opts['domain'] = g.accounts.config['session']['domain']
		if g.accounts.config['session']['path']:
			opts['path'] = g.accounts.config['session']['path']

		response.set_cookie(g.accounts.config['session']['name'], **opts)
		return response

# require objects or abort
def require_user(**kwargs):
	try:
		user = g.accounts.require_user(**kwargs)
	except ValueError as e:
		abort(404, str(e))
	else:
		return user

def require_session(id):
	try:
		session = g.accounts.require_session(id)
	except ValueError as e:
		abort(404, str(e))
	else:
		return session

def require_invite(id):
	try:
		invite = g.accounts.require_invite(id)
	except ValueError as e:
		abort(404, str(e))
	else:
		return invite

# decorators for calling accounts methods in request context
# after g.accounts exists
def require_sign_in(f):
	@wraps(f)
	def decorated_function(*args, **kwargs):
		try:
			g.accounts.require_sign_in()
		except ValueError as e:
			abort(401, str(e))
		return f(*args, **kwargs)
	return decorated_function

def require_permissions(**decorator_kwargs):
	def decorator(f):
		@wraps(f)
		@require_sign_in
		def decorated_function(*args, **kwargs):
			try:
				g.accounts.require_permissions(**decorator_kwargs)
			except ValueError as e:
				abort(403, str(e))
			return f(*args, **kwargs)
		return decorated_function
	return decorator

def populate_sessions_useragents(sessions):
	for session in sessions.values():
		session.useragent = UserAgent(session.useragent)

def try_third_party_auth_request(f):
	try:
		result = f()
	# communication error during authentication
	except urllib.error.HTTPError as e:
		abort(500, str(e))
	# non-success response from service
	except urllib.error.URLError as e:
		abort(500, str(e))
	# empty response from service
	except ValueError as e:
		abort(500, str(e))
	# couldn't validate response
	except ArithmeticError as e:
		abort(400, str(e))
	# something else went wrong
	except Exception as e:
		abort(500, str(e))
	else:
		return result

def register_third_party_auth(service, action):
	service_credentials = {}
	if service in g.accounts.config['credentials']:
		service_credentials = g.accounts.config['credentials'][service]

	from thirdpartyauth import third_party_auth

	try:
		auth = third_party_auth(service, service_credentials)
	except KeyError as e:
		abort(500, str(e))
	except ValueError as e:
		abort(400, str(e))
	except Exception:
		abort(500)

	redirect_uri = url_for(
		'accounts_signed_out.authentication_landing',
		_external=True
	)
	state = action + ',' + service

	# if the auth doesn't have the request args it needs
	# then do redirect to service to get them
	if auth.requires_redirect():
		authentication_uri = try_third_party_auth_request(
			lambda: auth.authentication_uri(redirect_uri, state)
		)
		return redirect(authentication_uri)

	# otherwise do backend request to service to get authentication value
	value = try_third_party_auth_request(
		lambda: auth.authentication_value(redirect_uri, state)
	)

	authentications = g.accounts.search_authentications(
		filter={
			'services': service,
			'values': value,
		},
	)
	#TODO status page errors should come from accounts package exceptions
	#TODO break this up and move it to a main accounts method at some point
	authentication = None
	if authentications.values():
		authentication = authentications.values()[0]
		if authentication.forbidden:
			if g.accounts.current_user:
				#TODO deactivate current user 
				#TODO that tried to connect forbidden authentication?
				pass
			abort(403, 'Authentication has been forbidden')
		if not authentication.user:
			#TODO silent removal and re-registration of authentication
			#TODO tied to non-existant user?
			abort(400, 'Authentication tied to non-existant user')
		redirect_endpoint = g.accounts.config['home_endpoint']
		if not g.accounts.current_user:
			g.accounts.sign_in(
				authentication.user,
				str(request.remote_addr),
				str(request.user_agent),
			)
			set_session_cookie(g.accounts.current_user.session)
		elif authentication.user.id != g.accounts.current_user.id:
			g.accounts.access_log.create_log(
				'authentication_collision',
				subject_id=self.current_user.id_bytes,
				object_id=authentication.id_bytes,
			)
			abort(403, 'This authentication already exists for a different user')
	else:
		redirect_endpoint = 'accounts_signed_in.settings'
		g.accounts.register(
			service,
			value, 
			str(request.remote_addr),
			str(request.user_agent),
		)
		set_session_cookie(g.accounts.current_user.session)
	return redirect(url_for(redirect_endpoint), 303)
