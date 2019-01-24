import base64
import time
import os

from flask import Blueprint, render_template, abort, request, redirect
from flask import url_for, g, current_app, send_from_directory

from . import set_session_cookie, require_sign_in, require_user
from . import require_session, require_invite, register_third_party_auth

accounts_signed_out = Blueprint(
	'accounts_signed_out',
	__name__,
	template_folder='templates',
)

@accounts_signed_out.route('/sign-in')
def sign_in_services(*args, **kwargs):
	if g.accounts.current_user:
		return redirect(url_for(g.accounts.config['home_endpoint']), code=303)
	return render_template(
		'sign_in_services.html',
		endpoint='accounts_signed_out.sign_in',
		**kwargs
	), 401

def validate_service(service):
	try:
		g.accounts.validate_service(service)
	except KeyError as e:
		abort(400, str(e))
	except ValueError:
		abort(400, str(e))

def validate_invite(service):
	if g.accounts.config['registration_closed']:
		if 'invite' not in request.args:
			return redeem_invite(service)
		invite = require_invite(request.args['invite'])
		if 0 > invite.redeem_time:
			abort(400, 'Invite already redeemed')
		expiration_time = int(time.time()) - g.accounts.config['invite_lifetime']
		if invite.creation_time < expiration_time:
			abort(400, 'Invite expired')
		return invite
	return None

@accounts_signed_out.route('/redeem-invite')
@accounts_signed_out.route('/redeem-invite/<service>')
def redeem_invite(service=None):
	if g.accounts.current_user:
		return redirect(url_for(g.accounts.config['home_endpoint']), code=303)
	invite = ''
	if 'invite' in request.args:
		invite = request.args['invite']
	if not service:
		return render_template(
			'sign_in_services.html',
			endpoint='accounts_signed_out.register',
			invite=invite,
		)
	return render_template('redeem_invite.html', invite=invite)

def register_local():
	if g.accounts.register_cooldown():
		abort(
			429,
			(
				'Too many registrations from this remote origin, '
					+ 'please wait before creating another account'
			),
		)
	invite = validate_invite('local')
	if 'POST' != request.method:
		return render_template('register_local.html')
	for field in ['account_name', 'pass', 'pass_confirmation']:
		if field not in request.form:
			abort(400, 'Missing local registration fields')
	errors = g.accounts.register_local(
		request.form['account_name'],
		request.form['pass'],
		request.form['pass_confirmation'],
		str(request.remote_addr),
		str(request.user_agent),
	)
	if errors:
		return render_template(
			'register_local.html',
			account_name=request.form['account_name'],
			errors=errors,
		)
	if invite:
		g.accounts.redeem_invite(
			invite.id_bytes,
			g.accounts.current_user.id_bytes,
		)
	set_session_cookie(g.accounts.current_user.session)
	return redirect(url_for('accounts_signed_in.settings'), 303)

def sign_in_local():
	if 'POST' != request.method:
		return render_template('sign_in_local.html')
	for field in ['account_name', 'pass']:
		if field not in request.form:
			abort(400, 'Missing local sign-in fields')
	errors = g.accounts.sign_in_local(
		request.form['account_name'],
		request.form['pass'],
		str(request.remote_addr),
		str(request.user_agent),
	)
	if errors:
		return render_template(
			'sign_in_local.html',
			account_name=request.form['account_name'],
			errors=errors,
		)
	set_session_cookie(g.accounts.current_user.session)
	return redirect(url_for(g.accounts.config['home_endpoint']), 303)

@accounts_signed_out.route('/sign-in/<service>', methods=['GET', 'POST'])
def sign_in(service, register=False, **kwargs):
	if g.accounts.current_user:
		return redirect(url_for(g.accounts.config['home_endpoint']), code=303)
	validate_service(service)
	if (
			g.accounts.sign_in_attempt_cooldown()
			or g.accounts.authentication_collision_cooldown()
		):
		abort(429, 'Too many sign in attempts, please wait before trying again')
	if 'local' == service:
		if register:
			return register_local()
		return sign_in_local()
	elif 'cert' == service:
		#TODO register cert
		return 'register client cert'
	elif 'mail' == service:
		#TODO sign in mail
		return 'sign in by mail code'
	else:
		return register_third_party_auth(service, 'sign_in')

@accounts_signed_out.route('/register/<service>', methods=['GET', 'POST'])
def register(service, **kwargs):
	return sign_in(service, register=True, **kwargs)

@accounts_signed_out.route('/authenticate')
def authentication_landing():
	if 'state' not in request.args and 'openid.state' not in request.args:
		# state should be returned so we know what action and service to handle
		abort(400)
	action, service = request.args['state'].split(',')
	if 'connect' == action:
		endpoint = 'accounts_signed_in.add_authentication'
	elif 'sign_in' == action:
		endpoint = 'accounts_signed_out.sign_in'
	else:
		abort(400)
	kwargs = {}
	if 'code' in request.args:
		# pass only oauth code
		kwargs['code'] = request.args['code']
	elif 'openid.identity' in request.args:
		# pass all query params for openid to verify
		kwargs = request.args
	else:
		# pass only oauth query params
		for arg in request.args:
			if 'oauth_' == arg[:6]:
				kwargs[arg] = request.args[arg]
	return redirect(
		url_for(
			endpoint,
			service=service,
			**kwargs,
		),
		code=303,
	)

@accounts_signed_out.route('/profile')
@accounts_signed_out.route('/profile/<user_identifier>')
def profile(user_identifier=''):
	if not user_identifier:
		if not g.accounts.current_user:
			return redirect(url_for(g.accounts.config['home_endpoint']), code=303)
		user = g.accounts.current_user
	else:
		user = require_user(identifier=user_identifier)
	return render_template('user_profile.html', user=user)

@accounts_signed_out.route('/avatar/<avatar_filename>')
def avatar_file(avatar_filename):
	if '.' not in avatar_filename:
		avatar_filename += '.webp'
	if not os.path.exists(
			os.path.join(
				g.accounts.config['avatars_path'],
				avatar_filename,
			)
		):
		abort(404)
	return send_from_directory(
		g.accounts.config['avatars_path'],
		avatar_filename,
		conditional=True,
	)
