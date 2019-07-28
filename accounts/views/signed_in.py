from flask import Blueprint, render_template, abort, request, redirect
from flask import url_for, g

from . import clear_session_cookie, require_sign_in, require_session
from . import require_invite, populate_sessions_useragents
from . import register_third_party_auth

accounts_signed_in = Blueprint(
	'accounts_signed_in',
	__name__,
	template_folder='templates',
	static_folder='static',
	static_url_path='/static/accounts',
)

@accounts_signed_in.route('/sign-out')
@require_sign_in
def sign_out():
	g.accounts.populate_user_authentications(g.accounts.current_user)
	if 'cert' in g.accounts.current_user.authentications:
		return render_template('unable_to_sign_out_cert.html')
	clear_session_cookie()
	g.accounts.sign_out()
	return redirect(url_for(g.accounts.config['home_endpoint']), code=307)

@accounts_signed_in.route('/settings', methods=['GET', 'POST'])
@require_sign_in
def settings():
	user = g.accounts.current_user
	sessions = g.accounts.search_sessions(
		filter={'user_ids': user.id_bytes},
	)
	populate_sessions_useragents(sessions)
	invites = g.accounts.search_invites(
		filter={'created_by_user_ids': user.id_bytes},
	)
	g.accounts.populate_user_authentications(user)
	if 'POST' != request.method:
		return render_template(
			'user_settings.html',
			user=user,
			redeemed_invite=g.accounts.get_redeemed_invite(user.id_bytes),
			name=user.name,
			display=user.display,
			sessions=sessions,
			invites=invites,
		)
	for field in ['name', 'display']:
		if field not in request.form:
			abort(400, 'Missing user settings fields')
	opts = {
		'name': request.form['name'],
		'display': request.form['display'],
	}
	if 'remove_avatar' in request.form:
		opts['remove_avatar'] = True
	elif 'avatar' in request.files and '' != request.files['avatar'].filename:
		opts['avatar'] = request.files['avatar']
	errors = g.accounts.edit_user_settings(user, **opts)
	if not errors:
		return redirect(url_for('accounts_signed_in.settings'), code=303)
	return render_template(
		'user_settings.html',
		user=user,
		redeemed_invite=g.accounts.get_redeemed_invite(user.id_bytes),
		name=request.form['name'],
		display=request.form['display'],
		sessions=sessions,
		invites=invites,
		errors=errors,
	)

@accounts_signed_in.route('/sessions/close')
@require_sign_in
def close_all_sessions():
	clear_session_cookie()
	g.accounts.close_all_sessions(g.accounts.current_user.id_bytes)
	return redirect(url_for(g.accounts.config['home_endpoint']), code=303)

@accounts_signed_in.route('/sessions/<session_id>/close')
@require_sign_in
def close_session(session_id):
	if (
			hasattr(g.accounts.current_user, 'session')
			and session_id == g.accounts.current_user.session.id
		):
		return sign_out()
	session = require_session(session_id)
	if session.user_id != g.accounts.current_user.id:
		abort(403)
	g.accounts.close_session(
		session.id_bytes,
		user_id=g.accounts.current_user.id_bytes,
	)
	return redirect(url_for('accounts_signed_in.settings'), code=303)

@accounts_signed_in.route('/create_invite')
@require_sign_in
def create_invite():
	#TODO limit invitation creation to certain users?
	if g.accounts.create_invite_cooldown(g.accounts.current_user.id_bytes):
		abort(
			429,
			(
				'Too many invite creation attempts, '
					+ 'please wait before creating another invite'
			)
		)
	try:
		invite = g.accounts.create_invite(g.accounts.current_user.id_bytes)
	except ValueError as e:
		abort(400, str(e))
	return render_template('invite_created.html', invite=invite)

@accounts_signed_in.route('/invites/<invite_id>/remove')
@require_sign_in
def remove_invite(invite_id):
	invite = require_invite(invite_id)
	if invite.created_by_user_id != g.accounts.current_user.id:
		abort(403)
	try:
		g.accounts.delete_invite(
			invite,
			user_id=g.accounts.current_user.id_bytes,
		)
	except ValueError as e:
		abort(400, str(e))
	return redirect(url_for('accounts_signed_in.settings'), code=303)

@accounts_signed_in.route('/authentication/<service>/add', methods=['GET', 'POST'])
@require_sign_in
def add_authentication(service):
	if 'local' == service:
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
		return redirect(url_for('accounts_signed_in.settings'), code=303)
	return register_third_party_auth(service, 'connect')

@accounts_signed_in.route('/authentication/<service>/remove')
@require_sign_in
def remove_authentication(service):
	g.accounts.populate_user_authentications(g.accounts.current_user)
	if (
			1 == len(g.accounts.current_user.authentications.items())
			and 'confirm' not in request.args
		):
		return render_template(
			'confirm_remove_final_authentication.html',
			service=service,
		)
	g.accounts.remove_current_user_authentication_by_service(service)
	return redirect(url_for('accounts_signed_in.settings'), code=303)

@accounts_signed_in.route('/deactivate')
@require_sign_in
def deactivate():
	if 'confirm' not in request.args:
		return render_template('confirm_deactivate_self.html')
	g.accounts.deactivate_user(g.accounts.current_user.id_bytes)
	clear_session_cookie()
	return redirect(url_for(g.accounts.config['home_endpoint']), code=303)

@accounts_signed_in.route('/redeem-permission')
@require_sign_in
def redeem_auto_permission():
	if 'permission_code' not in request.args:
		return render_template('redeem_auto_permission.html')
	auto_permission = g.accounts.get_auto_permission(
		request.args['permission_code']
	)
	if not auto_permission:
		abort(400, 'Redeemable permission not found')
	if auto_permission.valid_from_time:
		print(auto_permission.valid_from_time)
		abort(400, 'Permission has already been redeemed')
	if (
			auto_permission.user
			and auto_permission.user.id != g.accounts.current_user.id
		):
		abort(400, 'This permission is associated with another account')
	if 'confirm' not in request.args:
		return render_template(
			'redeem_auto_permission.html',
			auto_permission=auto_permission,
		)
	g.accounts.redeem_auto_permission(auto_permission, g.accounts.current_user.id_bytes)
	return redirect(url_for('accounts_signed_out.profile'), code=303)
