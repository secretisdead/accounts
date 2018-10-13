import math
import json
import urllib

from flask import Blueprint, render_template, abort, request, redirect
from flask import url_for, g
import dateutil.parser

from . import clear_session_cookie, require_permissions, require_user
from . import require_session, require_invite, populate_sessions_useragents
from pagination_from_request import pagination_from_request

accounts_manager = Blueprint(
	'accounts_manager',
	__name__,
	template_folder='templates',
	static_folder='static',
	static_url_path='/static/accounts',
)

# users
@accounts_manager.route('/users')
@require_permissions(group_names='manager')
def users_list():
	search = {
		'id': '',
		'created_before': '',
		'created_after': '',
		'name': '',
		'display': '',
		'status': '',
		'protection': '',
	}
	for field in search:
		if field in request.args:
			search[field] = request.args[field]

	filter = {}
	escape = lambda value: (
		value
			.replace('\\', '\\\\')
			.replace('_', '\_')
			.replace('%', '\%')
			.replace('-', '\-')
	)
	# for parsing datetime and timestamp from submitted form
	# filter fields are named the same as search fields
	time_fields = [
		'created_before',
		'created_after',
	]
	for field, value in search.items():
		if value:
			if 'id' == field:
				filter['ids'] = value
			elif field in time_fields:
				try:
					parsed = dateutil.parser.parse(value)
				except ValueError:
					filter[field] = 'bad_query'
				else:
					search[field] = parsed.strftime('%Y-%m-%dT%H:%M:%S.%f%z')
					filter[field] = parsed.timestamp()
			elif 'name' == field:
				filter['names'] = '%' + escape(value) + '%'
			elif 'display' == field:
				filter['displays'] = '%' + escape(value) + '%'
			elif 'status' == field:
				filter['statuses'] = value
			elif 'protection' == field:
				filter['protection'] = ('protected' == value)

	pagination = pagination_from_request('last_seen_time', 'desc', 0, 32)

	total_results = g.accounts.count_users(filter=filter)
	results = g.accounts.search_users(filter=filter, **pagination)

	return render_template(
		'users_list.html',
		results=results,
		search=search,
		pagination=pagination,
		total_results=total_results,
		total_pages=math.ceil(total_results / pagination['perpage']),
	)

@accounts_manager.route('/users/<user_id>', methods=['GET', 'POST'])
@require_permissions(group_names='manager')
def edit_user(user_id):
	if (
			user_id == g.accounts.current_user.id
			and not g.accounts.current_user.has_permission(group_names='admin')
		):
		return redirect(url_for('accounts_signed_in.settings'), code=303)
	user = require_user(id=user_id)
	sessions = g.accounts.search_sessions(filter={'user_ids': user.id_bytes})
	populate_sessions_useragents(sessions)
	invites = g.accounts.search_invites(
		filter={'created_by_user_ids': user.id_bytes},
	)
	g.accounts.populate_user_authentications(user)
	g.accounts.populate_user_permissions(user)
	selected_groups = {}
	for scope in g.accounts.available_scopes:
		if scope not in user.permissions:
			continue
		if scope not in selected_groups:
			selected_groups[scope] = []
		for group_name in g.accounts.available_groups:
			if g.accounts.contains_all_bits(
					user.permissions[scope].group_bits,
					g.accounts.group_name_to_bit(group_name),
				):
				selected_groups[scope].append(group_name)
	groups = g.accounts.available_groups.copy()
	if not g.accounts.current_user.has_permission(group_names='admin'):
		for group_name in ['admin', 'manager']:
			if group_name in groups:
				groups.remove(group_name)

	if 'POST' != request.method:
		return render_template(
			'edit_user.html',
			user=user,
			redeemed_invite=g.accounts.get_redeemed_invite(user.id_bytes),
			name=user.name,
			display=user.display,
			sessions=sessions,
			invites=invites,
			groups=groups,
			selected_groups=selected_groups,
		)
	if 'permissions_submit' in request.form:
		if 'protected' in request.form:
			g.accounts.protect_user(user.id)
		else:
			g.accounts.unprotect_user(user.id)
		permissions = {}
		for scope in g.accounts.available_scopes:
			for group_name in g.accounts.available_groups:
				if 'scope_' + scope + '_group_' + group_name in request.form:
					if (
							'admin' == group_name
							or 'manager' == group_name
						):
						require_permissions(group_names='admin')
					if scope not in permissions:
						permissions[scope] = []
					permissions[scope].append(group_name)
		g.accounts.set_user_permissions(user, permissions)
		return redirect(
			url_for('accounts_manager.edit_user', user_id=user.id),
			code=303,
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
	elif 'avatar' in request.files:
		opts['avatar'] = request.files['avatar']
	errors = g.accounts.edit_user_settings(user, **opts)
	if not errors:
		return redirect(
			url_for('accounts_manager.edit_user', user_id=user.id),
			code=303,
		)
	return render_template(
		'user_settings.html',
		user=user,
		redeemed_invite=g.accounts.get_redeemed_invite(user.id_bytes),
		name=request.form['name'],
		display=request.form['display'],
		sessions=sessions,
		invites=invites,
		errors=errors,
		groups=groups,
		selected_groups=selected_groups,
	)

@accounts_manager.route('/users/<user_id>/activate')
@require_permissions(group_names='manager')
def activate_user(user_id):
	user = require_user(id=user_id)
	g.accounts.activate_user(user.id_bytes)
	return redirect(
		url_for('accounts_manager.edit_user', user_id=user.id),
		code=303,
	)

@accounts_manager.route('/users/<user_id>/deactivate')
@require_permissions(group_names='manager')
def deactivate_user(user_id):
	user = require_user(id=user_id)
	if 'confirm' not in request.args:
		return render_template('confirm_deactivate_user.html', user_id=user.id)
	user = g.accounts.deactivate_user(user.id_bytes)
	return redirect(
		url_for('accounts_manager.edit_user', user_id=user.id),
		code=303,
	)

# permissions
@accounts_manager.route('/permissions')
@require_permissions(group_names='manager')
def permissions_list():
	search = {
		'id': '',
		'created_before': '',
		'created_after': '',
		'user': '',
		'scope': '',
	}
	for group_name in g.accounts.available_groups:
		search.update({'group_' + group_name: ''})
	for field in search:
		if field in request.args:
			search[field] = request.args[field]

	filter = {}
	group_bits = 0
	# for parsing datetime and timestamp from submitted form
	# filter fields are named the same as search fields
	time_fields = [
		'created_before',
		'created_after',
	]
	for field, value in search.items():
		if value:
			if 'id' == field:
				filter['ids'] = value
			elif field in time_fields:
				try:
					parsed = dateutil.parser.parse(value)
				except ValueError:
					filter[field] = 'bad_query'
				else:
					search[field] = parsed.strftime('%Y-%m-%dT%H:%M:%S.%f%z')
					filter[field] = parsed.timestamp()
			elif 'user' == field:
				filter['user_ids'] = value
			elif 'scope' == field:
				if 'global' == value:
					value = ''
				filter['scopes'] = value
	selected_groups = []
	for group in g.accounts.available_groups:
		if 'group_' + group in request.form:
			selected_groups.append(group)
	if selected_groups:
		filter['with_group_bits'] = g.accounts.combine_groups(
			names=selected_groups,
		)

	pagination = pagination_from_request('creation_time', 'desc', 0, 32)

	total_results = g.accounts.count_permissions(filter=filter)
	results = g.accounts.search_permissions(filter=filter, **pagination)

	return render_template(
		'permissions_list.html',
		results=results,
		search=search,
		pagination=pagination,
		total_results=total_results,
		total_pages=math.ceil(total_results / pagination['perpage']),
	)

# auto permissions
@accounts_manager.route('/auto-permissions')
@require_permissions(group_names='manager')
def auto_permissions_list():
	search = {
		'id': '',
		'created_before': '',
		'created_after': '',
		'created_by_user': '',
		'duration_shorter_than': '',
		'duration_longer_than': '',
		'scope': '',
		'user': '',
		'valid_from': '',
		'valid_until': '',
	}
	for group_name in g.accounts.available_groups:
		search.update({'group_' + group_name: ''})
	for field in search:
		if field in request.args:
			search[field] = request.args[field]

	filter = {}
	group_bits = 0
	# for parsing datetime and timestamp from submitted form
	# filter fields are named the same as search fields
	time_fields = [
		'created_before',
		'created_after',
		'valid_from',
		'valid_until',
	]
	for field, value in search.items():
		if value:
			if 'id' == field:
				filter['ids'] = value
			elif field in time_fields:
				try:
					parsed = dateutil.parser.parse(value)
				except ValueError:
					filter[field] = 'bad_query'
				else:
					search[field] = parsed.strftime('%Y-%m-%dT%H:%M:%S.%f%z')
					filter[field] = parsed.timestamp()
			elif 'created_by_user' == field:
				if 'system' == value:
					value = ''
				filter['created_by_user_ids'] = value
			elif 'duration_longer_than' == field:
				filter['duration_longer_than'] = value
			elif 'duration_shorter_than' == field:
				filter['duration_shorter_than'] = value
			elif 'scope' == field:
				if 'global' == value:
					value = ''
				filter['scopes'] = value
			elif 'user' == field:
				filter['user_ids'] = value
			elif 'group_' == field[:6]:
				group_bits = g.accounts.combine_groups(bits=[group_bits], names=[field[6:]])
	if group_bits:
		filter['with_group_bits'] = group_bits

	pagination = pagination_from_request('creation_time', 'desc', 0, 32)

	total_results = g.accounts.count_auto_permissions(filter=filter)
	results = g.accounts.search_auto_permissions(filter=filter, **pagination)

	return render_template(
		'auto_permissions_list.html',
		results=results,
		search=search,
		pagination=pagination,
		total_results=total_results,
		total_pages=math.ceil(total_results / pagination['perpage']),
	)

@accounts_manager.route('/auto-permissions/create', methods=['GET', 'POST'])
@require_permissions(group_names='manager')
def create_auto_permissions():
	if 'POST' != request.method:
		return render_template('create_auto_permissions.html')
	for field in ['duration', 'user_id']:
		if field not in request.form:
			abort(400, 'Missing auto permissions fields')
	errors = []
	if request.form['user_id']:
		try:
			user = g.accounts.require_user(id=request.form['user_id'])
		except ValueError as e:
			errors.append(str(e))
	if not errors:
		groups_selected = False
		for scope in g.accounts.available_scopes:
			selected_groups = []
			for group in g.accounts.available_groups:
				if 'scope_' + scope + '_group_' + group in request.form:
					selected_groups.append(group)
			if selected_groups:
				groups_selected = True
				g.accounts.create_auto_permission(
					duration=request.form['duration'],
					user_id=request.form['user_id'],
					scope=scope,
					group_bits=g.accounts.combine_groups(names=selected_groups),
					created_by_user_id=g.accounts.current_user.id,
				)
		if not groups_selected:
			errors.append('No groups were selected')
	if errors:
		#TODO store submitted form fields and populate them in the failed form?
		#TODO this panel probably won't be used often manually
		return render_template('create_auto_permissions.html', errors=errors)
	return redirect(
		url_for('accounts_manager.auto_permissions_list'),
		code=303,
	)

@accounts_manager.route('/auto-permissions/sync')
@require_permissions(group_names='manager')
def sync_auto_permissions():
	g.accounts.sync_auto_permissions(
		sync_initiated_by_user_id=g.accounts.current_user.id,
	)
	return redirect(
		url_for('accounts_manager.auto_permissions_list'),
		code=303,
	)

@accounts_manager.route('/auto-permissions/<auto_permission_id>/remove')
@require_permissions(group_names='manager')
def remove_auto_permission(auto_permission_id):
	auto_permission = g.accounts.get_auto_permission(auto_permission_id)
	if not auto_permission:
		abort(404, 'Auto permission not found')
	g.accounts.delete_auto_permission(
		auto_permission,
		g.accounts.current_user.id_bytes,
	)
	return redirect(
		url_for('accounts_manager.auto_permissions_list'),
		code=303,
	)

# sessions
@accounts_manager.route('/sessions')
@require_permissions(group_names='manager')
def sessions_list():
	search = {
		'id': '',
		'created_before': '',
		'created_after': '',
		'user': '',
		'remote_origin': '',
		'touched_before': '',
		'touched_after': '',
		'closed_before': '',
		'closed_after': '',
	}
	for field in search:
		if field in request.args:
			search[field] = request.args[field]

	filter = {}
	# for parsing datetime and timestamp from submitted form
	# filter fields are named the same as search fields
	time_fields = [
		'created_before',
		'created_after',
		'touched_before',
		'touched_after',
		'closed_before',
		'closed_after',
	]
	for field, value in search.items():
		if value:
			if 'id' == field:
				filter['ids'] = value
			elif field in time_fields:
				try:
					parsed = dateutil.parser.parse(value)
				except ValueError:
					filter[field] = 'bad_query'
				else:
					search[field] = parsed.strftime('%Y-%m-%dT%H:%M:%S.%f%z')
					filter[field] = parsed.timestamp()
			elif 'user' == field:
				filter['user_ids'] = value
			elif 'remote_origin' == field:
				filter['with_remote_origins'] = value

	pagination = pagination_from_request('touch_time', 'desc', 0, 32)

	total_results = g.accounts.count_sessions(filter=filter)
	results = g.accounts.search_sessions(filter=filter, **pagination)

	populate_sessions_useragents(results)

	return render_template(
		'sessions_list.html',
		results=results,
		search=search,
		pagination=pagination,
		total_results=total_results,
		total_pages=math.ceil(total_results / pagination['perpage']),
	)

@accounts_manager.route('/sessions/<session_id>/close')
@require_permissions(group_names='manager')
def close_session(session_id):
	session = require_session(session_id)
	g.accounts.close_session(
		g.accounts.current_user.id_bytes,
		session.id_bytes,
	)
	return redirect(
		url_for('accounts_manager.edit_user', user_id=session.user_id),
		code=303,
	)

@accounts_manager.route('/users/<user_id>/sessions/close')
@require_permissions(group_names='manager')
def close_all_sessions(user_id):
	user = require_user(id=user_id)
	g.accounts.close_all_sessions(user.id_bytes)
	return redirect(
		url_for('accounts_manager.edit_user', user_id=user.id),
		code=303,
	)

# authentications
@accounts_manager.route('/authentications')
@require_permissions(group_names='manager')
def authentications_list():
	search = {
		'created_before': '',
		'created_after': '',
		'user': '',
		'service': '',
	}
	for field in search:
		if field in request.args:
			search[field] = request.args[field]

	filter = {}
	# for parsing datetime and timestamp from submitted form
	# filter fields are named the same as search fields
	time_fields = [
		'created_before',
		'created_after',
	]
	for field, value in search.items():
		if value:
			if field in time_fields:
				try:
					parsed = dateutil.parser.parse(value)
				except ValueError:
					filter[field] = 'bad_query'
				else:
					search[field] = parsed.strftime('%Y-%m-%dT%H:%M:%S.%f%z')
					filter[field] = parsed.timestamp()
			elif 'user' == field:
				filter['user_ids'] = value
			elif 'service' == field:
				filter['services'] = value

	pagination = pagination_from_request('creation_time', 'desc', 0, 32)

	total_results = g.accounts.count_authentications(filter=filter)
	results = g.accounts.search_authentications(filter=filter, **pagination)

	return render_template(
		'authentications_list.html',
		results=results,
		search=search,
		pagination=pagination,
		total_results=total_results,
		total_pages=math.ceil(total_results / pagination['perpage']),
	)

@accounts_manager.route('/users/<user_id>/authentication/<service>')
@require_permissions(group_names='manager')
def view_user_authentication(user_id, service):
	user = require_user(id=user_id)
	g.accounts.populate_user_authentications(user)
	if service not in user.authentications:
		abort(404, 'Authentication not found')
	authentication = user.authentications[service]
	return render_template(
		'view_user_authentication.html',
		authentication=authentication,
	)

@accounts_manager.route('/users/<user_id>/authentication/<service>/profile')
@require_permissions(group_names='manager')
def authentication_redirect(user_id, service):
	user = require_user(id=user_id)
	g.accounts.populate_user_authentications(user)
	if service not in user.authentications:
		abort(404, 'Authentication not found')
	authentication = user.authentications[service]
	service_profile_uris = {
		'local': url_for(
			'accounts_signed_out.profile',
			user_identifier=authentication.user.id,
		),
		'google': 'https://plus.google.com/{}',
		'twitter': 'https://twitter.com/intent/user?user_id={}',
		'patreon': 'https://www.patreon.com/user?u={}',
		'discord': 'https://discordapp.com/users/{}',
		'steam': 'https://steamcommunity.com/profiles/{}',
		'twitch': 'https://api.twitch.tv/helix/users?id={}',
	}
	if 'github' == authentication.service:
		# get actual github user page from user id
		req = urllib.request.Request(
			'https://api.github.com/user/{}'.format(authentication.value)
		)
		req.add_header('User-Agent', 'Accounts App')
		#req.add_header('Accept', 'application/json')
		response = urllib.request.urlopen(req)
		user_info = json.loads(response.read())
		service_profile_uri = user_info['html_url']
	elif authentication.service in service_profile_uris:
		service_profile_uri = service_profile_uris[authentication.service].format(
			authentication.value
		)
	else:
		abort(400, 'Couldn\'t get profile for the specified authentication')
	return redirect(service_profile_uri, code=303)

# invites
@accounts_manager.route('/invites')
@require_permissions(group_names='manager')
def invites_list():
	search = {
		'id': '',
		'created_before': '',
		'created_after': '',
		'created_by_user': '',
		'redeemed_before': '',
		'redeemed_after': '',
		'redeemed_by_user': '',
	}
	for field in search:
		if field in request.args:
			search[field] = request.args[field]

	filter = {}
	# for parsing datetime and timestamp from submitted form
	# filter fields are named the same as search fields
	time_fields = [
		'created_before',
		'created_after',
		'redeemed_before',
		'redeemed_after',
	]
	for field, value in search.items():
		if value:
			if 'id' == field:
				filter['ids'] = value
			elif field in time_fields:
				try:
					parsed = dateutil.parser.parse(value)
				except ValueError:
					filter[field] = 'bad_query'
				else:
					search[field] = parsed.strftime('%Y-%m-%dT%H:%M:%S.%f%z')
					filter[field] = parsed.timestamp()
			elif 'created_by_user' == field:
				if 'system' == value:
					value = ''
				filter['created_by_user_ids'] = value
			elif 'redeemed_by_user' == field:
				filter['redeemed_by_user_ids'] = value

	pagination = pagination_from_request('creation_time', 'desc', 0, 32)

	total_results = g.accounts.count_invites(filter=filter)
	results = g.accounts.search_invites(filter=filter, **pagination)

	return render_template(
		'invites_list.html',
		results=results,
		search=search,
		pagination=pagination,
		total_results=total_results,
		total_pages=math.ceil(total_results / pagination['perpage']),
	)

@accounts_manager.route('/invites/<invite_id>/remove')
@require_permissions(group_names='manager')
def remove_invite(invite_id):
	invite = require_invite(invite_id)
	try:
		g.accounts.delete_invite(
			invite,
			user_id=g.accounts.current_user.id_bytes,
		)
	except ValueError as e:
		abort(400, str(e))
	if not invite.created_by_user_id:
		redirect_uri = url_for('accounts_manager.invites_list')
	else:
		redirect_uri = url_for(
			'accounts_manager.edit_user',
			user_id=invite.created_by_user_id,
		)
	return redirect(redirect_uri, code=303)

