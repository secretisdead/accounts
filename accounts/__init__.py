import time
import os
import re
import hashlib
import uuid

from passlib.apps import custom_app_context as pass_context
from ipaddress import ip_address
from PIL import Image

from users import Users
from base64_url import base64_url_encode, base64_url_decode
from parse_id import get_id_bytes

class Accounts(Users):
	def __init__(
			self,
			config,
			access_log,
			engine,
			install=False,
			connection=None,
		):
		super().__init__(
			engine,
			config['db_prefix'],
			install=install,
			connection=connection,
		)

		self.require_unique_names = True
		self.require_unique_displays = True

		self.config = config
		self.access_log = access_log

		self.populate_scopes()
		self.populate_groups()
		if 'admin' not in self.available_groups:
			self.create_group('admin')
		if 'manager' not in self.available_groups:
			self.create_group('manager')
		self.populate_groups()

		self.current_user = None

		self.enabled_services = []
		for service, enabled in self.config['authentication_services'].items():
			if not enabled:
				continue
			self.enabled_services.append(service)

		self.config['maximum_name_length'] = min(
			self.name_length,
			self.config['maximum_name_length'],
		)
		self.config['maximum_display_length'] = min(
			self.display_length,
			self.config['maximum_display_length'],
		)

		self.callbacks = {}

	def add_callback(self, name, f):
		if name not in self.callbacks:
			self.callbacks[name] = []
		self.callbacks[name].append(f)

	# cooldowns
	def register_cooldown(self, remote_origin=None):
		return self.access_log.cooldown(
			'register',
			self.config['registration_cooldown_amount'],
			self.config['registration_cooldown_period'],
			remote_origin=remote_origin,
		)

	def authentication_collision_cooldown(self, remote_origin=None, user_id=None):
		return self.access_log.cooldown(
			'authentication_collision',
			self.config['authentication_collision_cooldown_amount'],
			self.config['authentication_collision_cooldown_period'],
			remote_origin=remote_origin,
			subject_id=user_id,
		)

	def create_invite_cooldown(self, user_id, remote_origin=None):
		return self.access_log.cooldown(
			'create_invite',
			self.config['invite_creation_cooldown_amount'],
			self.config['invite_creation_cooldown_period'],
			remote_origin=remote_origin,
			subject_id=user_id,
		)

	def sign_in_attempt_cooldown(self, remote_origin=None):
		return self.access_log.cooldown(
			'sign_in_attempt',
			self.config['sign_in_attempt_cooldown_amount'],
			self.config['sign_in_attempt_cooldown_period'],
			remote_origin=remote_origin,
		)

	# require object or raise
	def require_user(self, id=None, identifier=None):
		if identifier:
			user = self.get_user_by_identifier(identifier)
		elif id:
			user = self.get_user(id)
		else:
			user = None
		if not user:
			raise ValueError('User not found')
		return user

	def require_session(self, id):
		session = self.get_session(id)
		if not session:
			raise ValueError('Session not found')
		return session

	def require_invite(self, id):
		invite = self.get_invite(id)
		if not invite:
			raise ValueError('Invite not found')
		return invite

	# extend users methods
	def get_user(self, user_id):
		user = super().get_user(user_id)
		if user:
			self.populate_user_properties(user)
		return user

	def search_users(self, **kwargs):
		users = super().search_users(**kwargs)
		for user in users.values():
			self.populate_user_properties(user)
		return users

	def create_invite(self, user_id=None):
		subject_id = ''
		if user_id:
			subject_id = user_id
			invite = super().create_invite(
				created_by_user_id=user_id,
			)
		else:
			invite = super().create_invite()
		self.access_log.create_log(
			scope='create_invite',
			subject_id=subject_id,
			object_id=invite.id_bytes,
		)
		return invite

	def redeem_invite(self, invite_id, user_id):
		super().redeem_invite(invite_id, user_id)
		self.access_log.create_log(
			scope='redeem_invite',
			subject_id=user_id,
			object_id=invite_id,
		)

	def delete_invite(self, invite, user_id=None):
		if invite.redeem_time or invite.redeemed_by_user_id:
			raise ValueError(
				'Cannot remove an invite which has already been redeemed'
			)
		super().delete_invite(invite.id_bytes)
		subject_id = ''
		if user_id:
			subject_id = user_id
		self.access_log.create_log(
			scope='delete_invite',
			subject_id=subject_id,
			object_id=invite.id,
		)
		return invite

	def close_session(self, session_id, user_id=''):
		try:
			super().close_session(session_id)
		# ignore non-existant and already closed session exceptions
		except Exception as e:
			print(e)
			pass
		else:
			self.access_log.create_log(
				scope='close_session',
				subject_id=user_id,
				object_id=session_id,
			)

	def close_all_sessions(self, user_id):
		super().close_user_sessions(user_id)
		subject_id = ''
		if self.current_user:
			subject_id = self.current_user.id_bytes
		self.access_log.create_log(
			scope='close_all_sessions',
			subject_id=subject_id,
			object_id=user_id,
		)

	def prune_sessions(self):
		closed_before = (
			time.time() - self.config['session']['review_lifetime']
		)
		super().prune_sessions(closed_before=closed_before)

	def create_auto_permission(self, **kwargs):
		auto_permission = super().create_auto_permission(**kwargs)
		subject_id = ''
		if auto_permission.created_by_user_id:
			subject_id = auto_permission.created_by_user_id
		self.access_log.create_log(
			scope='create_auto_permission',
			subject_id=subject_id,
			object_id=auto_permission.id,
		)
		return auto_permission

	def delete_auto_permission(self, auto_permission, user_id):
		super().delete_auto_permission(auto_permission.id_bytes)
		self.access_log.create_log(
			scope='delete_auto_permission',
			subject_id=user_id,
			object_id=auto_permission.id_bytes,
		)

	def sync_auto_permissions(self, subject_id='', **kwargs):
		super().sync_auto_permissions(**kwargs)
		#TODO auto permissions sync with multiple user ids doesn't log well
		#TODO nothing to do about this except log only the first one
		#TODO or loop and log all of them
		object_id = ''
		if 'user_ids' in kwargs:
			if list == type(kwargs['user_ids']):
				object_id = kwargs['user_ids'][0]
			else:
				object_id = kwargs['user_ids']
		self.access_log.create_log(
			scope='sync_auto_permissions',
			subject_id=subject_id,
			object_id=object_id,
		)

	# checks that raise on failure
	def validate_service(self, service):
		if service not in self.config['authentication_services']:
			raise KeyError('Authentication service not implemented')
		if not self.config['authentication_services'][service]:
			raise ValueError('Authentication service not enabled')

	def require_sign_in(self):
		if not self.current_user:
			raise ValueError('Sign in required')

	def require_permissions(self, **kwargs):
		if (
				not self.current_user
				or not self.current_user.has_permission(**kwargs)
			):
			raise ValueError('Permissions required')

	# checks that return True or False
	def is_same_user(self, user_id, user):
		if not user:
			return False
		if user.id == user_id:
			return True
		if user.id_bytes == user_id:
			return True
		return False

	def is_current_user(self, user_id):
		return self.is_same_user(user_id, self.current_user)

	# additional accounts methods
	def populate_avatar(self, user):
		user.avatar = ''
		extensions = ['webp', 'png']
		for extension in extensions:
			if not os.path.exists(
					os.path.join(
						self.config['avatars_path'],
						user.id + '.' + extension,
					)
				):
				return
		user.avatar = self.config['avatar_file_uri'].format(user.id)

	def populate_user_properties(self, user):
		self.populate_avatar(user)

	def populate_current_user(self, remote_origin, useragent, session_id=None):
		if not session_id:
			return False

		#TODO this won't scale well and will become wasteful if there are users
		# touching the site extremely frequently, which shouldn't matter for
		# most instances, but probably move this prune_sessions to a cronjob
		# that runs less frequently if it becomes a problem
		self.prune_sessions()

		session = self.get_session(session_id)
		if not session:
			return False

		if 0 != session.close_time:
			self.access_log.create_log(
				scope='closed_session',
				subject_id=session.user.id_bytes,
				object_id=session.id_bytes,
			)
			return False

		expiration_time = (
			session.creation_time + self.config['session']['lifetime']
		)
		if expiration_time < time.time():
			self.close_session(session.id)
			self.access_log.create_log(
				scope='expired_session',
				subject_id=session.user.id_bytes,
				object_id=session.id_bytes,
			)
			return False

		if (
				not self.config['ignore_session_remote_origin_mismatch']
				and ip_address(remote_origin) != session.remote_origin
			):
			self.access_log.create_log(
				scope='session_remote_origin_mismatch',
				subject_id=session.user.id_bytes,
				object_id=session.id_bytes,
			)
			self.close_session(session.id)
			return False
			
		if (
				not self.config['ignore_session_useragent_mismatch']
				and str(useragent) != str(session.useragent)
			):
			self.access_log.create_log(
				scope='session_useragent_mismatch',
				subject_id=session.user.id_bytes,
				object_id=session.id_bytes,
			)
			self.close_session(session.id)
			return False

		if not session.user:
			self.close_session(session.id)
			return False

		self.current_user = session.user
		self.current_user.session = session
		self.touch_session(session.id)
		self.populate_user_permissions(self.current_user)

		if self.current_user:
			self.populate_user_properties(self.current_user)

		return True

	def get_user_by_identifier(self, identifier):
		try:
			user_id = get_id_bytes(identifier)
		except:
			pass
		else:
			user = self.get_user(user_id)
			if user:
				return user
		users = self.search_users(filter={'names': identifier})
		if 0 == len(users):
			return None
		return users.values()[0]

	def activate_user(self, user_id):
		self.update_user(user_id, status='ACTIVATED')
		subject_id = ''
		if self.current_user and not self.is_current_user(user_id):
			subject_id = self.current_user.id_bytes
		self.access_log.create_log(
			scope='activate_user',
			subject_id=subject_id,
			object_id=user_id,
		)

	def deactivate_user(self, user_id):
		subject_id = ''
		object_id = ''
		if self.current_user:
			subject_id = self.current_user.id_bytes
		deactivating_self = False
		if self.is_current_user(user_id):
			self.delete_user_authentications(user_id)
			self.update_user(user_id, status='DEACTIVATED_BY_SELF')
			user = self.current_user
			deactivating_self = True
		else:
			authentications = self.get_user_authentications(user_id)
			for authentication in authentications.values():
				self.forbid_authentication(authentication.id)
			self.update_user(user_id, status='DEACTIVATED_BY_STAFF')
			user = self.get_user(user_id)
			object_id = user.id_bytes
		self.remove_avatar(user)
		self.unprotect_user(user.id_bytes)
		self.delete_user_created_invites(user.id_bytes, preserve_redeemed=True)
		self.delete_user_redeemed_invites(user.id_bytes)
		self.delete_user_permissions(user.id_bytes)
		self.delete_user_auto_permissions(user.id_bytes)
		self.close_user_sessions(user.id_bytes)
		new_user_id = self.anonymize_user(user.id_bytes)
		if deactivating_self:
			subject_id = new_user_id
			scope = 'deactivate_user_self'
		else:
			object_id = new_user_id
			scope = 'deactivate_user'
		self.access_log.create_log(
			scope=scope,
			subject_id=subject_id,
			object_id=object_id,
		)
		return self.get_user(new_user_id)

	def register(self, service, value, remote_origin, useragent):
		if self.current_user:
			authentication = self.create_current_user_authentication(service, value)
		else:
			self.current_user = self.create_user()
			authentication = self.create_current_user_authentication(service, value)
			activate = False
			if self.config['automatic_activation']:
				activate = True
			# super only user
			if 1 == self.count_users():
				activate = True
				self.create_permission(
					user_id=self.current_user.id_bytes,
					group_bits=-1,
				)
				self.protect_user(self.current_user.id_bytes)
				self.access_log.create_log(
					scope='super_user',
					object_id=self.current_user.id_bytes,
				)
			if activate:
				self.activate_user(self.current_user.id_bytes)
				self.create_current_user_session(remote_origin, useragent)
			self.access_log.create_log(
				scope='register',
				subject_id=self.current_user.id_bytes,
			)
			if 'register' in self.callbacks:
				for f in self.callbacks['register']:
					f(self.current_user)
		self.access_log.create_log(
			scope='create_authentication',
			subject_id=self.current_user.id_bytes,
			object_id=authentication.id_bytes,
		)
		if 'create_authentication' in self.callbacks:
			for f in self.callbacks['create_authentication']:
				f(authentication)

	def register_local(
			self,
			account_name,
			passphrase,
			passphrase_confirmation,
			remote_origin,
			useragent,
		):
		errors = []
		if not account_name:
			errors.append('Missing account name')
		else:
			account_name_bytes = account_name.encode()
			account_name_hash = base64_url_encode(
				hashlib.sha256(account_name_bytes).digest()
			)
			authentications = self.search_authentications(
				filter={'values': account_name_hash + ';%'}
			)
			if 0 < len(authentications.items()):
				self.access_log.create_log(
					scope='authentication_collision',
				)
				errors.append('Account name unavailable')

		if not passphrase:
			errors.append('Missing passphrase')
		else:
			if self.config['minimum_pass_length'] > len(passphrase):
				errors.append(
					'Passphrase must be at least {} characters'.format(
						str(self.config['minimum_pass_length'])
					)
				)
			elif not passphrase_confirmation:
				errors.append('Missing passphrase confirmation')
			elif passphrase != passphrase_confirmation:
				errors.append('Passphrase and confirmation did not match')

		if errors:
			return errors

		value = account_name_hash + ';' + pass_context.hash(passphrase)
		try:
			self.register('local', value, remote_origin, useragent)
		except ValueError as e:
			return [str(e)]
		return []

	def sign_in(self, user, remote_origin, useragent):
		self.current_user = user
		self.create_current_user_session(remote_origin, useragent)
		self.access_log.create_log(
			scope='sign_in',
			subject_id=self.current_user.id_bytes,
		)

	def sign_in_local(self, account_name, passphrase, remote_origin, useragent):
		errors = []
		if not account_name:
			errors.append('Missing account name')
		if not passphrase:
			errors.append('Missing passphrase')

		if errors:
			return errors

		account_name_bytes = account_name.encode()
		account_name_hash = base64_url_encode(
			hashlib.sha256(account_name_bytes).digest()
		)
		authentications = self.search_authentications(
			filter={'values': account_name_hash + ';%'}
		)

		if not authentications.values():
			self.access_log.create_log(scope='sign_in_attempt')
			self.access_log.create_log(
				scope='sign_in_failure_account_name_not_found',
			)
			return ['Incorrect account name or passphrase']

		authentication = authentications.values()[0]
		pass_hash = authentication.value.split(';')[1]

		if not pass_context.verify(
				passphrase,
				pass_hash,
			):
			self.access_log.create_log(scope='sign_in_attempt')
			self.access_log.create_log(scope='sign_in_failure_incorrect_pass')
			return ['Incorrect account name or passphrase']

		self.sign_in(authentication.user, remote_origin, useragent)
		return []

	def sign_out(self):
		if not self.current_user:
			return
		if hasattr(self.current_user, 'session'):
			self.access_log.create_log(
				scope='sign_out',
				subject_id=self.current_user.id_bytes,
			)
			self.close_session(
				self.current_user.session.id_bytes,
				user_id=self.current_user.id_bytes,
			)

	def create_current_user_session(self, remote_origin, useragent):
		self.current_user.session = self.create_session(
			user_id=self.current_user.id_bytes,
			remote_origin=remote_origin,
			useragent=useragent,
		)

	def create_current_user_authentication(self, service, value):
		try:
			authentication = self.create_authentication(
				user_id=self.current_user.id_bytes,
				service=service,
				value=value,
			)
		except ValueError:
			self.access_log.create_log(
				scope='problem_during_create_authentication',
				subject_id=self.current_user.id_bytes,
			)
			raise
		else:
			return authentication

	def set_user_permissions(self, user, permissions):
		subject_id = ''
		if self.current_user:
			subject_id = self.current_user.id_bytes
		if not permissions.items():
			self.delete_permissions(user_ids=user.id_bytes)
			return
		for scope, group_names in permissions.items():
			self.create_permission(
				user_id=user.id_bytes,
				scope=scope,
				group_bits=self.combine_groups(names=group_names),
				preserve_protected=False,
			)
		self.access_log.create_log(
			scope='edit_user_permissions',
			subject_id=subject_id,
			object_id=user.id_bytes,
		)

	def add_avatar(self, user, image):
		avatar_path = os.path.join(self.config['avatars_path'], user.id)

		edge = self.config['avatar_edge']
		image_copy = image.copy()
		image_copy.thumbnail((edge, edge), Image.BICUBIC)

		# static
		thumbnail_path = avatar_path + '.webp'
		image_copy.save(thumbnail_path, 'WebP', lossless=True)

		# fallback
		thumbnail_path = avatar_path + '.png'
		image_copy.save(thumbnail_path, 'PNG', optimize=True)

		image_copy.close()

	def remove_avatar(self, user):
		avatar_path = os.path.join(self.config['avatars_path'], user.id)
		extensions = ['webp', 'png']
		for extension in extensions:
			if os.path.exists(avatar_path + '.' + extension):
				os.remove(avatar_path + '.' + extension)

	def edit_user_settings(self, user, **kwargs):
		errors = []
		updates = {}
		if 'name' in kwargs and kwargs['name'] != user.name:
			updates['name'] = kwargs['name']
			if updates['name'] and user.name != updates['name']:
				if self.config['maximum_name_length'] < len(updates['name']):
					errors.append(
						'Name must be {} or fewer characters'.format(
							str(self.config['maximum_name_length']),
						)
					)
				if not re.match(r'^[a-zA-Z0-9_\-]*$', updates['name']):
					errors.append('Name must contain only a-z, A-Z, 0-9, _, and -')
				if (
						updates['name'] in self.config['reserved_names']
						or 0 < self.count_users(filter={'names': updates['name']})
					):
					errors.append('Name unavailable')
		if 'display' in kwargs and kwargs['display'] != user.display:
			updates['display'] = kwargs['display']
			if updates['display'] and user.display != updates['display']:
				if self.config['maximum_display_length'] < len(updates['display']):
					errors.append(
						'Display must be {} or fewer characters'.format(
							str(self.config['maximum_display_length']),
						)
					)
				if 0 < self.count_users(
						filter={'displays': updates['display']},
					):
					errors.append('Display unavailable')

		if not errors:
			self.update_user(user.id_bytes, **updates)
			scope = ''
			subject_id = ''
			object_id = ''
			if self.is_current_user(user.id_bytes):
				scope = 'edit_user_settings_self'
				subject_id = user.id_bytes
			else:
				scope = 'edit_user_settings'
				object_id = user.id_bytes
			self.access_log.create_log(
				scope=scope,
				subject_id=subject_id,
				object_id=object_id,
			)

		if 'remove_avatar' in kwargs:
			self.remove_avatar(user)
		elif 'avatar' in kwargs:
			try:
				file_contents = kwargs['avatar'].stream.read()
			except ValueError as e:
				errors.append('Problem uploading avatar')

			file_path = os.path.join(
				self.config['temp_path'],
				'temp_avatar_' + str(uuid.uuid4()),
			)
			f = open(file_path, 'w+b')
			f.write(file_contents)
			f.close()

			try:
				image = Image.open(file_path)
			# catch general exceptions here in case of problem reading image file
			except:
				#TODO file in use?
				#os.remove(file_path)
				errors.append('Problem opening avatar image')
			else:
				self.remove_avatar(user)
				self.add_avatar(user, image)
				image.close()
				#TODO file in use?
				#os.remove(file_path)
				self.access_log.create_log(
					scope='upload_avatar',
					subject_id=user.id_bytes,
				)

		return errors

	def get_redeemed_invite(self, user_id):
		redeemed_invites = self.search_invites(
			filter={'redeemed_by_user_ids': user_id},
		)
		if redeemed_invites.values():
			return redeemed_invites.values()[0]
		return None

	def remove_current_user_authentication_by_service(self, service):
		object_id = None
		self.populate_user_authentications(self.current_user)
		if service not in self.current_user.authentications:
			return
		authentication = self.current_user.authentications[service]
		self.delete_authentication(authentication.id_bytes)
		self.access_log.create_log(
			scope='remove_authentication',
			subject_id=self.current_user.id_bytes,
			object_id=authentication.id_bytes,
		)

	def redeem_auto_permission(self, auto_permission, user_id):
		current_time = time.time()
		self.update_auto_permission(
			auto_permission.id_bytes,
			valid_from_time=current_time - 1,
			valid_until_time=(current_time + auto_permission.duration),
			user_id=user_id,
		)
		super().sync_auto_permissions(ids=auto_permission.id_bytes)
		self.access_log.create_log(
			scope='redeem_auto_permission',
			subject_id=user_id,
			object_id=auto_permission.id_bytes,
		)
