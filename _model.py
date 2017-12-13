"""PytSite Authorization ODM Storage Models
"""
import hashlib as _hashlib
from pytsite import util as _util, events as _events, errors as _errors
from plugins import auth as _auth, file_storage_odm as _file_storage_odm, file as _file, odm as _odm
from . import _field

__author__ = 'Alexander Shepetko'
__email__ = 'a@shepetko.com'
__license__ = 'MIT'


class ODMRole(_odm.model.Entity):
    @classmethod
    def odm_auth_permissions_group(cls) -> str:
        return 'security'

    def _setup_fields(self):
        """Hook.
        """
        self.define_field(_odm.field.String('name'))
        self.define_field(_odm.field.String('description'))
        self.define_field(_odm.field.UniqueStringList('permissions'))

    def _setup_indexes(self):
        """Hook.
        """
        self.define_index([('name', _odm.I_ASC)], unique=True)

    def _after_save(self, first_save: bool = False, **kwargs):
        super()._after_save(first_save, **kwargs)

        role = _auth.get_role(uid=str(self.id))

        if first_save:
            _events.fire('auth@role.create', role=role)

        _events.fire('auth@role.save', role=role)

    def _pre_delete(self, **kwargs):
        """Hook.
        """
        # Check if the role is used by users
        for user in _auth.get_users():
            if user.has_role(self.f_get('name')):
                raise _errors.ForbidDeletion(self.t('role_used_by_user', {'user': user.login}))

        _events.fire('auth@role.delete', role=_auth.get_role(uid=str(self.id)))


class Role(_auth.model.AbstractRole):
    def __init__(self, odm_entity: ODMRole):
        if not isinstance(odm_entity, ODMRole):
            raise TypeError('Instance of ODMRole expected, got {}.'.format(type(odm_entity)))

        self._entity = odm_entity

    @property
    def odm_entity(self) -> ODMRole:
        return self._entity

    @property
    def uid(self) -> str:
        return str(self._entity.id)

    def has_field(self, field_name: str) -> bool:
        return self._entity.has_field(field_name)

    def get_field(self, field_name: str, **kwargs):
        return self._entity.f_get(field_name)

    def set_field(self, field_name: str, value):
        self._entity.f_set(field_name, value)

        return self

    def add_to_field(self, field_name: str, value):
        self._entity.f_add(field_name, value)

        return self

    def remove_from_field(self, field_name: str, value):
        self._entity.f_sub(field_name, value)

        return self

    @property
    def is_modified(self) -> bool:
        return self._entity.is_modified

    def save(self):
        self._entity.save()

        return self

    def delete(self):
        try:
            self._entity.delete()
        except _odm.error.EntityDeleted:
            # Entity was deleted by another instance
            pass

        return self


class ODMUser(_odm.model.Entity):
    """ODM model to store information about user.
    """

    @classmethod
    def odm_auth_permissions_group(cls) -> str:
        """Hook.
        """
        return 'security'

    def _setup_fields(self):
        """Hook.
        """
        # Fields
        self.define_field(_odm.field.String('login', required=True))
        self.define_field(_odm.field.Email('email', required=True))
        self.define_field(_odm.field.String('password', required=True))
        self.define_field(_odm.field.String('nickname', required=True))
        self.define_field(_odm.field.Bool('profile_is_public', default=False))
        self.define_field(_odm.field.String('first_name'))
        self.define_field(_odm.field.String('last_name'))
        self.define_field(_odm.field.String('description'))
        self.define_field(_odm.field.DateTime('birth_date'))
        self.define_field(_odm.field.DateTime('last_sign_in'))
        self.define_field(_odm.field.DateTime('last_activity'))
        self.define_field(_odm.field.Integer('sign_in_count'))
        self.define_field(_odm.field.String('status', default='active'))
        self.define_field(_field.Roles('roles'))
        self.define_field(_odm.field.String('gender'))
        self.define_field(_odm.field.String('phone'))
        self.define_field(_odm.field.Dict('options'))
        self.define_field(_file_storage_odm.field.Image('picture'))
        self.define_field(_odm.field.StringList('urls', unique=True))
        self.define_field(_odm.field.Integer('follows_count'))
        self.define_field(_odm.field.Integer('followers_count'))
        self.define_field(_odm.field.Integer('blocked_users_count'))
        self.define_field(_odm.field.String('last_ip'))
        self.define_field(_odm.field.String('country'))
        self.define_field(_odm.field.String('city'))

    def _setup_indexes(self):
        """Hook.
        """
        self.define_index([('login', _odm.I_ASC)], unique=True)
        self.define_index([('nickname', _odm.I_ASC)], unique=True)
        self.define_index([('last_sign_in', _odm.I_DESC)])

    def _on_f_get(self, field_name: str, value, **kwargs):
        if field_name == 'picture' and not self.get_field('picture').get_val():
            if not (self.is_new or self.is_deleted or self.is_being_deleted):
                # Load user picture from Gravatar
                img_url = 'https://www.gravatar.com/avatar/' + _util.md5_hex_digest(self.f_get('email')) + '?s=512'
                img = _file.create(img_url)
                _auth.switch_user_to_system()
                self.f_set('picture', img).save()
                _auth.restore_user()
                value = img

        return value

    def _on_f_set(self, field_name: str, value, **kwargs):
        """Hook.
        """
        if field_name == 'password':
            if value:
                value = _auth.hash_password(value)
            else:
                if self.is_new:
                    # Set random password
                    value = _auth.hash_password(_util.random_password())
                else:
                    # Keep old password
                    value = self.f_get('password')

        elif field_name == 'status':
            if value not in [v[0] for v in _auth.get_user_statuses()]:
                raise RuntimeError("Invalid user status: '{}'.".format(value))

        elif field_name == 'nickname':
            value = self._sanitize_nickname(value)

        return super()._on_f_set(field_name, value, **kwargs)

    def _sanitize_nickname(self, s: str) -> str:
        """Generate unique nickname.
        """
        cnt = 0
        s = _util.transform_str_2(s[:32])
        nickname = s
        while True:
            try:
                user = _auth.get_user(nickname=nickname)

                # If nickname of THIS user was not changed
                if user.nickname == self.f_get('nickname'):
                    return s

            except _auth.error.UserNotFound:
                return nickname

            cnt += 1
            nickname = s + '-' + str(cnt)

    def _pre_save(self, **kwargs):
        """Hook.
        """
        super()._pre_save(**kwargs)

        if not self.f_get('password'):
            self.f_set('password', '')

        if not self.f_get('nickname'):
            m = _hashlib.md5()
            m.update(self.f_get('login').encode('UTF-8'))
            self.f_set('nickname', m.hexdigest())

    def _after_save(self, first_save: bool = False, **kwargs):
        super()._after_save(first_save, **kwargs)

        user = _auth.get_user(uid=str(self.id))

        if first_save:
            _events.fire('auth@user.create', user=user)

        _events.fire('auth@user.save', user=user)

    def _pre_delete(self, **kwargs):

        super()._pre_delete(**kwargs)

        if str(self.id) == _auth.get_current_user().uid:
            raise _errors.ForbidDeletion(self.t('you_cannot_delete_yourself'))

        _events.fire('auth@user.delete', user=_auth.get_user(uid=str(self.id)))

    def _after_delete(self, **kwargs):
        """Hook.
        """
        pic = self.f_get('picture')
        if pic:
            try:
                pic.delete()
            except _odm.error.EntityDeleted:
                # Entity was deleted by another instance
                pass


class User(_auth.model.AbstractUser):
    def __init__(self, odm_entity: ODMUser):
        if not isinstance(odm_entity, ODMUser):
            raise TypeError('Instance of ODMUser expected, got {}.'.format(type(odm_entity)))

        self._entity = odm_entity

    @property
    def odm_entity(self) -> ODMUser:
        return self._entity

    @property
    def uid(self) -> str:
        return str(self._entity.id)

    @property
    def is_modified(self) -> bool:
        return self._entity.is_modified

    @property
    def created(self) -> str:
        return self.get_field('_created')

    def has_field(self, field_name: str) -> bool:
        return self._entity.has_field(field_name)

    def get_field(self, field_name: str, **kwargs):
        if field_name == 'follows':
            f = _odm.find('follower').eq('follower', self)
            return [f.follows for f in f.skip(kwargs.get('skip', 0)).get(kwargs.get('count', 10))]
        if field_name == 'follows_count':
            return _odm.find('follower').eq('follower', self).count()
        elif field_name == 'followers':
            return [f.follower for f in _odm.find('follower').eq('follows', self).get()]
        elif field_name == 'followers_count':
            return _odm.find('follower').eq('follows', self).count()
        elif field_name == 'blocked_users':
            return [b.blocked for b in _odm.find('blocked_user').eq('blocker', self).get()]
        elif field_name == 'blocked_users_count':
            return _odm.find('blocked_user').eq('blocker', self).count()

        return self._entity.f_get(field_name)

    def set_field(self, field_name: str, value):
        self._entity.f_set(field_name, value)

        return self

    def add_to_field(self, field_name: str, value):
        if field_name == 'follows':
            if not self.is_follows(value):
                _odm.dispense('follower').f_set('follower', self).f_set('follows', value).save()
        elif field_name == 'blocked_users':
            if not self.is_blocks(value):
                _odm.dispense('blocked_user').f_set('blocker', self).f_set('blocked', value).save()
        else:
            self._entity.f_add(field_name, value)

        return self

    def remove_from_field(self, field_name: str, value):
        if field_name == 'follows':
            _odm.find('follower').eq('follower', self).eq('follows', value).delete()
        elif field_name == 'blocked_users':
            _odm.find('blocked_user').eq('blocker', self).eq('blocked', value).delete()
        else:
            self._entity.f_sub(field_name, value)

        return self

    def is_follows(self, user_to_check: _auth.model.AbstractUser) -> bool:
        return bool(_odm.find('follower').eq('follower', self).eq('follows', user_to_check).count())

    def is_followed(self, user_to_check: _auth.model.AbstractUser) -> bool:
        return bool(_odm.find('follower').eq('follower', user_to_check).eq('follows', self).count())

    def is_blocks(self, user_to_check: _auth.model.AbstractUser) -> bool:
        return bool(_odm.find('blocked_user').eq('blocker', self).eq('blocked', user_to_check).count())

    def save(self):
        super().save()

        self._entity.save()

        return self

    def delete(self):
        super().delete()

        self._entity.delete()

        return self


class ODMFollower(_odm.model.Entity):
    def _setup_fields(self):
        self.define_field(_field.User('follower', required=True))
        self.define_field(_field.User('follows', required=True))

    def _setup_indexes(self):
        self.define_index([('follower', _odm.I_ASC), ('follows', _odm.I_ASC)], True)

    @property
    def follower(self) -> _auth.model.AbstractUser:
        return self.f_get('follower')

    @property
    def follows(self) -> _auth.model.AbstractUser:
        return self.f_get('follows')


class ODMBlockedUser(_odm.model.Entity):
    def _setup_fields(self):
        self.define_field(_field.User('blocker', required=True))
        self.define_field(_field.User('blocked', required=True))

    def _setup_indexes(self):
        self.define_index([('blocker', _odm.I_ASC), ('blocked', _odm.I_ASC)], True)

    @property
    def blocker(self) -> _auth.model.AbstractUser:
        return self.f_get('blocker')

    @property
    def blocked(self) -> _auth.model.AbstractUser:
        return self.f_get('blocked')
