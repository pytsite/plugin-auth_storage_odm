"""PytSite Authorization ODM Storage Models
"""
__author__ = 'Oleksandr Shepetko'
__email__ = 'a@shepetko.com'
__license__ = 'MIT'

import hashlib as _hashlib
from pytsite import util as _util, lang as _lang
from plugins import auth as _auth, file_storage_odm as _file_storage_odm, file as _file, odm as _odm
from . import _field


class ODMRole(_odm.model.Entity):
    def _setup_fields(self):
        """Hook
        """
        self.define_field(_odm.field.String('uid'))
        self.define_field(_odm.field.String('name'))
        self.define_field(_odm.field.String('description'))
        self.define_field(_odm.field.UniqueStringList('permissions'))

    def _setup_indexes(self):
        """Hook
        """
        self.define_index([('uid', _odm.I_ASC)], unique=True)
        self.define_index([('name', _odm.I_ASC)], unique=True)
        self.define_index([
            ('name', _odm.I_TEXT),
            ('description', _odm.I_TEXT),
        ], name='text_index')

    def _pre_save(self, **kwargs):
        super()._pre_save(**kwargs)

        if self.is_new:
            self.f_set('uid', self.ref)


class Role(_auth.model.AbstractRole):
    def __init__(self, odm_entity: ODMRole):
        if not isinstance(odm_entity, ODMRole):
            raise TypeError('Instance of ODMRole expected, got {}.'.format(type(odm_entity)))

        self._entity = odm_entity

    @property
    def odm_entity(self) -> ODMRole:
        return self._entity

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

    def sub_from_field(self, field_name: str, value):
        self._entity.f_sub(field_name, value)

        return self

    @property
    def is_new(self) -> bool:
        return self._entity.is_new

    @property
    def is_modified(self) -> bool:
        return self._entity.is_modified

    @property
    def created(self) -> str:
        return self.get_field('_created')

    def do_save(self):
        self._entity.save()

    def do_delete(self):
        self._entity.delete()


class ODMUser(_odm.model.Entity):
    """ODM model to store information about user
    """

    @classmethod
    def odm_auth_permissions_group(cls) -> str:
        """Hook
        """
        return 'security'

    def _setup_fields(self):
        """Hook
        """
        # Fields
        self.define_field(_odm.field.String('uid', required=True))
        self.define_field(_odm.field.String('login', required=True, max_length=_auth.LOGIN_MAX_LENGTH))
        self.define_field(_odm.field.String('nickname', required=True, max_length=_auth.NICKNAME_MAX_LENGTH))
        self.define_field(_odm.field.String('password', required=True))
        self.define_field(_odm.field.String('confirmation_hash'))
        self.define_field(_odm.field.Bool('is_public'))
        self.define_field(_odm.field.Virtual('is_confirmed'))
        self.define_field(_odm.field.String('first_name', max_length=_auth.FIRST_NAME_MAX_LENGTH))
        self.define_field(_odm.field.String('middle_name', max_length=_auth.MIDDLE_NAME_MAX_LENGTH))
        self.define_field(_odm.field.String('last_name', max_length=_auth.LAST_NAME_MAX_LENGTH))
        self.define_field(_odm.field.String('position', max_length=_auth.USER_POSITION_MAX_LENGTH))
        self.define_field(_odm.field.String('description', max_length=_auth.USER_DESCRIPTION_MAX_LENGTH))
        self.define_field(_odm.field.DateTime('birth_date'))
        self.define_field(_odm.field.String('timezone'))
        self.define_field(_odm.field.DateTime('last_sign_in'))
        self.define_field(_odm.field.DateTime('last_activity'))
        self.define_field(_odm.field.Integer('sign_in_count'))
        self.define_field(_odm.field.String('status', default='active'))
        self.define_field(_field.Roles('roles'))
        self.define_field(_odm.field.Enum('gender', values=('m', 'f')))
        self.define_field(_odm.field.String('phone', max_length=_auth.PHONE_MAX_LENGTH))
        self.define_field(_odm.field.Dict('options'))
        self.define_field(_file_storage_odm.field.Image('picture'))
        self.define_field(_file_storage_odm.field.Image('cover_picture'))
        self.define_field(_odm.field.StringList('urls', unique=True))
        self.define_field(_odm.field.Integer('follows_count'))
        self.define_field(_odm.field.Integer('followers_count'))
        self.define_field(_odm.field.Integer('blocked_users_count'))
        self.define_field(_odm.field.String('last_ip'))
        self.define_field(_odm.field.String('country', max_length=_auth.COUNTRY_MAX_LENGTH))
        self.define_field(_odm.field.String('region', max_length=_auth.REGION_MAX_LENGTH))
        self.define_field(_odm.field.String('city', max_length=_auth.CITY_MAX_LENGTH))
        self.define_field(_odm.field.String('street', max_length=_auth.STREET_MAX_LENGTH))
        self.define_field(_odm.field.String('house_number', max_length=_auth.HOUSE_NUMBER_MAX_LENGTH))
        self.define_field(_odm.field.String('apt_number', max_length=_auth.APT_NUMBER_MAX_LENGTH))
        self.define_field(_odm.field.String('postal_code', max_length=10))

    def _setup_indexes(self):
        """Hook.
        """
        self.define_index([('uid', _odm.I_ASC)], unique=True)
        self.define_index([('login', _odm.I_ASC)], unique=True)
        self.define_index([('nickname', _odm.I_ASC)], unique=True)
        self.define_index([('last_sign_in', _odm.I_DESC)])

        text_index_fields = ['login', 'nickname', 'first_name', 'last_name', 'position', 'city', 'country', 'region',
                             'street', 'phone']
        text_index = []
        for f_name in text_index_fields:
            if self.has_field(f_name) and isinstance(self.get_field(f_name), _odm.field.String):
                text_index.append((f_name, _odm.I_TEXT))
        self.define_index(text_index, name='text_index')

    def _on_f_get(self, field_name: str, value, **kwargs):
        if field_name == 'picture':
            if not self.get_field('picture').get_val() and \
                    not (self.is_new or self.is_deleted or self.is_being_deleted):
                try:
                    # Load user picture from Gravatar
                    img_url = 'https://www.gravatar.com/avatar/' + _util.md5_hex_digest(self.f_get('login')) + '?s=512'
                    img = _file.create(img_url)
                    _auth.switch_user_to_system()
                    self.f_set('picture', img).save()
                    value = img
                finally:
                    _auth.restore_user()

        elif field_name == 'is_confirmed':
            value = not self.f_get('confirmation_hash')

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

        elif field_name == 'is_confirmed':
            self.f_set('confirmation_hash', _util.random_str(64) if not value else None)

        return super()._on_f_set(field_name, value, **kwargs)

    def _sanitize_nickname(self, s: str) -> str:
        """Generate unique nickname.
        """
        cnt = 0
        s = _util.transform_str_2(s[:32], _lang.get_current())
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

        if self.is_new:
            self.f_set('uid', self.ref)

        # Generate password
        if not self.f_get('password'):
            self.f_set('password', '')

        if not self.f_get('nickname'):
            m = _hashlib.md5()
            m.update(self.f_get('login').encode('UTF-8'))
            self.f_set('nickname', m.hexdigest())

    def _after_delete(self, **kwargs):
        """Hook
        """
        for f_name in ('picture', 'cover_picture'):
            pic = self.f_get(f_name)
            if pic:
                pic.delete()


class User(_auth.model.AbstractUser):
    def __init__(self, odm_entity: ODMUser):
        if not isinstance(odm_entity, ODMUser):
            raise TypeError('Instance of {} expected, got {}'.format(ODMUser, type(odm_entity)))

        self._entity = odm_entity

    @property
    def odm_entity(self) -> ODMUser:
        return self._entity

    @property
    def is_new(self) -> bool:
        return self._entity.is_new

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

        return self._entity.f_get(field_name, **kwargs)

    def set_field(self, field_name: str, value):
        super().set_field(field_name, value)

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

    def sub_from_field(self, field_name: str, value):
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

    def do_save(self):
        self._entity.save()

    def do_delete(self):
        self._entity.delete()


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
