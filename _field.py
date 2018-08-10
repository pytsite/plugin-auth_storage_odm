"""PytSite Auth Storage ODM Fields.
"""
__author__ = 'Oleksandr Shepetko'
__email__ = 'a@shepetko.com'
__license__ = 'MIT'

from bson import DBRef as _DBRef
from typing import List as _List, Optional as _Optional, Union as _Union, Iterable as _Iterable
from plugins import auth as _auth, odm as _odm


def _resolve_user(f_name: str, allow_system: bool, allow_anonymous: bool, disallowed_users: _List[_auth.AbstractUser],
                  value: _Union[_auth.AbstractUser, str, _DBRef]) -> _auth.AbstractUser:
    """Helper
    """
    if isinstance(value, _auth.AbstractUser):
        user = value
    elif isinstance(value, str):
        user = _auth.get_user(uid=value)
    elif isinstance(value, _DBRef):
        user = _auth.get_user(uid=value.id)
    else:
        raise TypeError("Field '{}': user object, str or DB ref expected, got {}".
                        format(f_name, type(value)))

    if user.is_anonymous and not allow_anonymous:
        raise ValueError('Anonymous user is not allowed here')

    if user.is_system and not allow_system:
        raise ValueError('System user is not allowed here')

    for u in disallowed_users:  # type: _auth.model.AbstractUser
        if u.uid == user.uid:
            raise ValueError("User '{}' is not allowed here".format(user.login))

    return user


class Roles(_odm.field.UniqueList):
    def __init__(self, name: str, **kwargs):
        super().__init__(name, allowed_types=(_auth.model.AbstractRole,), **kwargs)

    def _resolve_role(self, value) -> _auth.AbstractRole:
        """Helper
        """
        if isinstance(value, _auth.model.AbstractRole):
            return value
        elif isinstance(value, str):
            return _auth.get_role(uid=value)
        elif isinstance(value, _DBRef):
            return _auth.get_role(uid=str(value.id))
        else:
            raise TypeError("Field '{}': role object, str or DB ref expected, got {}".format(self.name, type(value)))

    def _on_get_storable(self, value: _List[_auth.AbstractRole], **kwargs) -> _Iterable[str]:
        """Hook
        """
        return [v.uid for v in value]

    def _on_set(self, raw_value: _Union[list, tuple], **kwargs) -> _Iterable[_auth.AbstractRole]:
        """Hook
        """
        if raw_value is None:
            return []

        if not isinstance(raw_value, (list, tuple)):
            raise TypeError("Field '{}': list or tuple expected, got {}".format(self.name, type(raw_value)))

        return [self._resolve_role(r) for r in raw_value]

    def _on_add(self, current_value: _List[_auth.AbstractRole], raw_value_to_add, **kwargs):
        return super()._on_add(current_value, self._resolve_role(raw_value_to_add))

    def _on_sub(self, current_value: _List[_auth.AbstractRole], raw_value_to_sub, **kwargs):
        return super()._on_sub(current_value, self._resolve_role(raw_value_to_sub))

    def sanitize_finder_arg(self, arg):
        """Hook. Used for sanitizing Finder's query argument.
        """
        if isinstance(arg, _auth.model.AbstractRole):
            return arg.uid
        elif isinstance(arg, (list, tuple)):
            clean_arg = []
            for role in arg:
                if isinstance(role, _auth.model.AbstractRole):
                    clean_arg.append(role.uid)
                else:
                    clean_arg.append(role)
            return clean_arg
        else:
            return arg


class User(_odm.field.Abstract):
    """Field to store reference to user
    """

    def __init__(self, name: str, **kwargs):
        """Init
        """
        self._allow_anonymous = kwargs.get('allow_anonymous', False)
        self._allow_system = kwargs.get('allow_system', False)
        self._disallowed_users = kwargs.get('disallowed_users', ())

        super().__init__(name, **kwargs)

    def _on_set(self, raw_value, **kwargs) -> _Optional[_auth.AbstractUser]:
        """Hook
        """
        if raw_value is None:
            return None

        return _resolve_user(self._name, self._allow_system, self._allow_anonymous, self._disallowed_users, raw_value)

    def _on_get_storable(self, value: _Optional[_auth.AbstractUser], **kwargs) -> _Optional[str]:
        """Hook
        """
        return value.uid if value else None

    def sanitize_finder_arg(self, arg):
        """Hook. Used for sanitizing Finder's query argument.
        """
        if isinstance(arg, _auth.model.AbstractUser):
            if arg.is_anonymous:
                return 'ANONYMOUS'
            elif arg.is_system:
                return 'SYSTEM'
            else:
                return arg.uid
        elif isinstance(arg, (list, tuple)):
            clean_arg = []
            for user in arg:
                if isinstance(user, _auth.model.AbstractUser):
                    clean_arg.append(user.uid)
                else:
                    clean_arg.append(user)
            return clean_arg
        else:
            return arg


class Users(_odm.field.UniqueList):
    """Field to store list of users
    """

    def __init__(self, name: str, **kwargs):
        """Init.
        """
        kwargs.setdefault('default', [])
        self._allow_anonymous = kwargs.get('allow_anonymous', False)
        self._allow_system = kwargs.get('allow_system', False)
        self._disallowed_users = kwargs.get('disallowed_users', ())

        super().__init__(name, allowed_types=(_auth.model.AbstractUser,), **kwargs)

    def _on_set(self, raw_value: _Union[list, tuple], **kwargs) -> _Iterable[_auth.AbstractUser]:
        """Hook
        """
        if raw_value is None:
            return []

        if not isinstance(raw_value, (list, tuple)):
            raise TypeError("Field '{}': list or tuple expected, got {}".format(self.name, type(raw_value)))

        return [_resolve_user(self._name, self._allow_system, self._allow_anonymous, self._disallowed_users, v)
                for v in raw_value]

    def _on_get_storable(self, value: _List[_auth.AbstractUser], **kwargs) -> _Iterable[str]:
        """Hook
        """
        return [v.uid for v in value]

    def _on_add(self, current_value: _List[_auth.AbstractUser], raw_value_to_add, **kwargs):
        u = _resolve_user(self._name, self._allow_system, self._allow_anonymous, self._disallowed_users,
                          raw_value_to_add)

        return super()._on_add(current_value, u)

    def _on_sub(self, current_value: _List[_auth.AbstractUser], raw_value_to_sub, **kwargs):
        u = _resolve_user(self._name, self._allow_system, self._allow_anonymous, self._disallowed_users,
                          raw_value_to_sub)

        return super()._on_sub(current_value, u)
