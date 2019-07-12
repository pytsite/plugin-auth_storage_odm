"""PytSite Auth Storage ODM Fields.
"""
__author__ = 'Oleksandr Shepetko'
__email__ = 'a@shepetko.com'
__license__ = 'MIT'

from bson import DBRef
from typing import Dict, List, Optional, Union, Any
from plugins import auth, odm


def _resolve_user(allow_system: bool, allow_anonymous: bool, disallowed_users: List[auth.AbstractUser],
                  value: Union[auth.AbstractUser, str, DBRef]) -> Optional[auth.AbstractUser]:
    """Helper
    """
    if isinstance(value, auth.AbstractUser):
        user = value
    elif isinstance(value, str):
        user = auth.get_user(uid=value)
    elif isinstance(value, DBRef):
        user = auth.get_user(uid=value.id)
    else:
        raise TypeError("User object, str or DB ref expected, got {}".format(type(value)))

    if user.is_anonymous and not allow_anonymous:
        raise ValueError('Anonymous user is not allowed here')

    if user.is_system and not allow_system:
        raise ValueError('System user is not allowed here')

    for u in disallowed_users:  # type: auth.model.AbstractUser
        if u.uid == user.uid:
            raise ValueError("User '{}' is not allowed here".format(user.login))

    return user


class Roles(odm.field.UniqueList):
    def __init__(self, name: str, **kwargs):
        super().__init__(name, allowed_types=(auth.model.AbstractRole,), **kwargs)

    def _resolve_role(self, value) -> auth.AbstractRole:
        """Helper
        """
        if isinstance(value, auth.model.AbstractRole):
            return value
        elif isinstance(value, str):
            return auth.get_role(uid=value)
        elif isinstance(value, DBRef):
            return auth.get_role(uid=str(value.id))
        else:
            raise TypeError("Field '{}': role object, str or DB ref expected, got {}".format(self.name, type(value)))

    def _on_set(self, raw_value: Any, **kwargs) -> List[str]:
        """Hook
        """
        if raw_value is None:
            return []

        if not isinstance(raw_value, (list, tuple)):
            raise TypeError("Field '{}': list or tuple expected, got {}".format(self.name, type(raw_value)))

        return [self._resolve_role(r).uid for r in raw_value if r]

    def _on_get(self, value: List[str], **kwargs) -> List[auth.AbstractRole]:
        """Hook
        """
        return [auth.get_role(uid=v) for v in value]

    def _on_add(self, current_value: tuple, raw_value_to_add, **kwargs):
        """Hook
        """
        return super()._on_add(current_value, self._resolve_role(raw_value_to_add))

    def _on_sub(self, current_value: tuple, raw_value_to_sub, **kwargs):
        """Hook
        """
        return super()._on_sub(current_value, self._resolve_role(raw_value_to_sub))

    def sanitize_finder_arg(self, arg):
        """Hook
        """
        if isinstance(arg, auth.model.AbstractRole):
            return arg.uid
        elif isinstance(arg, (list, tuple)):
            clean_arg = []
            for role in arg:
                if isinstance(role, auth.model.AbstractRole):
                    clean_arg.append(role.uid)
                else:
                    clean_arg.append(role)
            return clean_arg
        else:
            return arg


class User(odm.field.Base):
    """Field to store reference to user
    """

    def __init__(self, name: str, **kwargs):
        """Init
        """
        self._allow_anonymous = kwargs.get('allow_anonymous', False)
        self._allow_system = kwargs.get('allow_system', False)
        self._disallowed_users = kwargs.get('disallowed_users', ())

        super().__init__(name, **kwargs)

    def _on_get(self, raw_value, **kwargs) -> Optional[auth.AbstractUser]:
        """Hook
        """
        if raw_value is None:
            return None

        return _resolve_user(self._allow_system, self._allow_anonymous, self._disallowed_users, raw_value)

    def _on_set(self, raw_value: Optional[auth.AbstractUser], **kwargs) -> Optional[str]:
        """Hook
        """
        if raw_value is None:
            return None

        return _resolve_user(self._allow_system, self._allow_anonymous, self._disallowed_users, raw_value).uid

    def sanitize_finder_arg(self, arg):
        """Hook. Used for sanitizing Finder's query argument.
        """
        if isinstance(arg, auth.model.AbstractUser):
            if arg.is_anonymous:
                return 'ANONYMOUS'
            elif arg.is_system:
                return 'SYSTEM'
            else:
                return arg.uid
        elif isinstance(arg, (list, tuple)):
            clean_arg = []
            for user in arg:
                if isinstance(user, auth.model.AbstractUser):
                    clean_arg.append(user.uid)
                else:
                    clean_arg.append(user)
            return clean_arg
        else:
            return arg


class Users(odm.field.UniqueList):
    """Field to store list of users
    """

    def __init__(self, name: str, **kwargs):
        """Init.
        """
        self._allow_anonymous = kwargs.get('allow_anonymous', False)
        self._allow_system = kwargs.get('allow_system', False)
        self._disallowed_users = kwargs.get('disallowed_users', ())

        super().__init__(name, allowed_types=(auth.model.AbstractUser,), **kwargs)

    def _on_set(self, raw_value: Union[list, tuple], **kwargs) -> List[str]:
        """Hook
        """
        if raw_value is None:
            return []

        if not isinstance(raw_value, (list, tuple)):
            raise TypeError("Field '{}': list or tuple expected, got {}".format(self.name, type(raw_value)))

        return [_resolve_user(self._allow_system, self._allow_anonymous, self._disallowed_users, v).uid
                for v in raw_value if v]

    def _on_get(self, value: List[str], **kwargs) -> List[auth.AbstractUser]:
        """Hook
        """
        return [auth.get_user(uid=uid) for uid in value]

    def _on_add(self, current_value: tuple, raw_value_to_add: Any, **kwargs):
        """Hook
        """
        u = _resolve_user(self._allow_system, self._allow_anonymous, self._disallowed_users, raw_value_to_add)
        return super()._on_add(current_value, u)

    def _on_sub(self, current_value: tuple, raw_value_to_sub: Any, **kwargs):
        """Hook
        """
        u = _resolve_user(self._allow_system, self._allow_anonymous, self._disallowed_users, raw_value_to_sub)
        return super()._on_sub(current_value, u)

    def sanitize_finder_arg(self, arg):
        if isinstance(arg, (list, tuple)):
            return [_resolve_user(self._allow_system, self._allow_anonymous, self._disallowed_users, v).uid
                    for v in arg]
        else:
            return _resolve_user(self._allow_system, self._allow_anonymous, self._disallowed_users, arg).uid


class UsersDict(odm.field.Dict):
    def __init__(self, name: str, **kwargs):
        """Init.
        """
        self._allow_anonymous = kwargs.get('allow_anonymous', False)
        self._allow_system = kwargs.get('allow_system', False)
        self._disallowed_users = kwargs.get('disallowed_users', ())

        super().__init__(name, **kwargs)

    def _on_set(self, raw_value: dict, **kwargs) -> Dict[str, str]:
        try:
            raw_value = dict(raw_value)
        except (TypeError, ValueError):
            raise TypeError("Field '{}': dict expected, got '{}'".format(self._name, type(raw_value)))

        clean_value = {}
        for k, v in raw_value.items():
            clean_value[k] = _resolve_user(self._allow_system, self._allow_anonymous, self._disallowed_users, v).uid

        return clean_value

    def _on_get(self, value: Dict[str, str], **kwargs) -> Dict[Any, auth.AbstractUser]:
        """Hook
        """
        return {k: auth.get_user(uid=v) for k, v in value.items()}


class UsersDictReversed(UsersDict):
    def _on_set(self, raw_value: dict, **kwargs) -> [str, Any]:
        """Hook
        """
        try:
            raw_value = dict(raw_value)
        except (TypeError, ValueError):
            raise TypeError("Field '{}': dict expected, got '{}'".format(self._name, type(raw_value)))

        clean_value = {}
        for k, v in raw_value.items():
            clean_value[_resolve_user(self._allow_system, self._allow_anonymous, self._disallowed_users, k).uid] = v

        return clean_value

    def _on_get(self, value: dict, **kwargs) -> Dict[auth.AbstractUser, Any]:
        return {auth.get_user(uid=k): v for k, v in value.items()}
