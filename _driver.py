"""PytSite Authentication ODM Storage Driver
"""
__author__ = 'Oleksandr Shepetko'
__email__ = 'a@shepetko.com'
__license__ = 'MIT'

from typing import Iterator, List, Tuple
from pytsite import logger, reg, util
from plugins import auth, odm, query
from . import _model

_REG_ROLE_CLS = 'auth_storage_odm.role_class'
_REG_USER_CLS = 'auth_storage_odm.user_class'


class Storage(auth.driver.Storage):
    def __init__(self):
        self._role_cls = util.get_module_attr(reg.get(_REG_ROLE_CLS, 'plugins.auth_storage_odm.Role'))
        if not issubclass(self._role_cls, _model.Role):
            raise TypeError("Subclass of {} expected, got {}. Please check the '{}' configuration parameter".
                            format(auth.AbstractRole, type(self._role_cls), _REG_ROLE_CLS))

        self._user_cls = util.get_module_attr(reg.get(_REG_USER_CLS, 'plugins.auth_storage_odm.User'))
        if not issubclass(self._user_cls, _model.User):
            raise TypeError("Subclass of {} expected, got {}. Please check the '{}' configuration parameter".
                            format(auth.AbstractUser, type(self._user_cls), _REG_USER_CLS))

    def get_name(self) -> str:
        """Get driver's name.
        """
        return 'odm'

    def create_role(self, name: str, description: str = '') -> auth.AbstractRole:
        """Create a new role.
        """
        role_entity = odm.dispense('role')  # type: _model.ODMRole
        role_entity.f_set('name', name).f_set('description', description).save()

        return self._role_cls(role_entity)

    def get_role(self, name: str = None, uid: str = None) -> auth.AbstractRole:
        f = odm.find('role')

        if name:
            f.eq('name', name)
        elif uid:
            f.eq('uid', uid)
        else:
            raise RuntimeError("Either role's name or UID must be specified")

        role_entity = f.first()  # type: _model.ODMRole
        if not role_entity:
            raise auth.error.RoleNotFound(name)

        return self._role_cls(role_entity)

    def find_roles(self, query: query.Query = None, sort: List[Tuple[str, int]] = None, limit: int = None,
                   skip: int = 0) -> Iterator[auth.AbstractRole]:
        """Find roles
        """
        # Return generator
        return (self._role_cls(role_entity) for role_entity in odm.find('role', query=query).skip(skip).get(limit))

    def create_user(self, login: str, password: str = None) -> auth.AbstractUser:
        user_entity = odm.dispense('user')  # type: _model.ODMUser
        user_entity.f_set_multiple({
            'login': login,
            'password': password,
        })

        return self._user_cls(user_entity)

    def get_user(self, login: str = None, nickname: str = None, uid: str = None) -> auth.AbstractUser:
        # Don't cache finder results due to frequent user updates in database
        f = odm.find('user').cache(0)
        if login is not None:
            f.eq('login', login)
        elif nickname is not None:
            f.eq('nickname', nickname)
        elif uid is not None:
            f.eq('uid', uid)
        else:
            raise RuntimeError('User search criteria was not specified')

        user_entity = f.first()  # type: _model.ODMUser
        if not user_entity:
            # Hide exception details to logs
            logger.warn("User not exist: login={}, nickname={}, uid={}".format(login, nickname, uid))
            raise auth.error.UserNotFound()

        return self._user_cls(user_entity)

    def find_users(self, query: query.Query = None, sort: List[Tuple[str, int]] = None, limit: int = None,
                   skip: int = 0) -> Iterator[auth.AbstractUser]:
        """Find users
        """
        f = odm.find('user', query=query).skip(skip)

        if sort:
            for sort_field, sort_order in sort:
                if sort_field in ('created', 'modified'):
                    sort_field = '_' + sort_field
                elif sort_field == 'full_name':
                    sort_field = 'first_name'
                elif sort_field == 'is_online':
                    sort_field = 'last_activity'

                f.sort([(sort_field, sort_order)])

        # Return generator
        return (self._user_cls(user_entity) for user_entity in f.get(limit))

    def count_users(self, query: query.Query = None) -> int:
        return odm.find('user', query=query).count()

    def count_roles(self, query: query.Query = None) -> int:
        return odm.find('role', query=query).count()
