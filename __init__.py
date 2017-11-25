"""PytSIte Auth ODM Storage Driver Plugin
"""
# Public API
from . import _model as model, _field as field
from ._driver import Driver

__author__ = 'Alexander Shepetko'
__email__ = 'a@shepetko.com'
__license__ = 'MIT'


def _init():
    from pytsite import lang, router
    from plugins import auth, odm, admin

    # Resources
    lang.register_package(__name__)

    # ODM models
    odm.register_model('role', model.ODMRole)
    odm.register_model('user', model.ODMUser)
    odm.register_model('follower', model.ODMFollower)
    odm.register_model('blocked_user', model.ODMBlockedUser)

    # 'Security' admin sidebar section
    admin.sidebar.add_section('auth', 'auth_storage_odm@security', 1000)

    # 'Users' admin sidebar menu
    url = router.rule_path('odm_ui@browse', {'model': 'user'})
    admin.sidebar.add_menu('auth', 'users', 'auth_storage_odm@users', url, 'fa fa-users', weight=10,
                           permissions='odm_auth.view.user')

    # 'Roles' admin sidebar menu
    url = router.rule_path('odm_ui@browse', {'model': 'role'})
    admin.sidebar.add_menu('auth', 'roles', 'auth_storage_odm@roles', url, 'fa fa-key', weight=20,
                           permissions='odm_auth.view.role')

    # Register storage driver
    auth.register_storage_driver(Driver())


_init()
