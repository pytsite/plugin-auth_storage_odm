"""PytSite Auth ODM Storage Driver Plugin
"""
__author__ = 'Alexander Shepetko'
__email__ = 'a@shepetko.com'
__license__ = 'MIT'

# Public API
from . import _model as model, _field as field
from ._api import on_odm_setup_fields_role, on_odm_setup_fields_user
from ._model import User, Role, ODMRole, ODMUser, ODMBlockedUser, ODMFollower


def plugin_load():
    from plugins import auth, odm
    from . import _driver

    # ODM models
    odm.register_model('role', ODMRole)
    odm.register_model('user', ODMUser)
    odm.register_model('follower', ODMFollower)
    odm.register_model('blocked_user', ODMBlockedUser)

    # Register storage driver
    auth.register_storage_driver(_driver.Storage())
