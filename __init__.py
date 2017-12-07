"""PytSIte Auth ODM Storage Driver Plugin
"""
from pytsite import plugman as _plugman

# Public API
if _plugman.is_installed(__name__):
    from . import _model as model, _field as field

__author__ = 'Alexander Shepetko'
__email__ = 'a@shepetko.com'
__license__ = 'MIT'


def plugin_load():
    from plugins import auth, odm
    from . import _driver

    # ODM models
    odm.register_model('role', model.ODMRole)
    odm.register_model('user', model.ODMUser)
    odm.register_model('follower', model.ODMFollower)
    odm.register_model('blocked_user', model.ODMBlockedUser)

    # Register storage driver
    auth.register_storage_driver(_driver.Storage())
