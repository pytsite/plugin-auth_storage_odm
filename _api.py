"""PytSite Auth ODM Storage Driver Plugin API Functions
"""
__author__ = 'Oleksandr Shepetko'
__email__ = 'a@shepetko.com'
__license__ = 'MIT'

from pytsite import events as _events


def on_odm_setup_fields_role(handler, priority: int = 0):
    """Shortcut
    """
    _events.listen('odm@model.setup_fields.role', handler, priority)


def on_odm_setup_fields_user(handler, priority: int = 0):
    """Shortcut
    """
    _events.listen('odm@model.setup_fields.user', handler, priority)
