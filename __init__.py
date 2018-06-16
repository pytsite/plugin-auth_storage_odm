"""PytSite Auth ODM Storage Driver Plugin
"""
__author__ = 'Alexander Shepetko'
__email__ = 'a@shepetko.com'
__license__ = 'MIT'

# Public API
from . import _model as model, _field as field
from ._api import on_odm_setup_fields_role, on_odm_setup_fields_user
from ._model import User, Role, ODMRole, ODMUser, ODMBlockedUser, ODMFollower
from pytsite import semver as _semver


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


def plugin_update(v_from: _semver.Version):
    # Field 'uid' added to users and roles
    if v_from <= '2.3':
        from pytsite import console, mongodb
        from plugins import odm

        for c in ('users', 'roles'):
            col = mongodb.get_collection(c)
            for d in col.find():
                col.update_one({'_id': d['_id']}, {'$set': {'uid': str(d['_id'])}})
                console.print_info('Document updated: {}:{}'.format(c, d['_id']))

        odm.clear_cache('role')
        odm.clear_cache('user')
        odm.reindex('role')
        odm.reindex('user')

    if v_from <= '3.2':
        from pytsite import console, mongodb
        from plugins import odm

        for c in ('users', 'roles'):
            col = mongodb.get_collection(c)
            for d in col.find():
                col.update_one({'_id': d['_id']}, {'$set': {'uid': d['_ref']}})
                console.print_info('Document updated: {}:{}'.format(c, d['_id']))

        odm.clear_cache('role')
        odm.clear_cache('user')
        odm.reindex('role')
        odm.reindex('user')

        for m in odm.get_registered_models():
            mock = odm.dispense(m)
            for f_name, f in mock.fields.items():
                for d in mock.collection.find():
                    f_new_value = None

                    if isinstance(f, field.User) and d[f_name]:
                        f_new_value = '{}:{}'.format('user', d[f_name])

                    if isinstance(f, (field.Users, field.Roles)) and d[f_name]:
                        auth_model = 'role' if isinstance(f, field.Roles) else 'user'
                        f_new_value = ['{}:{}'.format(auth_model, v) for v in d[f_name]]

                    if f_new_value:
                        mock.collection.update_one({'_id': d['_id']}, {'$set': {f_name: f_new_value}})
                        console.print_info('Document updated: {}:{}'.format(m, d['_id']))

            odm.clear_cache(m)
