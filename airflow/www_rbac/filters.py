# -*- coding: utf-8 -*-
#
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
#

from flask import g
from flask_appbuilder.models.sqla.filters import BaseFilter

from airflow.www_rbac.app import appbuilder


class AirflowFilter(BaseFilter):
    """
    Add utility function to make BaseFilter easy and fast

    These utility function exist in the SecurityManager, but would do
    a database round trip at every check. Here we cache the role objects
    to be able to make multiple checks but query the db only once
    """

    def get_user_roles(self):
        if g.user.is_anonymous():
            public_role = appbuilder.config.get('AUTH_ROLE_PUBLIC')
            return [appbuilder.sm.find_role(public_role)] if public_role else []
        return g.user.roles

    def get_all_permissions(self):
        """
        Returns a set of tuples with the perm name and view menu name
        """
        perms = set()
        for role in self.get_user_roles():
            for perm_view in role.permissions:
                perms.add((perm_view.permission.name, perm_view.view_menu.name))
        return perms

    def has_role(self, role_name_or_list):
        """
        Whether the user has this role name
        """
        if not isinstance(role_name_or_list, list):
            role_name_or_list = [role_name_or_list]
        return any(
            [r.name in role_name_or_list for r in self.get_user_roles()])

    def has_perm(self, permission_name, view_menu_name):
        """
        Whether the user has this perm
        """
        return (permission_name, view_menu_name) in self.get_all_permissions()

    def get_view_menus(self, permission_name):
        """
        Returns the details of view_menus for a perm name
        """
        vm = set()
        for perm_name, vm_name in self.get_all_permissions():
            if perm_name == permission_name:
                vm.add(vm_name)
        return vm

    def has_all_dags_access(self):
        """
        Has all the dag access in any of the 3 cases:
        1. Role needs to be in (Admin, Viewer, User, Op).
        2. Has can_dag_read permission on all_dags view.
        3. Has can_dag_edit permission on all_dags view.
        """
        return (
            self.has_role(['Admin', 'Viewer', 'Op', 'User']) or
            self.has_perm('can_dag_read', 'all_dags') or
            self.has_perm('can_dag_edit', 'all_dags'))


class DagFilter(AirflowFilter):
    def apply(self, query, func): # noqa
        if self.has_all_dags_access():
            return query
        filter_dag_ids = appbuilder.sm.get_accessible_dag_ids()
        return query.filter(self.model.dag_id.in_(filter_dag_ids))
