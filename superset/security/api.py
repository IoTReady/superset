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
import logging

from flask import g, request, Response
from flask_appbuilder import expose
from flask_appbuilder.api import BaseApi, safe
from flask_appbuilder.security.decorators import permission_name, protect
from flask_wtf.csrf import generate_csrf

from superset.extensions import event_logger
from superset import security_manager

logger = logging.getLogger(__name__)


class SecurityRestApi(BaseApi):
    resource_name = "security"
    allow_browser_login = True
    openapi_spec_tag = "Security"

    @expose("/csrf_token/", methods=["GET"])
    @event_logger.log_this
    @protect()
    @safe
    @permission_name("read")
    def csrf_token(self) -> Response:
        """
        Return the csrf token
        ---
        get:
          description: >-
            Fetch the CSRF token
          responses:
            200:
              description: Result contains the CSRF token
              content:
                application/json:
                  schema:
                    type: object
                    properties:
                        result:
                          type: string
            401:
              $ref: '#/components/responses/401'
            500:
              $ref: '#/components/responses/500'
        """
        return self.response(200, result=generate_csrf())

    @expose("/register/", methods=["POST"])
    @event_logger.log_this
    @protect()
    @permission_name("post")
    def register_user(self) -> Response:
        if not request.is_json:
            return self.response_400(message="Request is not JSON")
        user_roles = [role.name.lower() for role in list(g.user.roles)]
        if 'admin' not in user_roles:
            return self.response_403(message="Not an admin.")
        payload = request.json
        role = payload.get('role')
        if not role:
          role = security_manager.find_role("Gamma") # Add users with Gamma role by default
        user = security_manager.add_user(
            payload['username'],
            payload['first_name'],
            payload['last_name'],
            payload['email'],
            role,
            password=payload['password'],
        )
        return self.response(200, id=user.id)
