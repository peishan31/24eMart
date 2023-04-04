# Copyright 2015-2015 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file
# except in compliance with the License. A copy of the License is located at
#
#     http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is distributed on an "AS IS"
# BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under the License.

import os
import string
import random
import time
from locust import HttpUser, TaskSet, task, between

class QuickstartUser(HttpUser):
    wait_time = between(1, 5)

    @task
    def home(self):
        self.client.get("/")
        self.client.get("/profile")

    @task(3)
    def view_items(self):
        for item_id in range(6):
            self.client.get(f"/item/{item_id}", name="/item")
            time.sleep(1)

    def on_start(self):
        self.client.post("/login", json={"username":"zhiyi456@gmail.com", "password":"abcd1234"})
