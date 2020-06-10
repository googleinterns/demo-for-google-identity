<!--
Copyright 2020 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-->

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Approval</title>
    <style>
          .leftbtn {
                width: 20%;
                margin-left:30%;
                float:left;
            }
            .rightbtn {
                width: 20%;
                margin-right:30%;
                float:right;
           }

        </style>
</head>
<body>
<div class="info" style="text-align:center">
    <h1>${clientID + " Request"}</h1>
    <h1>${"Scopes: " + scopes}</h1>
<form action="/oauth2/authorize" method="post" >
    <input type="hidden"  name="user_approval" value="true"/>
    <div class="leftbtn">
    <button type="submit" id="approve" class="btn btn-success btn-block">Approve</button>
    </div>
</form>
<form action="/oauth2/authorize" method="post" role="form">
    <input type="hidden"  name="user_deny" value="true"/>
    <div class="rightbtn">
    <button type="submit" id="deny" class="btn btn-success btn-block">Deny</button>
    </div>
</form>
</div>
</body>
</html>
