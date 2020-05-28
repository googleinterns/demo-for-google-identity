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
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Login</title>
    <link rel='stylesheet' href='../css/bootstrap/bootstrap.min.css' >
    <style>
            .container{
                display:table;
                height:100%;
            }

            .row{
                display: table-cell;
                vertical-align: middle;
            }
            .row-centered {
                text-align:center;
            }
            .col-centered {
                display:inline-block;
                float:none;
                text-align:left;
                margin-right:-4px;
            }
        </style>
</head>
<body>
<div class="container">
    <div class="row row-centered">
        <div class="well col-md-6 col-centered">
            <div style="text-align:center">
            <h2>Login</h2>
            </div>
            <form action="/login_check" method="post" role="form">
                <div class="input-group input-group-md">
                    <input type="text" class="form-control" id="username" name="username" placeholder="username"/>
                </div>
                <div class="input-group input-group-md">
                    <input type="password" class="form-control" id="password" name="password" placeholder="password"/>
                </div>
                <br/>
                <button type="button" id="login" class="btn btn-success btn-block">Login</button>
            </form>
        </div>
    </div>
</div>
</body>
<script type="text/javascript" src="../js/jquery-3.5.1.min.js";></script>
<script type='text/javascript' src='../js/CryptoJS/rollups/md5.js'></script>
<script type="text/javascript" >
    $(function(){
    $("#login").click(function(){
        var username = $("#username").val();
        var password = $("#password").val();
        password = CryptoJS.MD5(password);
        var url = '/login_check';
        $.post(url, 'username=' + username +  '&password=' + password,
            function(data, textStatus){
               window.location.href = data;
        });
    })
});
</script>
</html>