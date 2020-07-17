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
<head>
    <link rel="stylesheet" type="text/css" href="//fonts.googleapis.com/css?family=PT+Serif+Caption" /><link rel='stylesheet' href='//fonts.googleapis.com/css?family=Bevan' type='text/css' />
    <#include "/incs/meta.ftl">
    <#include "/incs/css.ftl">
    <#include "/incs/js.ftl">
</head>
<body>

<#include "/incs/header.ftl">
<div id="loginContainer">
    <div class="customContainer">
        <h2 style="text-align: center; padding-bottom: 10%; font-family: Georgia, serif">Google Account Linking Demo System</h2>
        <div class="row">
            <div class="col-md-12">
                <div style="margin-left: 30%; margin-right: 30%">
                    <form id="msform">
                        <div class="form-group" style="margin-bottom: 10px">
                            <label id="login_label0" style="text-align: left;color: #2177F3;">Username</label><br>
                            <input class="form-control" name="fname" id="username" type="text" placeholder="User Name">
                        </div>
                        <div class="form-group" style="margin-bottom: 10px">
                            <label id="login_label1" style="text-align: left;color: #2177F3;">Password</label><br>
                            <input class="form-control" name="lname" id="password" type="password" placeholder="Password">
                        </div>
                        <div class="row" style="margin-top: 7%">
                            <div class="col-6">
                                <button class="btn1" type="button" id="login" value="Login" >Login(User)</button>
                            </div>
                            <div class="col-6">
                                <button class="btn1 float-sm-right" type="button" id="Register0" value="Register" onclick="location.href='/register'">Register(User)</button>
                            </div>
                        </div>
                            <div class="row" style="margin-top: 7%">
                            <div class="col-6">
                                <button class="btn1" type="button" id="loginc" value="Login" >Login(Client)</button>
                            </div>
                            <div class="col-6">
                                <button class="btn1 float-sm-right" type="button" id="Register1" value="Register" onclick="location.href='/register_client'">Register(Client)</button>
                            </div>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    </div>
</div>
<#include "/incs/footer.ftl">
</body>
<script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/3.1.2/rollups/sha256.js"></script>
<script type="text/javascript" >
    $(function(){
    $("#login").click(function(){
        var username = $("#username").val();
        var password = $("#password").val();
        password = CryptoJS.SHA256(password);
        var url = '/login_check';
        $.ajax({
            url : "/login_check",
            type : "POST",
            data : "username=" + username + "&password=" +password,
            success : function(data){
                window.location.href = data;
            },
            error : function(xhr){
                alert("Login Failed!");
                window.location.reload();
            }
        });
    })
});

$(function(){
    $("#loginc").click(function(){
        var clientId = $("#username").val();
        var secret = $("#password").val();
        secret = CryptoJS.SHA256(secret);
        $.ajax({
            url : "/client_login_check",
            type : "POST",
            data : "client_id=" + clientId + "&secret=" +secret,
            success : function(data){
                window.location.href = data;
            },
            error : function(xhr){
                alert("Login Failed!");
                window.location.reload();
            }
        });
    })
});
</script>
</html>
