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
<style type="text/css">
       #home {
		 	background-color: #16284C;
		}
    </style>

<#include "/incs/header.ftl">
<#include "/incs/banner.ftl">
<div class="customContainer" style="margin-bottom: 15%">
    <h2 style="text-align: center; padding-top: 4%; font-family: Georgia, serif">Main User Page</h2>
    <div class="index-content">
        <div class="row">
            <div class="col-xl-4 col-lg-6 col-md-6 col-12" style="margin: 0px 0px 15px 0px;">
                <a href="/resource/user/change_password">
                    <div class="card h-100">
                        <img class="card-img-top rounded" src="../images/bg1.jpg" alt="Card image cap">
                        <div class="card-body" id="homeCard0">
                            <p id="homeCardBody0">Change Password</p>
                            <a href="/resource/user/change_password"  class="blue-button"  id="bottom-left0">Read More</a>
                        </div>
                    </div>
            </div>
            <div class="col-xl-4 col-lg-6 col-md-6 col-12" style="margin: 0px 0px 15px 0px;">
                <a href="/resource/user/unlink">
                    <div class="card h-100">
                        <img class="card-img-top rounded" src="../images/bg1.jpg" alt="Card image cap">
                        <div class="card-body" id="homeCard1">
                            <p id="homeCardBody1">Unlink</p>
                            <a href="/resource/user/unlink"  class="blue-button"  id="bottom-left1">Read More</a>
                        </div>
                    </div>
            </div>
            <div class="col-xl-4 col-lg-6 col-md-6 col-12" style="margin: 0px 0px 15px 0px;">
                <a href="/resource/user/view_tokens">
                    <div class="card h-100">
                        <img class="card-img-top rounded" src="../images/bg1.jpg" alt="Card image cap">
                        <div class="card-body" id="homeCard2">
                            <p id="homeCardBody2">View Current Tokens</p>
                            <a href="/resource/user/view_tokens"  class="blue-button"  id="bottom-left2">Read More</a>
                        </div>
                    </div>
            </div>
        </div>
    </div>
</div>
<#include "/incs/footer.ftl">
</body>
