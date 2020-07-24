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
<style type="text/css">
       #enter {
		 	background-color: #16284C;
		}
    </style>
  <#include "/incs/header.ftl">
  <#include "/incs/banner.ftl">
<div align="center">
  <h2 style="text-align: center; padding-top: 4%; padding-bottom: 7%; font-family: Georgia, serif">Current Access Tokens</h2>
  <form>
    <table class="simpletable"  id="datatable">
      <tr>
        <th>access_token</th>
        <th>client_id</th>
        <th>is_scoped</th>
        <th>scopes</th>
        <th>expired_time</th>
        <th>refresh_token</th>
      </tr>
      <#list accessTokens as accessToken>
      <tr>
        <#list accessToken as info>
        <td>${info}</td>
      </#list>
      </tr>
    </#list>
    </table>
  </form>
<h2 style="text-align: center; padding-top: 4%; padding-bottom: 7%; font-family: Georgia, serif">Current Refresh Tokens</h2>
<form>
  <table class="simpletable"  id="datatable1">
    <tr>
      <th>refresh_token</th>
      <th>client_id</th>
      <th>is_scoped</th>
      <th>scopes</th>
    </tr>
    <#list refreshTokens as refreshToken>
    <tr>
      <#list refreshToken as info>
      <td>${info}</td>
    </#list>
    </tr>
  </#list>
  </table>
</form>
</div>
</body>
</html>